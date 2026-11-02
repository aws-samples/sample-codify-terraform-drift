"""Gate A — was the whole surface observed, and is what was observed codifiable?

Providers fail *silently*, not loudly. A missing read permission does not reliably
surface as an authorization error: Terraform keeps the prior state for that object,
so the resource simply looks unchanged. Cross-account credentials that were never
provisioned can present as *phantom deletions* rather than an error. Write-only and
provider-computed attributes never refresh at all. Every one of those failure modes
produces the same output as "no drift", which is the most dangerous possible
ambiguity for a pattern whose job is detecting drift.

So this gate does not merely look for errors — it makes **positive assertions** and
fails closed when it cannot make them:

  1. the plan exists and parses
  2. no read/authorization failures appear in the run log
  3. no throttling or provider-inconsistency warnings appear (both mean the read may
     be incomplete)
  4. every candidate attribute is classified against the provider schema, so
     structurally un-refreshable ones are reported as *unverifiable* rather than
     silently counted as clean
  5. attributes that cannot be codified (computed, write-only) are separated from
     those that can

It also constrains the claim the pipeline is allowed to make. Never
"fully reconciled" — only **reconciled over the observable projection**, with the
unobservable part enumerated.

Checkov's verdict on the refresh-only plan is folded in when supplied, so Gate A is
a single decision point, but this module never shells out to it: keeping it pure
keeps it testable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

from ..policy import evaluated_checks, failed_checks, failure_keys

# --- signals that a read may have been incomplete ---------------------------

READ_FAILURE_PATTERNS = {
    "authorization": re.compile(
        r"AccessDenied|UnauthorizedOperation|AuthFailure|not authorized to perform|"
        r"is not authorized|InvalidClientTokenId|ExpiredToken|SignatureDoesNotMatch",
        re.I,
    ),
    "throttling": re.compile(
        r"Throttling|ThrottlingException|RequestLimitExceeded|TooManyRequests|"
        r"\b429\b|\b503\b|ServiceUnavailable|SlowDown",
        re.I,
    ),
    "provider_inconsistency": re.compile(
        r"Provider produced inconsistent result|produced an unexpected new value|"
        r"provider produced invalid plan",
        re.I,
    ),
}


def scan_log(text: str) -> dict[str, list[str]]:
    """Group log lines by the failure signal they carry."""
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        for label, pattern in READ_FAILURE_PATTERNS.items():
            if pattern.search(line):
                found.setdefault(label, []).append(line.strip()[:300])
    return found


# --- provider schema classification -----------------------------------------

CODIFIABLE = "codifiable"
COMPUTED = "computed"
WRITE_ONLY = "write_only"
UNKNOWN = "unknown"


def _resource_schema(schema: dict[str, Any], resource_type: str) -> dict[str, Any] | None:
    for provider in (schema.get("provider_schemas") or {}).values():
        rs = (provider.get("resource_schemas") or {}).get(resource_type)
        if rs:
            return rs.get("block") or {}
    return None


def _attribute_spec(block: dict[str, Any], path: list[str]) -> dict[str, Any] | None:
    """Resolve a dotted attribute path against a schema block.

    Numeric segments are list indices into a nested block and are skipped.
    """
    if not path:
        return None
    head, rest = path[0], path[1:]

    attrs = block.get("attributes") or {}
    if head in attrs and not rest:
        return attrs[head]
    if head in attrs and rest:
        # Nested data inside a single attribute (e.g. a map/object). The attribute
        # itself governs codifiability.
        return attrs[head]

    nested = (block.get("block_types") or {}).get(head)
    if nested:
        inner = nested.get("block") or {}
        rest = [p for p in rest if not p.isdigit()]
        return _attribute_spec(inner, rest) if rest else {"__block__": True, "optional": True}
    return None


def classify_attribute(schema: dict[str, Any], resource_type: str, attr_path: str) -> str:
    """Classify one attribute path as codifiable / computed / write_only / unknown."""
    block = _resource_schema(schema, resource_type)
    if block is None:
        return UNKNOWN
    spec = _attribute_spec(block, attr_path.split("."))
    if spec is None:
        return UNKNOWN
    if spec.get("write_only"):
        return WRITE_ONLY
    # Computed-only (no optional/required counterpart) cannot be set in config, so it
    # cannot be codified even though it legitimately differs.
    if spec.get("computed") and not (spec.get("optional") or spec.get("required")):
        return COMPUTED
    return CODIFIABLE


def classify_candidates(
    reconciled: dict[str, Any], schema: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """Split each reconciled resource's candidate attributes by codifiability."""
    out = []
    for entry in reconciled.get("real_drift", []):
        buckets: dict[str, list[str]] = {}
        for attr in entry.get("changed_attributes", []):
            verdict = classify_attribute(schema, entry.get("type", ""), attr) if schema else UNKNOWN
            buckets.setdefault(verdict, []).append(attr)
        out.append(
            {
                "address": entry.get("address"),
                "type": entry.get("type"),
                "codifiable": buckets.get(CODIFIABLE, []),
                "computed": buckets.get(COMPUTED, []),
                "write_only": buckets.get(WRITE_ONLY, []),
                "unclassified": buckets.get(UNKNOWN, []),
            }
        )
    return out


# --- the gate ---------------------------------------------------------------

def evaluate(
    refresh_only_plan: dict[str, Any] | None,
    log_text: str = "",
    provider_schema: dict[str, Any] | None = None,
    reconciled: dict[str, Any] | None = None,
    checkov_result: dict[str, Any] | None = None,
    checkov_baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assert what the run is entitled to claim, and fail closed when it cannot.

    ``checkov_result`` is a scan of the **drift projection** - the live values, made
    scannable by :mod:`driftcode.project`. Scanning the refresh-only plan directly does
    not work: its ``planned_values`` is empty, so a plan-based scanner evaluates nothing
    and reports a clean result on an estate it never looked at.

    ``checkov_baseline`` is a scan of the full plan, which represents the configured
    intent. The verdict is the **set difference** between the two, not the failure count.
    An estate normally has pre-existing findings - the sample workspace has nine - so any
    absolute threshold fails every run forever and gets switched off. What matters is
    whether *this drift* introduced a finding that the configuration did not already have.
    """
    failures: list[str] = []
    warnings: list[str] = []

    # 1. the plan must exist and parse
    if refresh_only_plan is None:
        failures.append("refresh-only plan is missing or unparseable; cannot assert anything about drift")

    # 2-3. the read must not be suspect
    signals = scan_log(log_text)
    if "authorization" in signals:
        failures.append(
            f"{len(signals['authorization'])} authorization failure(s) in the run log: part of the "
            "managed surface was unreadable, so 'no drift' cannot be claimed for it"
        )
    if "throttling" in signals:
        failures.append(
            f"{len(signals['throttling'])} throttling signal(s): a throttled read can return an "
            "incomplete object with no error"
        )
    if "provider_inconsistency" in signals:
        failures.append(
            f"{len(signals['provider_inconsistency'])} provider-inconsistency warning(s): the "
            "refreshed values cannot be trusted"
        )

    # 4. is the drift itself dangerous — measured as a delta against configured intent
    checkov_failed = 0
    checkov_evaluated = 0
    baseline_evaluated = 0
    introduced: list[dict[str, str]] = []

    if checkov_result is not None:
        # Shape-tolerant: checkov emits a list when more than one runner reports.
        checkov_failed = len(failed_checks(checkov_result))
        checkov_evaluated = evaluated_checks(checkov_result)

        if checkov_evaluated == 0:
            # An empty scan is not a clean scan. Checkov's terraform_plan framework reads
            # planned_values, which a refresh-only plan leaves empty, so it evaluates
            # nothing and reports 0 failures. Treating that as a pass is the same mistake
            # as inferring "no drift" from silence, which this gate exists to refuse.
            failures.append(
                "the policy scan evaluated 0 checks, so it asserts nothing about whether "
                "the drift is dangerous. A refresh-only plan carries its values in "
                "prior_state and resource_drift, not in planned_values, so a plan-based "
                "scanner has no resources to evaluate. Scan the drift projection produced "
                "by drift-project instead"
            )
        elif checkov_failed and checkov_baseline is None:
            # With findings but no baseline the only available verdict is the absolute
            # count, and on any real estate that is a permanent failure. Say so rather
            # than emit it. Zero findings needs no baseline: nothing can have been
            # introduced.
            failures.append(
                f"the drift projection scan reported {checkov_failed} finding(s) but no "
                "baseline was supplied, so it cannot be said which of them this drift "
                "introduced. A pre-existing finding is not a reason to refuse a drift that "
                "did not cause it"
            )
        elif checkov_baseline is not None:
            baseline_evaluated = evaluated_checks(checkov_baseline)
            if baseline_evaluated == 0:
                failures.append(
                    "the baseline scan evaluated 0 checks, so there is nothing to compare "
                    "against and every pre-existing finding would read as newly introduced"
                )
            else:
                introduced = [
                    {"check_id": check_id, "resource": resource}
                    for check_id, resource in sorted(
                        failure_keys(checkov_result) - failure_keys(checkov_baseline)
                    )
                ]
                if introduced:
                    detail = ", ".join(f"{f['check_id']} on {f['resource']}" for f in introduced)
                    failures.append(
                        f"the drift introduces {len(introduced)} policy finding(s) absent "
                        f"from the configured intent: {detail}. This drift is dangerous and "
                        "must not be codified"
                    )
                pre_existing = len(failure_keys(checkov_baseline))
                if pre_existing:
                    warnings.append(
                        f"{pre_existing} pre-existing policy finding(s) in the configured "
                        "intent, unrelated to this drift and not grounds for refusing it"
                    )

    # 5. classify which attributes can actually be codified
    classified = classify_candidates(reconciled or {}, provider_schema)
    if provider_schema is None:
        warnings.append(
            "no provider schema supplied: attributes could not be classified, so "
            "computed and write-only values may be mistaken for codifiable ones"
        )
    for c in classified:
        for bucket, note in (
            ("computed", "provider-computed, cannot be set in configuration"),
            ("write_only", "write-only, never returned by the provider"),
            ("unclassified", "not found in the pinned provider schema"),
        ):
            if c[bucket]:
                warnings.append(f"{c['address']}: {', '.join(c[bucket])} — {note}")

    passed = not failures
    return {
        "verdict": "PASS" if passed else "FAIL",
        "failures": failures,
        "warnings": warnings,
        "log_signals": signals,
        "checkov_failed_checks": checkov_failed,
        "checkov_evaluated_checks": checkov_evaluated,
        "checkov_baseline_evaluated_checks": baseline_evaluated,
        "policy_findings_introduced_by_drift": introduced,
        "attribute_classification": classified,
        # The claim the pipeline is permitted to make downstream.
        "claim": (
            "reconciled over the observable projection"
            if passed
            else "no claim: the observable surface could not be established"
        ),
    }


def _load(path: str | None) -> Any:
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--refresh-only-plan", required=True)
    ap.add_argument("--log", help="terraform run output to scan for read failures")
    ap.add_argument("--provider-schema", help="output of `terraform providers schema -json`")
    ap.add_argument("--reconciled", help="output of reconcile.py")
    ap.add_argument(
        "--checkov-result",
        help="checkov JSON for the DRIFT PROJECTION from drift-project, not for the "
        "refresh-only plan: a plan-based scanner evaluates nothing on the latter",
    )
    ap.add_argument(
        "--checkov-baseline",
        help="checkov JSON for the full plan, representing configured intent. The "
        "verdict is the difference between the two scans, not the failure count",
    )
    ap.add_argument("--out")
    args = ap.parse_args(argv)

    log_text = ""
    if args.log:
        try:
            with open(args.log, encoding="utf-8", errors="replace") as fh:
                log_text = fh.read()
        except OSError:
            log_text = ""

    result = evaluate(
        refresh_only_plan=_load(args.refresh_only_plan),
        log_text=log_text,
        provider_schema=_load(args.provider_schema),
        reconciled=_load(args.reconciled),
        checkov_result=_load(args.checkov_result),
        checkov_baseline=_load(args.checkov_baseline),
    )

    payload = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    else:
        print(payload)

    print(f"Gate A: {result['verdict']} — {result['claim']}", file=sys.stderr)
    for f in result["failures"]:
        print(f"  FAIL: {f}", file=sys.stderr)
    for w in result["warnings"]:
        print(f"  warn: {w}", file=sys.stderr)

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
