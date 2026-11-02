"""Gates B and C: scan what will actually be true once the change is merged.

Gate A asks whether the *live drift* is dangerous, on a projection of live values. These ask a
different question: whether the *codified result* is dangerous once the configuration is
evaluated. The answers can differ, and the case where they differ is the whole reason both
exist — an edit that lands in a shared variable can be benign where it was observed and
dangerous where a sibling consumes it.

Two scans, because each is blind to something the other sees:

  * **Gate B — the branch's ``terraform plan``.** Values are resolved through the workspace's
    variable context, so a dangerous value trips the gate whether it is a literal or arrives
    via ``var``/``tfvars``. Blind spot: a plan under-evaluates some module-graph values, and
    it is **completely blinded by ``ignore_changes``** — a frozen attribute drops out of the
    plan, so a world-open value hiding behind a freeze would sail past.
  * **Gate C — ``checkov -d`` on the source.** Resolves variables to literals independently of
    any plan, so it sees what Gate B's freeze hid. Blind spot: no plan context, so values that
    only exist after graph evaluation are invisible to it.

Every verdict is a **delta against a baseline**, never a count, for the same reason as Gate A:
a real estate carries pre-existing findings this change did not cause, and a gate that fails on
those fails every run and gets switched off. The baseline is the same scan against the
unmodified checkout, so the comparison isolates exactly what the edit introduced.

Both gates run on a **branch that has been verified**, never on an unverified diff. Scanning a
change that does not match the work order would be measuring the wrong artifact.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any

from .policy import evaluated_checks, failure_keys

PASS = "PASS"
FAIL = "FAIL"

GATE_B = "Gate B (branch plan, variables resolved)"
GATE_C = "Gate C (source directory, variables resolved without a plan)"


@dataclass
class GateResult:
    name: str
    #: Starts as FAIL. A gate that has not reached a conclusion has not passed, so the default
    #: cannot be the permissive one - every early return must be an explicit failure.
    verdict: str = FAIL
    introduced: list[dict[str, str]] = field(default_factory=list)
    resolved: list[dict[str, str]] = field(default_factory=list)
    pre_existing: int = 0
    evaluated: int = 0
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.verdict == PASS

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "verdict": self.verdict,
            "introduced": self.introduced,
            "resolved": self.resolved,
            "pre_existing": self.pre_existing,
            "evaluated": self.evaluated,
            "failures": self.failures,
            "warnings": self.warnings,
        }


def evaluate_gate(
    name: str,
    before: Any,
    after: Any,
    frozen_attributes: list[str] | None = None,
) -> GateResult:
    """Compare a scan of the codified result against the same scan of the baseline.

    ``frozen_attributes`` names attributes held under ``ignore_changes`` during a merge window.
    Their presence is a warning on a plan-based gate, because a frozen attribute is absent from
    the plan and therefore from this scan — the gate cannot speak to it, and saying so is
    better than a pass that appears to cover it.
    """
    result = GateResult(name=name)

    result.evaluated = evaluated_checks(after)
    if result.evaluated == 0:
        # The same failure mode Gate A guards against: zero findings out of zero checks reads
        # as clean to anything that looks at the count.
        result.verdict = FAIL
        result.failures.append(
            "the scan evaluated 0 checks, so it asserts nothing about the codified result. "
            "Check that the scan target contains the resources in question"
        )
        return result

    baseline_evaluated = evaluated_checks(before)
    if baseline_evaluated == 0:
        result.verdict = FAIL
        result.failures.append(
            "the baseline scan evaluated 0 checks, so there is nothing to compare against and "
            "every pre-existing finding would read as newly introduced"
        )
        return result

    before_keys, after_keys = failure_keys(before), failure_keys(after)

    result.introduced = [
        {"check_id": check, "resource": resource}
        for check, resource in sorted(after_keys - before_keys)
    ]
    result.resolved = [
        {"check_id": check, "resource": resource}
        for check, resource in sorted(before_keys - after_keys)
    ]
    result.pre_existing = len(before_keys)

    if result.pre_existing:
        result.warnings.append(
            f"{result.pre_existing} pre-existing finding(s) in the baseline, unrelated to this "
            "change and not grounds for refusing it"
        )
    if result.resolved:
        # Not a pass condition on its own, and not a reason to fail. Recorded because a change
        # that removes a finding is worth a reviewer knowing about.
        result.warnings.append(
            f"{len(result.resolved)} finding(s) present in the baseline are absent after the "
            "change"
        )

    for attribute in frozen_attributes or []:
        result.warnings.append(
            f"{attribute} is under ignore_changes for the merge window, so it is absent from a "
            "plan-based scan; this gate cannot speak to its value. Gate C covers it"
        )

    if result.introduced:
        detail = ", ".join(f"{f['check_id']} on {f['resource']}" for f in result.introduced)
        result.verdict = FAIL
        result.failures.append(
            f"the codified change introduces {len(result.introduced)} policy finding(s) absent "
            f"from the baseline: {detail}"
        )
    else:
        result.verdict = PASS

    return result


def evaluate(
    plan_before: Any = None,
    plan_after: Any = None,
    source_before: Any = None,
    source_after: Any = None,
    frozen_attributes: list[str] | None = None,
) -> dict[str, Any]:
    """Run both gates and combine them. A missing scan fails its gate rather than skipping it.

    Gate C is mandatory, not supplementary. A plan-only regime is blinded by ``ignore_changes``,
    which is precisely the mechanism that holds a merge window open — so the one configuration
    where the freeze is in play is the one where a plan scan cannot be trusted alone.
    """
    gates: dict[str, GateResult] = {}

    if plan_before is None or plan_after is None:
        missing = GateResult(name=GATE_B, verdict=FAIL)
        missing.failures.append(
            "no branch-plan scan supplied; a value arriving through var/tfvars would go "
            "unexamined, so this cannot be treated as passed"
        )
        gates[GATE_B] = missing
    else:
        gates[GATE_B] = evaluate_gate(GATE_B, plan_before, plan_after, frozen_attributes)

    if source_before is None or source_after is None:
        missing = GateResult(name=GATE_C, verdict=FAIL)
        missing.failures.append(
            "no source-directory scan supplied. Gate C is mandatory: a plan-based scan is "
            "blinded by ignore_changes, so it cannot be the only scan"
        )
        gates[GATE_C] = missing
    else:
        gates[GATE_C] = evaluate_gate(GATE_C, source_before, source_after)

    introduced: list[dict[str, str]] = []
    for gate in gates.values():
        for finding in gate.introduced:
            if finding not in introduced:
                introduced.append(finding)

    passed = all(gate.passed for gate in gates.values())
    return {
        "verdict": PASS if passed else FAIL,
        "gates": {name: gate.as_dict() for name, gate in gates.items()},
        "introduced": introduced,
        "counts": {
            "gates_failed": sum(0 if g.passed else 1 for g in gates.values()),
            "introduced": len(introduced),
        },
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
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan-before", help="checkov JSON for the base branch's plan")
    parser.add_argument("--plan-after", help="checkov JSON for the drift branch's plan")
    parser.add_argument("--source-before", help="checkov -d JSON for the unmodified checkout")
    parser.add_argument("--source-after", help="checkov -d JSON for the modified checkout")
    parser.add_argument(
        "--frozen-attribute",
        action="append",
        default=[],
        help="attribute held under ignore_changes for the merge window; repeatable",
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    result = evaluate(
        _load(args.plan_before),
        _load(args.plan_after),
        _load(args.source_before),
        _load(args.source_after),
        args.frozen_attribute,
    )

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)

    print(f"Gates B/C: {result['verdict']}", file=sys.stderr)
    for gate in result["gates"].values():
        print(f"  {gate['verdict']}  {gate['name']}", file=sys.stderr)
        for failure in gate["failures"]:
            print(f"      FAIL: {failure}", file=sys.stderr)
        for warning in gate["warnings"]:
            print(f"      warn: {warning}", file=sys.stderr)

    # Non-zero routes the run to the blocked path: a pull request still opens, labelled, because
    # the dangerous configuration is already live. The caller decides; this only reports.
    return 0 if result["verdict"] == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
