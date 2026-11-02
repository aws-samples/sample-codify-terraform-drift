"""Two-plan reconciliation: establish what actually drifted.

A locked ``terraform plan -refresh-only`` is NOT a sufficient drift trigger. It
reports provider *representation* normalization as drift — ``null`` vs empty list,
and deprecated in-line attributes populated from their standalone resources — and
all of it carries ``actions: ["update"]``, so an action gate cannot tell it apart
from a real change. Acting on refresh-only alone opens pull requests that codify
changes nobody made.

This module reconciles the refresh-only plan against a full ``terraform plan`` and
returns three *asymmetric* verdicts:

    in refresh-only AND full plan  -> real drift; eligible for classification
    in refresh-only ONLY           -> provider normalization; SUPPRESS
    in full plan ONLY              -> NOT drift by itself. A full plan also shows
                                      un-applied code changes (code ahead of
                                      state), which is precisely what
                                      ``-refresh-only`` excludes.
                                      Requires a HEAD-vs-deployed comparison
                                      before anything here is admitted.

Pure and offline: it takes two ``terraform show -json`` documents and calls no AWS
API. That is what makes it testable against captured real-provider fixtures.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterable

NO_OP = ["no-op"]


def _is_managed(entry: dict[str, Any]) -> bool:
    """Data sources are not manageable infrastructure; exclude them."""
    return entry.get("mode", "managed") == "managed"


def _actions(entry: dict[str, Any]) -> list[str]:
    return list((entry.get("change") or {}).get("actions") or [])


def _meaningful(entry: dict[str, Any]) -> bool:
    return _is_managed(entry) and _actions(entry) not in ([], NO_OP)


def _index(entries: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index meaningful entries by resource address (last wins, addresses unique)."""
    return {e["address"]: e for e in entries if e.get("address") and _meaningful(e)}


def _diff_paths(before: Any, after: Any, prefix: str = "") -> list[str]:
    """Dotted paths of scalar differences between two value representations.

    Recurses dicts and lists so nested-block changes surface as
    ``ingress.0.cidr_blocks`` rather than just ``ingress``.
    """
    if isinstance(before, dict) and isinstance(after, dict):
        out: list[str] = []
        for key in sorted(set(before) | set(after)):
            out += _diff_paths(before.get(key), after.get(key), f"{prefix}{key}.")
        return out
    if isinstance(before, list) and isinstance(after, list):
        out = []
        for i in range(max(len(before), len(after))):
            b = before[i] if i < len(before) else None
            a = after[i] if i < len(after) else None
            out += _diff_paths(b, a, f"{prefix}{i}.")
        return out
    if before != after:
        return [prefix.rstrip(".")] if prefix else ["<root>"]
    return []


def changed_attributes(entry: dict[str, Any]) -> list[str]:
    change = entry.get("change") or {}
    return _diff_paths(change.get("before"), change.get("after"))


def reconcile_attributes(
    drift_entry: dict[str, Any], plan_entry: dict[str, Any]
) -> dict[str, list[str]]:
    """Attribute-level reconciliation within a genuinely drifted resource.

    Resource-level intersection is necessary but NOT sufficient: a resource that
    really drifted still reports normalization noise among its attributes. A
    launch-template drift, for instance, reports six changed attributes in the
    refresh-only plan — the two the operator changed, two consequential version
    fields, and ``security_group_names: null -> []`` plus ``tags: null -> {}``, which
    are pure representation normalization.

    An attribute that genuinely drifted appears in *both* plans — in the
    refresh-only plan as ``state -> live``, and in the full plan as the proposed
    revert ``live -> config``. Directions differ; the *path* is what intersects.

    Attributes present only in the refresh-only plan are noise and must not be
    handed to the agent as things to codify.

    The intersection can still contain provider-*computed* attributes (e.g.
    ``latest_version``), which are not codifiable. Excluding those requires the
    provider schema and is Gate A's responsibility — not something an attribute diff
    can determine on its own.
    """
    drift_attrs = changed_attributes(drift_entry)
    plan_attrs = set(changed_attributes(plan_entry))
    return {
        "candidates": [a for a in drift_attrs if a in plan_attrs],
        "noise": [a for a in drift_attrs if a not in plan_attrs],
    }


def _descriptor(entry: dict[str, Any], **extra: Any) -> dict[str, Any]:
    d = {
        "address": entry["address"],
        "type": entry.get("type"),
        "name": entry.get("name"),
        "module_address": entry.get("module_address"),
        "actions": _actions(entry),
    }
    d.update(extra)
    return d


def reconcile(refresh_only_plan: dict[str, Any], full_plan: dict[str, Any]) -> dict[str, Any]:
    """Reconcile the two plans into real / suppressed / pending-verification sets."""
    drift = _index(refresh_only_plan.get("resource_drift") or [])
    changes = _index(full_plan.get("resource_changes") or [])

    real_addrs = sorted(set(drift) & set(changes))
    suppressed_addrs = sorted(set(drift) - set(changes))
    pending_addrs = sorted(set(changes) - set(drift))

    real = []
    for a in real_addrs:
        attrs = reconcile_attributes(drift[a], changes[a])
        real.append(
            _descriptor(
                drift[a],
                changed_attributes=attrs["candidates"],
                attribute_noise=attrs["noise"],
                full_plan_actions=_actions(changes[a]),
            )
        )
    suppressed = [
        _descriptor(
            drift[a],
            changed_attributes=changed_attributes(drift[a]),
            reason=(
                "present in refresh-only but not in the full plan: provider "
                "representation normalization, not a real change"
            ),
        )
        for a in suppressed_addrs
    ]
    pending = [
        _descriptor(
            changes[a],
            reason=(
                "present in the full plan but not in refresh-only: may be an "
                "un-applied code change rather than drift; requires a "
                "HEAD-vs-deployed check before admission"
            ),
        )
        for a in pending_addrs
    ]

    return {
        "real_drift": real,
        "suppressed": suppressed,
        "pending_verification": pending,
        "counts": {
            "refresh_only_reported": len(drift),
            "full_plan_reported": len(changes),
            "real_drift": len(real),
            "suppressed": len(suppressed),
            "pending_verification": len(pending),
        },
        "has_real_drift": bool(real),
    }


def _load(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--refresh-only", required=True, help="terraform show -json of the refresh-only plan")
    ap.add_argument("--full-plan", required=True, help="terraform show -json of the full plan")
    ap.add_argument("--out", help="write the reconciliation result here (default: stdout)")
    args = ap.parse_args(argv)

    result = reconcile(_load(args.refresh_only), _load(args.full_plan))
    payload = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    else:
        print(payload)

    c = result["counts"]
    print(
        f"reconciled: refresh-only reported {c['refresh_only_reported']}, "
        f"full plan reported {c['full_plan_reported']} -> "
        f"{c['real_drift']} real, {c['suppressed']} suppressed, "
        f"{c['pending_verification']} pending",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
