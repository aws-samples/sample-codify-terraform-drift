"""Make the drifted live values scannable by a plan-based policy engine.

A ``terraform plan -refresh-only`` document cannot be scanned by Checkov, and the reason
is structural rather than a misconfiguration. Checkov's ``terraform_plan`` framework builds
its resource graph from ``planned_values``, and a refresh-only plan leaves that empty: its
whole purpose is to report that *state* should change, so the refreshed live values are
carried in ``prior_state`` and the deltas in ``resource_drift``. Pointed at one, Checkov
evaluates zero resources and reports zero findings - indistinguishable, to any caller that
reads the failure count, from a clean estate.

A refresh-only document has no ``resource_changes`` key at all. On the sample workspace it
carries 0 resources under ``planned_values`` and 11 under ``prior_state`` (9 managed, 2
data sources); Checkov reports 0 passed and 0 failed on it, against 9 failures on the full
plan.

The projection is a transplant, not a rewrite. ``prior_state.values.root_module`` already
holds the live values in exactly the shape ``planned_values`` uses, so moving it into place
produces a valid plan-shaped document whose contents are what the cloud currently looks
like. Scanning that answers the question Gate A actually wants answered - *is the drift
dangerous?* - because the values scanned are the drifted ones.

Two properties make this safe to rely on:

  * **Nothing is synthesized.** Values are copied from the plan Terraform produced. No
    defaults are invented and no attribute is filled in, so a finding is a finding about
    real live configuration.
  * **Data sources are dropped.** They are not manageable infrastructure and cannot drift,
    matching the filter the reconciler applies.

The scan of this projection is only half the answer. An estate almost always has
pre-existing findings - the sample workspace has nine - so an absolute threshold fails
every run forever. What Gate A compares is this projection against the configured
intent, and reports only the difference.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterator

#: Marks a document produced here, so a scan result can be attributed to the projection
#: rather than mistaken for a plan Terraform emitted.
PROJECTION_MARKER = "driftcode_drift_projection"


def _walk(module: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for resource in module.get("resources") or []:
        yield resource
    for child in module.get("child_modules") or []:
        yield from _walk(child)


def _managed_only(module: dict[str, Any]) -> dict[str, Any]:
    """Copy a module tree keeping only managed resources.

    Data sources cannot drift and are not remediable, so they are dropped here for the
    same reason the reconciler drops them.
    """
    out: dict[str, Any] = {k: v for k, v in module.items() if k not in ("resources", "child_modules")}

    resources = [r for r in (module.get("resources") or []) if r.get("mode", "managed") == "managed"]
    if resources:
        out["resources"] = resources

    children = [_managed_only(c) for c in (module.get("child_modules") or [])]
    children = [c for c in children if c.get("resources") or c.get("child_modules")]
    if children:
        out["child_modules"] = children

    return out


def count_resources(document: dict[str, Any], key: str = "planned_values") -> int:
    """Count resources under a plan section, tolerating the two nesting shapes.

    ``planned_values`` holds ``root_module`` directly while ``prior_state`` wraps it in
    ``values``. Handling both here keeps callers from having to remember which is which,
    and the difference between the two sections is exactly what this module exists to
    bridge.
    """
    section = document.get(key) or {}
    root = section.get("values", section).get("root_module") or {}
    return sum(1 for _ in _walk(root))


class ProjectionError(Exception):
    """Raised when a refresh-only plan carries no live state to project."""


def drift_projection(refresh_only_plan: dict[str, Any]) -> dict[str, Any]:
    """Build a plan-shaped document whose ``planned_values`` are the live drifted values.

    Raises rather than emitting an empty document: an empty projection would scan cleanly
    and so would silently reintroduce the failure this module exists to remove.
    """
    prior = (refresh_only_plan.get("prior_state") or {}).get("values") or {}
    root = prior.get("root_module")
    if not root:
        raise ProjectionError(
            "refresh-only plan carries no prior_state.values.root_module, so there are no "
            "live values to scan. Emitting an empty document would scan clean and assert "
            "nothing, which is the failure this projection exists to remove"
        )

    projected = _managed_only(root)
    if not (projected.get("resources") or projected.get("child_modules")):
        raise ProjectionError(
            "prior_state contains no managed resources; only data sources, which cannot "
            "drift and cannot be remediated"
        )

    document: dict[str, Any] = {
        "format_version": refresh_only_plan.get("format_version", "1.2"),
        "terraform_version": refresh_only_plan.get("terraform_version", "unknown"),
        "planned_values": {"root_module": projected},
        # Checkov resolves variable and module references through the configuration block
        # when it is present. Carried verbatim; it holds no live values.
        "configuration": refresh_only_plan.get("configuration") or {},
        "variables": refresh_only_plan.get("variables") or {},
        PROJECTION_MARKER: {
            "source": "prior_state of a terraform plan -refresh-only",
            "note": "live values as refreshed, with data sources removed. Not a plan "
            "Terraform produced; never apply this.",
        },
    }
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Project a refresh-only plan's live values into a scannable plan document"
    )
    parser.add_argument("--refresh-only-plan", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    with open(args.refresh_only_plan, encoding="utf-8") as fh:
        plan = json.load(fh)

    try:
        document = drift_projection(plan)
    except ProjectionError as exc:
        print(f"cannot project drifted values: {exc}", file=sys.stderr)
        return 1

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(document, fh)

    print(
        f"projected {count_resources(document)} managed resource(s) with live values "
        f"into {args.out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
