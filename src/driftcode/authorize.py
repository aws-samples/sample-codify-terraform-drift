"""Turn reconciled drift into a bounded work order, or into an escalation.

This is the stage between detection and the agent, and it is the reason the agent can be
given a model's freedom without giving it a model's blast radius. Everything the agent is
not allowed to decide is decided here, deterministically:

  * whether the drift is codifiable at all (``classify``)
  * which source layer supplies the value, and therefore which file holds it
    (``resolve``) - a literal in the resource block, a value in the caller's module block,
    or an entry in this workspace's ``tfvars`` are three different files
  * the exact lines that may change (``resolve`` plus ``locate``)
  * what the agent is permitted to see (``sanitize``)

The output is a list of work orders. Each names one resource, one or more attributes, and
for every attribute exactly one file and line. The agent's job is reduced to writing a
value into a known location; it chooses no target, reads no plan, and holds no
credentials. The verifier later rejects any diff that falls outside these sites, so a work
order is simultaneously the agent's instruction and the enforcement boundary.

Resources that cannot be reduced to that shape appear under ``escalate`` with the reason.
That output matters as much as the work orders: it is the pattern declining to guess.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .classify import classify_all
from .ledger import DEFAULT_REQUIRED_SAMPLES, Ledger, LedgerError, build_store
from .locate import LocateError, locate
from .resolve import Resolution, resolve_attributes
from .sanitize import altered_attributes, build_record
from .sign import branch_name, sign_all


def _resolver(repo_root: Path, workspace_dir: Path):
    """Bind source-layer tracing to a checked-out repository for ``classify_all``."""

    def resolve_layers(entry: dict[str, Any]) -> dict[str, str]:
        address = entry.get("address", "")
        attributes = list(entry.get("changed_attributes") or [])
        return {
            r.attribute: r.layer
            for r in resolve_attributes(address, attributes, repo_root, workspace_dir)
        }

    return resolve_layers


def _edit_sites(
    address: str,
    attributes: list[str],
    repo_root: Path,
    workspace_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """The authorized (file, line) per attribute, and any attribute that lost its site.

    An attribute can pass the scope guard and still fail here if its resolution carries no
    edit location. That is treated as a hard stop for that attribute rather than a
    fallback to the resource block, because writing into the block when the value lives in
    ``tfvars`` produces a change that the next plan immediately contradicts.
    """
    sites: list[dict[str, Any]] = []
    lost: list[dict[str, str]] = []

    resolutions: list[Resolution] = resolve_attributes(address, attributes, repo_root, workspace_dir)
    for resolution in resolutions:
        if not resolution.is_workspace_local or resolution.edit_file is None:
            lost.append(
                {
                    "attribute": resolution.attribute,
                    "code": f"source_layer_{resolution.layer}",
                    "reason": resolution.reason,
                }
            )
            continue
        sites.append(
            {
                "attribute": resolution.attribute,
                "layer": resolution.layer,
                "file": resolution.edit_file,
                "line": resolution.edit_line,
                # The identifier assigned on that line, which for a tfvars or variable
                # site is not the attribute's name. The verifier checks against this.
                "assigned_name": resolution.edit_name,
                "current_expression": resolution.expression,
                "chain": [h.as_dict() for h in resolution.chain],
            }
        )
    return sites, lost


def build_work_order(
    decision: dict[str, Any],
    drift_entry: dict[str, Any],
    repo_root: str | Path,
    workspace_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Assemble one work order, or an escalation if it cannot be fully bounded."""
    root = Path(repo_root)
    workspace = Path(workspace_dir) if workspace_dir is not None else root
    address = decision.get("config_address") or decision.get("address") or ""
    attributes = list(decision.get("authorized_attributes") or [])

    # Sanitize first, because it can disqualify an attribute. If neutralization had to
    # alter the observed value - invisible characters removed, a run collapsed, a long
    # value truncated - then the value on hand is no longer the value that is deployed.
    # Codifying it would write something the next plan immediately contradicts, and would
    # also mean the verifier compares the agent's edit against a value nobody observed.
    # So an altered value is escalated rather than repaired.
    preliminary = build_record(drift_entry, {**decision, "authorized_attributes": attributes})
    altered = set(altered_attributes(preliminary))

    lost: list[dict[str, str]] = [
        {
            "attribute": path,
            "code": "value_not_faithfully_representable",
            "reason": "the observed value had to be altered to be handled safely, so it "
            "cannot be codified faithfully; a human should inspect the live value directly",
        }
        for path in sorted(altered)
    ]

    sites, unresolved = _edit_sites(
        address, [a for a in attributes if a not in altered], root, workspace
    )
    lost += unresolved

    if not sites:
        return {
            "verdict": "escalate",
            "address": address,
            "code": "no_editable_location",
            "reason": "no attribute retained an editable location in this workspace",
            "rejected_attributes": lost,
        }

    # The block is an anchor for review and for the verifier's containment check, not an
    # edit target in itself: a tfvars-sourced value is edited outside the block entirely.
    anchor: dict[str, Any] | None = None
    try:
        target = locate(address, root)
        anchor = {
            "file": target.file,
            "block_start_line": target.block_start_line,
            "block_end_line": target.block_end_line,
        }
    except LocateError:
        anchor = None

    authorized = [s["attribute"] for s in sites]
    record = build_record(drift_entry, {**decision, "authorized_attributes": authorized})

    return {
        "verdict": "codify",
        "resource_address": address,
        "resource_type": decision.get("type") or drift_entry.get("type"),
        "declaration": anchor,
        "edit_sites": sites,
        "drift": record,
        "rejected_attributes": list(decision.get("rejected_attributes") or []) + lost,
        "constraint": (
            "Change only the value at each listed file and line, and only for the listed "
            "attribute. Do not add, remove or reorder anything else, and do not introduce "
            "lifecycle or ignore_changes blocks. Any other change is rejected."
        ),
    }


def authorize(
    reconciled: dict[str, Any],
    gate_a: dict[str, Any] | None,
    refresh_only_plan: dict[str, Any],
    repo_root: str | Path,
    workspace_dir: str | Path | None = None,
    confirmed_samples: int = 1,
    sample_counts: dict[str, int] | None = None,
    observations: dict[str, dict[str, Any]] | None = None,
    signatures: dict[str, str] | None = None,
    **classify_kwargs: Any,
) -> dict[str, Any]:
    """Run the full deterministic chain from reconciled drift to bounded work orders.

    ``sample_counts`` maps resource address to its consecutive-observation count from the
    ledger. ``confirmed_samples`` is the fallback for any address the ledger has no entry
    for, and defaults to 1 - unconfirmed - because the alternative default silently
    converts the debounce into a no-op.
    """
    root = Path(repo_root)
    workspace = Path(workspace_dir) if workspace_dir is not None else root
    counts = sample_counts or {}

    def resolve_samples(entry: dict[str, Any]) -> int:
        return counts.get(entry.get("address", ""), confirmed_samples)

    classification = classify_all(
        reconciled,
        gate_a=gate_a,
        layer_resolver=_resolver(root, workspace),
        sample_resolver=resolve_samples,
        **classify_kwargs,
    )

    by_address = {
        e.get("address"): e
        for e in (refresh_only_plan.get("resource_drift") or [])
        if e.get("address")
    }

    work_orders: list[dict[str, Any]] = []
    escalations: list[dict[str, Any]] = list(classification["escalate"])

    for decision in classification["codify"]:
        entry = by_address.get(decision.get("address"))
        if entry is None:
            escalations.append(
                {
                    "verdict": "escalate",
                    "address": decision.get("address"),
                    "reason": "cleared for codification but absent from the refresh-only "
                    "plan, so its values cannot be read",
                }
            )
            continue

        order = build_work_order(decision, entry, root, workspace)
        if order["verdict"] == "codify":
            address = decision.get("address", "")
            if signatures and address in signatures:
                order["signature"] = signatures[address]
                order["branch"] = branch_name(signatures[address], str(workspace.name))
            work_orders.append(order)
        else:
            escalations.append(order)

    return {
        "work_orders": work_orders,
        "escalate": escalations,
        "suppress": classification["suppress"],
        "observations": observations or {},
        "counts": {
            "work_orders": len(work_orders),
            "escalate": len(escalations),
            "suppress": len(classification["suppress"]),
        },
        "has_work": bool(work_orders),
    }


def _load(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert reconciled drift into bounded, agent-executable work orders"
    )
    parser.add_argument("--reconciled", required=True, help="output of drift-reconcile")
    parser.add_argument("--gate-a", required=True, help="output of drift-gate-a")
    parser.add_argument(
        "--refresh-only-plan", required=True, help="terraform show -json of the refresh-only plan"
    )
    parser.add_argument("--repo-root", required=True, help="checkout of the target repository")
    parser.add_argument(
        "--workspace-dir",
        help="root module Terraform ran against, relative to the repository root; this is "
        "what makes 'local to this workspace' decidable",
    )
    parser.add_argument(
        "--confirmed-samples",
        type=int,
        default=1,
        help="fallback consecutive-observation count for any address the ledger has no "
        "entry for. Defaults to 1, which suppresses: a single observation may be a "
        "transient flap, and codifying one permanently is worse than waiting a cycle",
    )
    parser.add_argument(
        "--ledger-table",
        help="DynamoDB table recording consecutive observations per drift signature. "
        "Without it every signature reads as a first observation and nothing is confirmed, "
        "which suppresses rather than inventing confirmation",
    )
    parser.add_argument(
        "--workspace-id",
        help="identifies this workspace in the drift signature's salt, so identical drift "
        "in a sibling workspace cannot share one signature or one pull request",
    )
    parser.add_argument("--repo", help="target repository, the other half of the salt")
    parser.add_argument(
        "--build-number",
        type=int,
        help="monotonic build number, used to decide whether this observation is "
        "consecutive with the previous one. Elapsed time is not used: it has to guess the "
        "cadence and silently accepts a gap when a run fails",
    )
    parser.add_argument(
        "--required-samples",
        type=int,
        default=DEFAULT_REQUIRED_SAMPLES,
        help="consecutive observations required before drift may be codified",
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    root = Path(args.repo_root)
    workspace = root / args.workspace_dir if args.workspace_dir else root

    reconciled = _load(args.reconciled)
    refresh_only_plan = _load(args.refresh_only_plan)

    # Sign, then record. Both are needed for the debounce to mean anything: the signature
    # is what makes "the same drift" decidable, and the ledger is what makes "consecutive"
    # decidable. Missing either one leaves every count at 1, which suppresses.
    signatures: dict[str, str] = {}
    observations: dict[str, dict[str, Any]] = {}
    sample_counts: dict[str, int] = {}

    if args.workspace_id and args.repo:
        signatures = sign_all(reconciled, refresh_only_plan, args.workspace_id, args.repo)

        if args.build_number is not None:
            ledger = Ledger(
                build_store(args.ledger_table), required_samples=args.required_samples
            )
            try:
                observations = ledger.observe(signatures, args.build_number)
            except LedgerError as exc:
                # Fail closed. If the count cannot be written, the next run cannot establish
                # consecutiveness, and proceeding would let drift accumulate confirmation it
                # never earned.
                print(f"observation ledger unavailable: {exc}", file=sys.stderr)
                return 1
            sample_counts = ledger.counts(observations)
        else:
            print(
                "no --build-number given, so consecutiveness cannot be established; every "
                "signature counts as a first observation and will be suppressed",
                file=sys.stderr,
            )
    else:
        print(
            "no --workspace-id/--repo given, so drift cannot be signed and observations "
            "cannot be counted; falling back to --confirmed-samples",
            file=sys.stderr,
        )

    result = authorize(
        reconciled,
        _load(args.gate_a),
        refresh_only_plan,
        root,
        workspace,
        confirmed_samples=args.confirmed_samples,
        sample_counts=sample_counts,
        observations=observations,
        signatures=signatures,
    )

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)

    counts = result["counts"]
    print(
        f"authorized {counts['work_orders']} work order(s); "
        f"{counts['escalate']} escalated, {counts['suppress']} suppressed",
        file=sys.stderr,
    )
    for address, observation in sorted(result.get("observations", {}).items()):
        state = "confirmed" if observation["confirmed"] else "unconfirmed"
        print(
            f"  ledger {address}: {observation['consecutive_samples']}/"
            f"{observation['required_samples']} {state} — {observation['reason']}",
            file=sys.stderr,
        )
    for order in result["work_orders"]:
        for site in order["edit_sites"]:
            print(
                f"  {order['resource_address']}.{site['attribute']} -> "
                f"{site['file']}:{site['line']} ({site['layer']})",
                file=sys.stderr,
            )
    for escalation in result["escalate"]:
        print(
            f"  ESCALATE {escalation.get('address') or escalation.get('resource_address')}: "
            f"{escalation.get('reason', '')}",
            file=sys.stderr,
        )

    # Nothing to codify is a normal outcome, not a failure. Exit status stays 0 so a
    # quiet estate does not look like a broken pipeline; the caller reads has_work.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
