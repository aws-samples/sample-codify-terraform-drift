"""Stand up one codify session as an MCP server over stdio.

One session per work order, deliberately. A server holding several would let a task for one
resource read files authorized for another, and the containment argument depends on the
authorized set being exactly one work order's worth.

The credential is read from the environment and never taken as an argument, so it cannot end
up in a process listing or a build log. This is the only component in the pipeline that holds
a write credential at all.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .github import GitHub, GitHubError
from .github_app import credential_for
from .server import CodifySession, serve


def _load(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def select_work_order(authorization: dict[str, Any], address: str | None) -> dict[str, Any]:
    """Pick the one work order this session is bound to.

    An ambiguous selection is an error rather than a default: silently taking the first would
    make which resource got codified depend on dictionary ordering.
    """
    orders = authorization.get("work_orders") or []
    if not orders:
        raise SystemExit("authorization contains no work orders; nothing to codify")

    if address:
        matches = [o for o in orders if o.get("resource_address") == address]
        if not matches:
            available = ", ".join(o.get("resource_address", "?") for o in orders)
            raise SystemExit(f"no work order for {address}. Available: {available}")
        return matches[0]

    if len(orders) > 1:
        available = ", ".join(o.get("resource_address", "?") for o in orders)
        raise SystemExit(
            f"{len(orders)} work orders present; pass --resource-address to choose one. "
            f"Available: {available}"
        )
    return orders[0]


def build_session(args: argparse.Namespace) -> CodifySession:
    authorization = _load(args.authorization)
    work_order = select_work_order(authorization, args.resource_address)

    client = None
    if not args.dry_run:
        client = GitHub(repo=args.repo, token=credential_for(args.repo, os.environ.get)[0])

    deployed_commit = ""
    if args.deployed_commit_file and Path(args.deployed_commit_file).is_file():
        deployed_commit = Path(args.deployed_commit_file).read_text(encoding="utf-8").strip()

    return CodifySession(
        # The session is scoped to one order, but the verifier is given an authorization
        # containing only that order too - otherwise a diff touching a sibling's file would
        # verify against the sibling's sites and pass.
        work_order=work_order,
        repo_root=Path(args.repo_root),
        authorization={"work_orders": [work_order]},
        workspace_id=args.workspace_id,
        base_branch=args.base_branch,
        base_sha=args.base_sha,
        deployed_commit=deployed_commit or args.deployed_commit,
        gate_results=_load(args.gate_results) if args.gate_results else None,
        client=client,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--authorization", required=True, help="output of drift-authorize")
    parser.add_argument("--repo-root", required=True, help="checkout of the target repository")
    parser.add_argument("--repo", help="owner/name of the target repository on GitHub")
    parser.add_argument("--workspace-id", default="dev")
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--base-sha", default="", help="commit the branch is cut from")
    parser.add_argument("--deployed-commit", default="", help="commit reconciled against")
    parser.add_argument("--deployed-commit-file", help="file holding that commit, e.g. target-head.txt")
    parser.add_argument("--gate-results", help="JSON of gate outcomes, recorded in the PR body")
    parser.add_argument(
        "--resource-address",
        help="which work order to serve, required when the authorization holds more than one",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="serve the tools and verify, but hold no credential and write nothing",
    )
    parser.add_argument(
        "--complete-on-exit",
        action="store_true",
        help="after the agent's session ends, verify the staged change and publish it. This "
        "step is deliberately not reachable from the tool surface",
    )
    parser.add_argument("--result", help="where to write the session outcome")
    args = parser.parse_args(argv)

    if not args.dry_run and not args.repo:
        parser.error("--repo is required unless --dry-run is given")

    try:
        session = build_session(args)
    except GitHubError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    serve(session)

    if not args.complete_on_exit:
        return 0

    result = session.complete()
    if args.result:
        with open(args.result, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)

    outcome = result.get("outcome")
    if outcome == "published":
        pull = result["pull_request"]
        print(
            f"{'adopted' if pull['adopted'] else 'opened'} pull request #{pull['number']}: "
            f"{pull['url']} [{', '.join(result['labels'])}]",
            file=sys.stderr,
        )
        return 0

    if outcome == "verified_not_published":
        print("verification passed; nothing written (dry run)", file=sys.stderr)
        return 0

    print(f"escalated without a pull request: {result.get('reason')}", file=sys.stderr)
    for violation in (result.get("detail") or {}).get("violations", []):
        print(f"  [{violation['kind']}] {violation.get('detail', '')}", file=sys.stderr)
    # Non-zero: the drift is still live and unaddressed, which must not read as success.
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
