"""The codify stage: one work order, one agent, one verified pull request or an escalation.

This is the orchestrator the pipeline runs. It owns the sequence that the security argument
depends on, and the ordering is not incidental:

    build the session   -> the authorized set is fixed before the model is reachable
    run the agent       -> it can only stage, and only within that set
    complete            -> the diff is computed here, verified here, published here

Nothing the model returns is trusted as a result. Its prose is recorded and ignored; what
happened is whatever the session staged, and what is reported is whatever the verifier found.
The pull-request body is assembled from recorded outputs by
:mod:`driftcode.mcp.publish`, never by the agent, so the review context cannot be a claim the
pipeline is unable to stand behind.

Exit status is the pipeline's signal, and it distinguishes three outcomes that are easy to
collapse into one:

    0   a pull request exists for this drift, whether opened now or adopted from a retry
    0   nothing to do - no work order survived detection, which is a quiet estate
    1   the drift is still live and unaddressed: the agent declined, the diff was rejected,
        or the model never produced one. A pipeline must not read that as success.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import agent as agent_module
from .mcp.cli import select_work_order
from .mcp.github import GitHub, GitHubError
from .mcp.github_app import credential_for
from .mcp.server import CodifySession


def _load(path: str | None) -> Any:
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _read(path: str | None) -> str:
    if not path or not Path(path).is_file():
        return ""
    return Path(path).read_text(encoding="utf-8").strip()


def codify_one(
    work_order: dict[str, Any],
    repo_root: Path,
    workspace_id: str,
    client: GitHub | None,
    converse: agent_module.ConverseClient,
    base_branch: str,
    base_sha: str,
    deployed_commit: str,
    gate_results: dict[str, Any] | None,
    model_id: str,
    max_turns: int,
) -> dict[str, Any]:
    """Codify one work order end to end and return the record of what happened."""
    session = CodifySession(
        work_order=work_order,
        repo_root=repo_root,
        # Scoped to this order alone. An authorization holding siblings would let a diff
        # touching a sibling's file verify against the sibling's sites and pass.
        authorization={"work_orders": [work_order]},
        workspace_id=workspace_id,
        base_branch=base_branch,
        base_sha=base_sha,
        deployed_commit=deployed_commit,
        gate_results=gate_results,
        client=client,
    )

    run = agent_module.run(session, converse, model_id=model_id, max_turns=max_turns)
    print(f"  {agent_module.summary(run)}", file=sys.stderr)

    result = session.complete()
    result["agent"] = run.as_dict()
    result["resource_address"] = work_order.get("resource_address")
    # Carried so the finalize step can find this pull request and prove it is the right one.
    # Reading them off the work order rather than the publish result means they are present
    # even when publication failed, which is when a human most needs to know which branch.
    result["branch"] = work_order.get("branch")
    result["signature"] = work_order.get("signature")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--authorization", required=True, help="output of drift-authorize")
    parser.add_argument("--repo-root", required=True, help="checkout of the target repository")
    parser.add_argument("--repo", help="owner/name of the target repository on GitHub")
    parser.add_argument("--workspace-id", default="dev")
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--base-sha", default="", help="commit the drift branch is cut from")
    parser.add_argument("--deployed-commit-file", help="e.g. target-head.txt from detection")
    parser.add_argument("--gate-results", help="JSON of gate outcomes, recorded in the PR body")
    parser.add_argument("--resource-address", help="codify only this work order")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--model-id", default=agent_module.DEFAULT_MODEL_ID)
    parser.add_argument("--max-turns", type=int, default=agent_module.DEFAULT_MAX_TURNS)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run the agent and verify, but hold no credential and open no pull request",
    )
    parser.add_argument("--out", help="where to write the stage result")
    args = parser.parse_args(argv)

    if not args.dry_run and not args.repo:
        parser.error("--repo is required unless --dry-run is given")

    authorization = _load(args.authorization) or {}
    orders = authorization.get("work_orders") or []

    if not orders:
        # A quiet estate. Detection ran, found nothing codifiable, and said so; that is a
        # normal outcome and must not fail the pipeline.
        print("no work orders to codify", file=sys.stderr)
        if args.out:
            Path(args.out).write_text(json.dumps({"results": [], "counts": {}}, indent=2), encoding="utf-8")
        return 0

    if args.resource_address:
        orders = [select_work_order(authorization, args.resource_address)]

    client = None
    credential: dict[str, Any] = {}
    if not args.dry_run:
        try:
            token, credential = credential_for(args.repo, os.environ.get)
        except GitHubError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        client = GitHub(repo=args.repo, token=token)
        # Logged so a run records WHICH KIND of credential wrote to the repository. The value
        # is never included - as_dict on an installation token deliberately omits it.
        print(f"credential: {json.dumps(credential, sort_keys=True)}", file=sys.stderr)

    converse = agent_module.bedrock_client(args.region)
    deployed_commit = _read(args.deployed_commit_file)
    gate_results = _load(args.gate_results)

    results: list[dict[str, Any]] = []
    for order in orders:
        print(f"codifying {order.get('resource_address')}", file=sys.stderr)
        results.append(
            codify_one(
                order,
                Path(args.repo_root),
                args.workspace_id,
                client,
                converse,
                args.base_branch,
                args.base_sha or deployed_commit,
                deployed_commit,
                gate_results,
                args.model_id,
                args.max_turns,
            )
        )

    counts: dict[str, int] = {}
    for result in results:
        counts[result["outcome"]] = counts.get(result["outcome"], 0) + 1

    payload = {"results": results, "counts": counts, "credential": credential}
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(file=sys.stderr)
    for result in results:
        if result["outcome"] == "published":
            pull = result["pull_request"]
            verb = "adopted" if pull["adopted"] else "opened"
            print(
                f"  {result['resource_address']}: {verb} #{pull['number']} {pull['url']} "
                f"[{', '.join(result['labels'])}]",
                file=sys.stderr,
            )
        elif result["outcome"] == "verified_not_published":
            print(f"  {result['resource_address']}: verified, nothing written (dry run)", file=sys.stderr)
        elif result["outcome"] == "publication_failed":
            # Distinct from a rejected diff and reported as such: the change was correct and
            # the write did not land, so a retry is the right response rather than a rewrite.
            retry = "retryable" if result.get("retryable") else "NOT retryable"
            print(
                f"  {result['resource_address']}: PUBLICATION FAILED ({retry}) — "
                f"{result['error_type']}: {result['error']}",
                file=sys.stderr,
            )
        else:
            print(f"  {result['resource_address']}: ESCALATED — {result.get('reason')}", file=sys.stderr)
            for violation in (result.get("detail") or {}).get("violations", []):
                print(f"      [{violation['kind']}] {violation.get('detail', '')}", file=sys.stderr)

    # Non-zero whenever drift is still live with nothing in front of a human - whether the
    # diff was rejected, the agent declined, or the write failed. Reporting success for any of
    # those is how an escalation becomes a silent no-op.
    unaddressed = [
        r for r in results if r["outcome"] in ("escalate_no_pull", "publication_failed")
    ]
    if unaddressed:
        print(
            f"\n{len(unaddressed)} of {len(results)} resource(s) still unaddressed",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
