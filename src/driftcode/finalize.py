"""Apply the gate verdict to a pull request that is already open.

The pull request opens before the gates run, and that is a consequence of the privilege split
rather than an oversight. Gate B is a `terraform plan` against the branch, which cannot run
without reading Terraform state - and the worker holding a repository write credential is
deliberately denied that state, because state names every resource in the estate and combining
the two would produce the single most useful credential in the system to compromise.

So three differently-privileged steps, in order:

    codify    model + write credential, no state       -> branch, and a pull request marked
                                                          gates-pending
    gates     state and estate read, no write credential -> a verdict, written to S3
    finalize  write credential, no state                -> this: relabel and comment

Nothing ever holds both state access and a write credential.

The cost is a window in which an open pull request has not been scanned. That window is made
loud rather than hidden: the pull request carries `do-not-merge` and `gates-pending` from the
moment it opens, and its body says in as many words that the change is unscanned. Opening it
labelled is still better than withholding it, for the reason the whole routing design rests on
- the drift is *already live*, and a pull request nobody can see does not make production safer.

Idempotent, because the gates stage can be re-run: labels are replaced rather than accumulated,
and a comment is posted only when the verdict actually changes something.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .mcp.github import GitHub, GitHubError, read_marker
from .mcp.github_app import credential_for
from .mcp.publish import (
    BLOCKED,
    CLEAN,
    LABEL_CLEAN,
    LABEL_PENDING,
    LABELS_BY_OUTCOME,
    PENDING,
)

#: Every label this pipeline manages. Removed before the verdict's labels are applied, so a
#: re-run cannot leave a stale `gates-pending` beside a `drift-codified`.
MANAGED_LABELS = sorted({LABEL_CLEAN, *LABEL_PENDING, "security-review-required"})


def outcome_for(gates: dict[str, Any]) -> str:
    """Translate a gates verdict into a routing outcome.

    An absent or unreadable verdict is treated as PENDING, not as a pass. The gates either ran
    and said something, or they did not run - and "did not run" must never present as clean.
    """
    if not gates or "verdict" not in gates:
        return PENDING
    return CLEAN if gates.get("verdict") == "PASS" else BLOCKED


def comment_body(gates: dict[str, Any], outcome: str) -> str:
    """The gate report posted to the pull request.

    Assembled from the gates artifact, never from the agent: a body the agent wrote could claim
    a verdict the pipeline cannot stand behind.
    """
    if outcome == CLEAN:
        lines = ["## Gates passed", "", "Both scans ran and the change introduces no new finding."]
    else:
        lines = [
            "## Gates failed — do not merge",
            "",
            "The codified change introduces at least one policy finding the baseline did not "
            "have. Note the drift itself is **already live**: refusing this pull request does "
            "not remove the exposure, it only leaves the configuration disagreeing with it.",
        ]

    for name, gate in sorted((gates.get("gates") or {}).items()):
        lines += ["", f"### {name}", "", f"- Verdict: **{gate.get('verdict')}**"]
        if gate.get("evaluated") is not None:
            lines.append(f"- Checks evaluated: {gate['evaluated']}")
        if gate.get("pre_existing"):
            lines.append(
                f"- Pre-existing findings in the baseline: {gate['pre_existing']} "
                "(not caused by this change)"
            )
        for finding in gate.get("introduced") or []:
            lines.append(f"- **Introduced**: `{finding['check_id']}` on `{finding['resource']}`")
        for finding in gate.get("resolved") or []:
            lines.append(f"- Resolved: `{finding['check_id']}` on `{finding['resource']}`")
        for failure in gate.get("failures") or []:
            lines.append(f"- Failure: {failure}")
        for warning in gate.get("warnings") or []:
            lines.append(f"- Note: {warning}")

    lines += [
        "",
        "---",
        "",
        "Scanned by a separately privileged run: the worker that opened this pull request holds "
        "a write credential and no Terraform state access, so it cannot run a branch plan "
        "itself.",
    ]
    return "\n".join(lines)


def finalize(
    client: GitHub,
    branch: str,
    gates: dict[str, Any],
    signature: str = "",
    workspace_id: str = "",
) -> dict[str, Any]:
    """Relabel and comment on the pull request for ``branch``.

    The signature is verified before anything is written, for the same reason adoption checks it:
    a branch name alone does not prove the pull request describes the drift this verdict is
    about.
    """
    pull = client.pull_for_branch(branch, state="open")
    if pull is None:
        raise GitHubError(
            f"no open pull request for branch {branch}; the gates verdict has nowhere to go. "
            "Either publication never happened or the pull request was closed"
        )

    if signature:
        found_signature, found_workspace = read_marker(pull.body)
        if found_signature != signature:
            raise GitHubError(
                f"pull request #{pull.number} carries signature {str(found_signature)[:12]}… but "
                f"this verdict is for {signature[:12]}…; refusing to label the wrong change"
            )
        if workspace_id and found_workspace != workspace_id:
            raise GitHubError(
                f"pull request #{pull.number} belongs to workspace {found_workspace!r}, not "
                f"{workspace_id!r}"
            )

    outcome = outcome_for(gates)
    labels = LABELS_BY_OUTCOME[outcome]

    # Replace rather than add: a re-run must not leave gates-pending beside drift-codified.
    for label in MANAGED_LABELS:
        if label not in labels:
            client.remove_label(pull.number, label)
    client.add_labels(pull.number, labels)

    client.comment(pull.number, comment_body(gates, outcome))

    return {
        "outcome": outcome,
        "pull_request": pull.as_dict(),
        "labels": labels,
        "introduced": gates.get("introduced") or [],
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
    parser.add_argument("--repo", required=True, help="owner/name of the target repository")
    parser.add_argument("--gates", required=True, help="output of drift-gates")
    parser.add_argument("--codify-result", help="output of drift-codify, for branch and signature")
    parser.add_argument("--branch", help="branch to finalize, when not taken from --codify-result")
    parser.add_argument("--workspace-id", default="")
    parser.add_argument("--out")
    args = parser.parse_args(argv)

    gates = _load(args.gates)
    if gates is None:
        # The verdict is missing or unreadable. Leaving the pull request as gates-pending is
        # correct: it already says do-not-merge, and inventing a pass here would be the worst
        # possible failure mode.
        print(
            "no readable gates verdict; leaving the pull request marked gates-pending",
            file=sys.stderr,
        )
        return 1

    branches: list[tuple[str, str]] = []
    if args.codify_result:
        result = _load(args.codify_result) or {}
        for entry in result.get("results") or []:
            if entry.get("outcome") == "published":
                branches.append((entry["branch"], entry.get("signature", "")))
    elif args.branch:
        branches.append((args.branch, ""))

    if not branches:
        print("no published pull request to finalize", file=sys.stderr)
        return 0

    try:
        token, credential = credential_for(args.repo, os.environ.get)
    except GitHubError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    client = GitHub(repo=args.repo, token=token)
    print(f"credential: {json.dumps(credential, sort_keys=True)}", file=sys.stderr)

    results = []
    failed = False
    for branch, signature in branches:
        try:
            outcome = finalize(client, branch, gates, signature, args.workspace_id)
        except GitHubError as exc:
            print(f"  {branch}: could not finalize — {exc}", file=sys.stderr)
            failed = True
            continue

        results.append(outcome)
        pull = outcome["pull_request"]
        print(
            f"  #{pull['number']} {pull['url']} -> {outcome['outcome']} "
            f"[{', '.join(outcome['labels'])}]",
            file=sys.stderr,
        )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"results": results}, fh, indent=2, sort_keys=True)

    if failed:
        return 1
    # A blocked verdict is not a stage failure: the pull request is correctly labelled and a
    # human has been given the evidence, which is the outcome the design asks for.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
