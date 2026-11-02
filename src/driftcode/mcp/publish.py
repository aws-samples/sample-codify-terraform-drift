"""Open, or converge on, exactly one pull request per drift.

This is the write path's policy layer: the GitHub client knows how to call the API, and this
decides what to call and what each outcome means.

Two rules from the design shape everything here.

**A failed gate must still open a pull request.** The instinct is to withhold the change when
a scan fails, but the dangerous configuration is *already live* - suppressing the pull request
leaves code and reality out of sync while production stays exposed, which is the exact failure
this pattern exists to fix. So a pull request opens on every gate outcome; the outcome selects
labels and body, not existence.

**A rejected diff must never open a pull request.** That is a different condition, and
conflating the two inverts the response to each. A failed gate means "the drift is real and
dangerous - a human must see it". A failed verification means "the change is not the change the
work order authorized", so its content is untrustworthy and publishing it would put an
unreviewed edit in front of a reviewer wearing the pipeline's credibility. That escalates
without a pull request.

Everything is keyed on the drift signature, so a retry converges instead of accumulating.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .github import (
    AdoptionConflict,
    GitHub,
    GitHubError,
    PullRequest,
    marker,
    verify_adoptable,
)

#: Applied when the drift is codified and every gate passed.
LABEL_CLEAN = "drift-codified"
#: Applied when a gate failed. Paired with a body that says which, and why.
LABEL_BLOCKED = ["do-not-merge", "security-review-required"]
#: Applied when the pull request opens before the gates have run.
#:
#: This exists because Gate B needs to read Terraform state and the codify worker deliberately
#: cannot: the worker holding a repository write credential is not also given access to the
#: state that names every resource in the estate. So the gates run in a separately privileged
#: worker afterwards, and the pull request opens in a state that says so. A reviewer seeing this
#: label must treat the change as un-scanned - which is why it is paired with do-not-merge
#: rather than standing alone.
LABEL_PENDING = ["do-not-merge", "gates-pending"]

CLEAN = "clean"
BLOCKED = "blocked"
PENDING = "pending"

LABELS_BY_OUTCOME = {
    CLEAN: [LABEL_CLEAN],
    BLOCKED: list(LABEL_BLOCKED),
    PENDING: list(LABEL_PENDING),
}


@dataclass
class FileEdit:
    """One file's new contents, already verified against the work order."""

    path: str
    content: str
    #: Blob sha of the version being replaced, so a concurrent edit fails rather than
    #: silently losing the other writer's change.
    blob_sha: str | None = None


@dataclass
class Published:
    pull: PullRequest
    branch: str
    commits: list[str]
    labels: list[str]
    outcome: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "pull_request": self.pull.as_dict(),
            "branch": self.branch,
            "commits": self.commits,
            "labels": self.labels,
            # Named for what it is - the gate routing decision - so it cannot be conflated
            # with the caller's own outcome when the two are merged into one record.
            "gate_outcome": self.outcome,
        }


def commit_message(work_order: dict[str, Any]) -> str:
    """A conventional-commit subject naming the resource and attributes changed."""
    address = work_order.get("resource_address", "unknown")
    resource = address.split(".")[-1]
    attributes = ", ".join(s["attribute"] for s in work_order.get("edit_sites") or [])
    return f"chore(drift): codify {resource} {attributes}"


def pull_body(
    work_order: dict[str, Any],
    workspace_id: str,
    gate_results: dict[str, Any] | None = None,
    verification: dict[str, Any] | None = None,
    deployed_commit: str = "",
    outcome: str = PENDING,
) -> str:
    """Assemble the review context.

    Written by the orchestrator from recorded outputs, never by the agent. The agent formats
    code; it does not get to report on the gates that judged it, or the body becomes a claim
    the pipeline cannot stand behind.
    """
    signature = work_order.get("signature", "")
    lines = [
        marker(signature, workspace_id),
        "",
        "## Codified drift",
        "",
        f"An operator changed live infrastructure directly. This makes the configuration "
        f"say what `{work_order.get('resource_address')}` already is, so the next apply is a "
        "no-op.",
        "",
        "| Attribute | In code | Live | Now |",
        "| --- | --- | --- | --- |",
    ]

    for attribute in (work_order.get("drift") or {}).get("attributes") or []:
        old = attribute.get("current_value_in_code")
        new = attribute.get("observed_value_in_cloud")
        lines.append(f"| `{attribute.get('path')}` | `{old}` | `{new}` | `{new}` |")

    lines += ["", "## Where the value lives", ""]
    for site in work_order.get("edit_sites") or []:
        lines.append(
            f"- `{site['file']}:{site['line']}` — `{site['assigned_name']}`, resolved as "
            f"**{site['layer']}**"
        )

    rejected = work_order.get("rejected_attributes") or []
    if rejected:
        lines += ["", "## Not codified", ""]
        for item in rejected:
            lines.append(f"- `{item.get('attribute')}` — {item.get('reason')}")

    if verification:
        lines += [
            "",
            "## Verification",
            "",
            f"- Diff verified against the work order: **{verification.get('verdict')}** "
            f"({verification.get('counts', {}).get('verified_edits', 0)} authorized edit(s), "
            "nothing else changed)",
        ]

    if outcome == PENDING:
        lines += [
            "",
            "## Gates: not yet run",
            "",
            "The policy gates have not run against this branch. Gate B needs to read Terraform "
            "state, and the worker that opened this pull request deliberately cannot: the "
            "component holding a write credential is not also given access to the state that "
            "names every resource in the estate. A separately privileged run scans this branch "
            "and updates these labels.",
            "",
            "**Until then, treat this change as unscanned.**",
        ]

    if gate_results:
        lines += ["", "## Gates", ""]
        for name, result in sorted(gate_results.items()):
            verdict = result.get("verdict") if isinstance(result, dict) else result
            lines.append(f"- **{name}**: {verdict}")
            for failure in (result.get("failures") or []) if isinstance(result, dict) else []:
                lines.append(f"  - {failure}")

    lines += [
        "",
        "## Provenance",
        "",
        f"- Drift signature: `{signature}`",
        f"- Workspace: `{workspace_id}`",
    ]
    if deployed_commit:
        lines.append(f"- Reconciled against commit: `{deployed_commit}`")
    lines += [
        "",
        "Values above were read from live cloud state and are treated as untrusted data. The "
        "file, line and attribute changed were computed outside the model, and any diff "
        "touching anything else is rejected before this pull request can open.",
    ]

    return "\n".join(lines)


def publish(
    client: GitHub,
    work_order: dict[str, Any],
    edits: list[FileEdit],
    base_branch: str,
    base_sha: str,
    workspace_id: str,
    outcome: str = PENDING,
    gate_results: dict[str, Any] | None = None,
    verification: dict[str, Any] | None = None,
    deployed_commit: str = "",
) -> Published:
    """Converge on one pull request for this drift, whatever ran before.

    Safe to call twice: the branch name is derived from the signature, creation is attempted
    unconditionally, and an existing pull request is adopted only after proving it describes
    the same drift in the same workspace.
    """
    branch = work_order.get("branch")
    signature = work_order.get("signature", "")
    if not branch or not signature:
        raise GitHubError(
            "work order carries no branch or signature; both are required for an idempotent "
            "write, and without them a retry would open a second pull request"
        )
    if not edits:
        raise GitHubError("nothing to publish: no file edits supplied")

    created = client.create_branch(branch, base_sha)

    message = commit_message(work_order)
    commits: list[str] = []
    for edit in edits:
        blob_sha = edit.blob_sha
        if blob_sha is None:
            # Look it up on the branch, not on base: a retry after a partial run finds the
            # already-updated blob and must replace that version, not the original.
            blob_sha = client.file_sha(edit.path, branch)
        sha = client.put_file(edit.path, edit.content, branch, message, blob_sha)
        if sha:
            commits.append(sha)

    body = pull_body(
        work_order, workspace_id, gate_results, verification, deployed_commit, outcome
    )
    title = message

    pull, status = client.create_pull(title, body, branch, base_branch)

    if pull is None:
        # 422: something occupies the head branch. Adopt it only if it is provably ours.
        existing = client.pull_for_branch(branch)
        if existing is None:
            raise GitHubError(
                f"creating a pull request for {branch} was refused as already existing, but "
                "no pull request for that branch can be found; refusing to guess"
            )
        verify_adoptable(existing, signature, workspace_id)
        existing.adopted = True
        pull = existing

    labels = LABELS_BY_OUTCOME.get(outcome, list(LABEL_BLOCKED))
    client.add_labels(pull.number, labels)

    return Published(
        pull=pull,
        branch=branch,
        commits=commits,
        labels=labels,
        outcome=outcome,
    )


def escalate_without_pull(
    work_order: dict[str, Any],
    reason: str,
    detail: Any = None,
) -> dict[str, Any]:
    """The outcome for a rejected diff: a report, and no pull request.

    Deliberately not a labelled pull request. A failed *gate* means the drift is real and
    dangerous and a human must see it, so that opens one. A failed *verification* means the
    change is not the change the work order authorized, so its content has no standing -
    publishing it would put an unreviewed edit in front of a reviewer under the pipeline's
    name.
    """
    return {
        "outcome": "escalate_no_pull",
        "resource_address": work_order.get("resource_address"),
        "signature": work_order.get("signature"),
        "branch": work_order.get("branch"),
        "reason": reason,
        "detail": detail,
        "note": (
            "No pull request was opened. The diff did not match the work order, so its "
            "content is untrusted; a labelled pull request would imply a reviewable change "
            "where there is none. The drift itself remains live and still needs attention."
        ),
    }


__all__ = [
    "BLOCKED",
    "CLEAN",
    "LABELS_BY_OUTCOME",
    "LABEL_PENDING",
    "PENDING",
    "LABEL_BLOCKED",
    "LABEL_CLEAN",
    "AdoptionConflict",
    "FileEdit",
    "Published",
    "commit_message",
    "escalate_without_pull",
    "publish",
    "pull_body",
]
