"""Applying the gate verdict to a pull request opened before the gates ran.

The window between publication and the verdict exists because of the privilege split: Gate B
needs Terraform state, and the worker holding a write credential is denied it. So the property
worth testing is that the window is *loud* — the pull request is unmergeable and says it is
unscanned — and that an absent or unreadable verdict never resolves to a pass.
"""

from __future__ import annotations

import json

import pytest

from driftcode.finalize import MANAGED_LABELS, comment_body, finalize, main, outcome_for
from driftcode.mcp.github import GitHub, GitHubError, marker
from driftcode.mcp.publish import BLOCKED, CLEAN, LABEL_CLEAN, LABEL_PENDING, PENDING

SIGNATURE = "a" * 64
BRANCH = f"drift/dev-{SIGNATURE}"
REPO = "acme/infra"
WORKSPACE = "dev"
SG = "module.networking.aws_security_group.web_prod"


class FakePR:
    """A GitHub stand-in tracking labels and comments on one pull request."""

    def __init__(self, body=None, number=42, exists=True):
        self.number = number
        self.body = body if body is not None else marker(SIGNATURE, WORKSPACE)
        self.exists = exists
        self.labels: set[str] = set(LABEL_PENDING)
        self.comments: list[str] = []
        self.removed: list[str] = []

    def __call__(self, method, url, body, headers):
        path = url.split(f"/repos/{REPO}", 1)[1]

        if method == "GET" and path.startswith("/pulls?head="):
            if not self.exists:
                return 200, []
            return 200, [
                {"number": self.number, "html_url": f"https://x/{self.number}",
                 "head": BRANCH, "state": "open", "body": self.body}
            ]
        if method == "POST" and path.endswith("/labels"):
            self.labels |= set(body["labels"])
            return 200, []
        if method == "DELETE" and "/labels/" in path:
            label = path.rsplit("/", 1)[1]
            self.removed.append(label)
            if label not in self.labels:
                return 404, {"message": "Label does not exist"}
            self.labels.discard(label)
            return 200, []
        if method == "POST" and path.endswith("/comments"):
            self.comments.append(body["body"])
            return 201, {}
        return 500, {"message": f"unhandled {method} {path}"}


def client(fake) -> GitHub:
    return GitHub(repo=REPO, token="t", transport=fake)


def gates(verdict="PASS", introduced=(), pre_existing=2):
    return {
        "verdict": verdict,
        "introduced": [{"check_id": c, "resource": r} for c, r in introduced],
        "gates": {
            "Gate B (branch plan, variables resolved)": {
                "verdict": verdict,
                "evaluated": 9,
                "pre_existing": pre_existing,
                "introduced": [{"check_id": c, "resource": r} for c, r in introduced],
                "resolved": [],
                "failures": [] if verdict == "PASS" else ["introduces CKV_AWS_24"],
                "warnings": ["2 pre-existing finding(s) in the baseline"],
            },
            "Gate C (source directory, variables resolved without a plan)": {
                "verdict": verdict,
                "evaluated": 17,
                "pre_existing": pre_existing,
                "introduced": [],
                "resolved": [],
                "failures": [],
                "warnings": [],
            },
        },
    }


# --- an absent verdict is never a pass ----------------------------------------------


@pytest.mark.parametrize("value", [None, {}, {"gates": {}}, {"counts": {}}])
def test_a_missing_verdict_stays_pending(value):
    """"Did not run" must never present as clean."""
    assert outcome_for(value) == PENDING


def test_a_pass_becomes_clean():
    assert outcome_for(gates("PASS")) == CLEAN


def test_a_fail_becomes_blocked():
    assert outcome_for(gates("FAIL")) == BLOCKED


def test_an_unreadable_verdict_file_leaves_the_pull_request_pending(tmp_path):
    bad = tmp_path / "gates.json"
    bad.write_text("{not json", encoding="utf-8")

    code = main(["--repo", REPO, "--gates", str(bad), "--branch", BRANCH])

    assert code == 1


# --- relabelling --------------------------------------------------------------------


def test_a_pass_replaces_pending_with_codified():
    fake = FakePR()

    result = finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)

    assert result["outcome"] == CLEAN
    assert fake.labels == {LABEL_CLEAN}
    assert "do-not-merge" not in fake.labels
    assert "gates-pending" not in fake.labels


def test_a_failure_keeps_it_unmergeable():
    fake = FakePR()

    result = finalize(client(fake), BRANCH, gates("FAIL", [("CKV_AWS_24", SG)]), SIGNATURE, WORKSPACE)

    assert result["outcome"] == BLOCKED
    assert "do-not-merge" in fake.labels
    assert "security-review-required" in fake.labels
    assert LABEL_CLEAN not in fake.labels


def test_stale_labels_are_removed_not_accumulated():
    """A re-run must not leave gates-pending beside drift-codified."""
    fake = FakePR()

    finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)

    assert set(fake.removed) >= {"do-not-merge", "gates-pending"}
    assert fake.labels == {LABEL_CLEAN}


def test_finalizing_twice_converges():
    fake = FakePR()

    finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)
    finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)

    assert fake.labels == {LABEL_CLEAN}


def test_a_verdict_can_flip_from_pass_to_fail_on_a_re_run():
    fake = FakePR()
    finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)

    finalize(client(fake), BRANCH, gates("FAIL", [("CKV_AWS_24", SG)]), SIGNATURE, WORKSPACE)

    assert LABEL_CLEAN not in fake.labels
    assert "do-not-merge" in fake.labels


def test_every_managed_label_is_one_this_pipeline_applies():
    """Removing a label the pipeline does not own would fight the reviewer."""
    assert set(MANAGED_LABELS) == {LABEL_CLEAN, "do-not-merge", "gates-pending", "security-review-required"}


# --- labelling the wrong change -----------------------------------------------------


def test_a_signature_mismatch_refuses_to_label():
    """A branch name alone does not prove the pull request is the change this verdict is about."""
    fake = FakePR(body=marker("b" * 64, WORKSPACE))

    with pytest.raises(GitHubError, match="refusing to label the wrong change"):
        finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)

    assert fake.comments == []


def test_a_workspace_mismatch_refuses_to_label():
    fake = FakePR(body=marker(SIGNATURE, "prod"))

    with pytest.raises(GitHubError, match="workspace"):
        finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)


def test_a_missing_pull_request_is_an_error_not_a_silent_pass():
    fake = FakePR(exists=False)

    with pytest.raises(GitHubError, match="nowhere to go"):
        finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)


# --- the comment --------------------------------------------------------------------


def test_the_comment_reports_each_gate():
    fake = FakePR()

    finalize(client(fake), BRANCH, gates("PASS"), SIGNATURE, WORKSPACE)

    body = fake.comments[0]
    assert "Gate B" in body and "Gate C" in body
    assert "Checks evaluated: 9" in body
    assert "Checks evaluated: 17" in body


def test_the_comment_names_the_introduced_finding():
    fake = FakePR()

    finalize(client(fake), BRANCH, gates("FAIL", [("CKV_AWS_24", SG)]), SIGNATURE, WORKSPACE)

    assert "CKV_AWS_24" in fake.comments[0]
    assert "Introduced" in fake.comments[0]


def test_the_comment_says_pre_existing_findings_are_not_this_changes_fault():
    body = comment_body(gates("PASS"), CLEAN)

    assert "not caused by this change" in body


def test_a_failure_comment_says_the_drift_is_already_live():
    """Refusing the pull request does not remove the exposure, and the reviewer should know."""
    body = comment_body(gates("FAIL", [("CKV_AWS_24", SG)]), BLOCKED)

    assert "already live" in body
    assert "do not merge" in body.lower()


def test_the_comment_explains_why_a_separate_run_scanned_it():
    body = comment_body(gates("PASS"), CLEAN)

    assert "separately privileged" in body
    assert "no Terraform state access" in body


# --- the command-line surface ------------------------------------------------------


def test_cli_finalizes_every_published_branch(tmp_path, monkeypatch):
    fake = FakePR()
    monkeypatch.setenv("DRIFT_GITHUB_TOKEN", "t")
    monkeypatch.setattr("driftcode.finalize.GitHub", lambda repo, token: client(fake))

    (tmp_path / "gates.json").write_text(json.dumps(gates("PASS")), encoding="utf-8")
    (tmp_path / "codify.json").write_text(
        json.dumps(
            {
                "results": [
                    {"outcome": "published", "branch": BRANCH, "signature": SIGNATURE},
                    {"outcome": "escalate_no_pull", "branch": "drift/dev-other", "signature": "c" * 64},
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "finalize.json"

    code = main(
        [
            "--repo", REPO,
            "--gates", str(tmp_path / "gates.json"),
            "--codify-result", str(tmp_path / "codify.json"),
            "--workspace-id", WORKSPACE,
            "--out", str(out),
        ]
    )

    assert code == 0
    # Only the published one is finalized; an escalation has no pull request to label.
    assert len(json.loads(out.read_text())["results"]) == 1
    assert fake.labels == {LABEL_CLEAN}


def test_cli_exits_zero_on_a_blocked_verdict(tmp_path, monkeypatch):
    """A blocked verdict is the design working: the PR is labelled and a human has the evidence."""
    fake = FakePR()
    monkeypatch.setenv("DRIFT_GITHUB_TOKEN", "t")
    monkeypatch.setattr("driftcode.finalize.GitHub", lambda repo, token: client(fake))

    (tmp_path / "gates.json").write_text(
        json.dumps(gates("FAIL", [("CKV_AWS_24", SG)])), encoding="utf-8"
    )

    code = main(["--repo", REPO, "--gates", str(tmp_path / "gates.json"), "--branch", BRANCH])

    assert code == 0
    assert "do-not-merge" in fake.labels


def test_cli_with_nothing_published_is_not_a_failure(tmp_path):
    (tmp_path / "gates.json").write_text(json.dumps(gates("PASS")), encoding="utf-8")
    (tmp_path / "codify.json").write_text(json.dumps({"results": []}), encoding="utf-8")

    code = main(
        [
            "--repo", REPO,
            "--gates", str(tmp_path / "gates.json"),
            "--codify-result", str(tmp_path / "codify.json"),
        ]
    )

    assert code == 0
