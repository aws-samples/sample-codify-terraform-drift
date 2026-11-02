"""The write path: the one component that holds a write credential.

The tests that matter are the convergence ones. A retried run, an overlapping run or a
redrive must end with exactly one pull request, and adopting an existing one must require
proof that it describes the same drift — a branch-name match is not proof.
"""

from __future__ import annotations

import base64
import json

import pytest

from driftcode.mcp.github import (
    AdoptionConflict,
    GitHub,
    GitHubError,
    marker,
    read_marker,
    token_from_environment,
    verify_adoptable,
)
from driftcode.mcp.publish import (
    CLEAN,
    LABEL_BLOCKED,
    LABEL_CLEAN,
    LABEL_PENDING,
    PENDING,
    FileEdit,
    commit_message,
    escalate_without_pull,
    publish,
    pull_body,
)

SIGNATURE = "a" * 64
BRANCH = f"drift/dev-{SIGNATURE}"
WORKSPACE = "dev"
REPO = "acme/infra"


class FakeGitHub:
    """A GitHub stand-in with just enough state to exercise convergence.

    Records every call so a test can assert on the *sequence* — notably that creation is
    attempted before any listing, since listing first is the race this design avoids.
    """

    def __init__(self, branches=None, pulls=None, files=None):
        self.branches = dict(branches or {"main": "base-sha"})
        self.pulls = list(pulls or [])
        self.files = dict(files or {})
        self.calls: list[tuple[str, str]] = []
        self.next_number = 100
        self.fail_on: dict[str, tuple[int, dict]] = {}

    def _record(self, method, path):
        self.calls.append((method, path))

    def __call__(self, method, url, body, headers):
        path = url.split(f"/repos/{REPO}", 1)[1]
        self._record(method, path)

        if path in self.fail_on:
            return self.fail_on[path]

        if method == "GET" and path.startswith("/git/ref/heads/"):
            branch = path.rsplit("/", 1)[1]
            if branch not in self.branches:
                return 404, {"message": "Not Found"}
            return 200, {"object": {"sha": self.branches[branch]}}

        if method == "POST" and path == "/git/refs":
            branch = body["ref"].removeprefix("refs/heads/")
            if branch in self.branches:
                return 422, {"message": "Reference already exists"}
            self.branches[branch] = body["sha"]
            return 201, {"ref": body["ref"]}

        if method == "PATCH" and path.startswith("/git/refs/heads/"):
            branch = path.rsplit("/", 1)[1]
            self.branches[branch] = body["sha"]
            return 200, {"object": {"sha": body["sha"]}}

        if method == "GET" and path.startswith("/contents/"):
            file_path = path.removeprefix("/contents/").split("?")[0]
            if file_path not in self.files:
                return 404, {"message": "Not Found"}
            return 200, {"sha": self.files[file_path]}

        if method == "PUT" and path.startswith("/contents/"):
            file_path = path.removeprefix("/contents/")
            existing = self.files.get(file_path)
            if existing and body.get("sha") != existing:
                return 409, {"message": "sha mismatch"}
            self.files[file_path] = f"blob-{len(self.calls)}"
            return 200, {"commit": {"sha": f"commit-{len(self.calls)}"}}

        if method == "POST" and path == "/pulls":
            if any(p["head"] == body["head"] for p in self.pulls):
                return 422, {"message": "A pull request already exists"}
            pull = {
                "number": self.next_number,
                "html_url": f"https://github.com/{REPO}/pull/{self.next_number}",
                "head": body["head"],
                "state": "open",
                "body": body["body"],
            }
            self.next_number += 1
            self.pulls.append(pull)
            return 201, pull

        if method == "GET" and path.startswith("/pulls?head="):
            head = path.split("head=")[1].split("&")[0].split(":")[1]
            return 200, [p for p in self.pulls if p["head"] == head]

        if method == "POST" and "/labels" in path:
            return 200, []

        if method == "POST" and "/comments" in path:
            return 201, {}

        return 500, {"message": f"unhandled {method} {path}"}


def client(fake: FakeGitHub) -> GitHub:
    return GitHub(repo=REPO, token="t", transport=fake)


def work_order(signature=SIGNATURE, branch=BRANCH) -> dict:
    return {
        "verdict": "codify",
        "resource_address": "module.compute.aws_launch_template.app",
        "resource_type": "aws_launch_template",
        "signature": signature,
        "branch": branch,
        "edit_sites": [
            {
                "attribute": "instance_type",
                "assigned_name": "instance_type",
                "layer": "workspace_tfvars",
                "file": "environments/dev/terraform.tfvars",
                "line": 7,
            }
        ],
        "drift": {
            "attributes": [
                {
                    "path": "instance_type",
                    "current_value_in_code": "t3.micro",
                    "observed_value_in_cloud": "t2.micro",
                }
            ]
        },
        "rejected_attributes": [
            {"attribute": "latest_version", "code": "not_codifiable_by_schema", "reason": "computed"}
        ],
    }


def edits() -> list[FileEdit]:
    return [FileEdit(path="environments/dev/terraform.tfvars", content='instance_type = "t2.micro"\n')]


# --- the happy path -----------------------------------------------------------------


def test_a_pull_request_opens_on_the_signature_branch():
    fake = FakeGitHub()

    result = publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)

    assert result.branch == BRANCH
    assert result.pull.number == 100
    assert result.pull.adopted is False
    assert fake.branches[BRANCH] == "base-sha"
    # PENDING by default: Gate B needs Terraform state, which this worker deliberately lacks,
    # so the gates run afterwards in a differently privileged stage.
    assert result.labels == LABEL_PENDING


def test_an_unscanned_pull_request_says_so_and_is_not_mergeable():
    """The window before the gates run is made loud rather than hidden."""
    fake = FakeGitHub()

    publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)

    body = fake.pulls[0]["body"]
    assert "do-not-merge" in LABEL_PENDING
    assert "treat this change as unscanned" in body
    assert "Gate B needs to read Terraform state" in body


def test_a_clean_outcome_labels_it_codified():
    fake = FakeGitHub()

    result = publish(
        client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE, outcome=CLEAN
    )

    assert result.labels == [LABEL_CLEAN]


def test_the_body_carries_the_signature_marker():
    fake = FakeGitHub()

    publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)

    signature, workspace = read_marker(fake.pulls[0]["body"])
    assert signature == SIGNATURE
    assert workspace == WORKSPACE


def test_creation_is_attempted_before_any_listing():
    """Listing first would be a time-of-check-to-time-of-use gap a concurrent run fits in."""
    fake = FakeGitHub()

    publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)

    pull_calls = [c for c in fake.calls if c[1].startswith("/pulls")]
    assert pull_calls[0] == ("POST", "/pulls"), pull_calls


def test_the_file_is_written_with_its_new_contents():
    fake = FakeGitHub()

    publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)

    assert "environments/dev/terraform.tfvars" in fake.files


def test_a_replaced_file_is_written_against_the_sha_being_replaced():
    """Without it a concurrent edit to the same file is a silent lost update."""
    fake = FakeGitHub(files={"environments/dev/terraform.tfvars": "original-blob"})
    fake.branches[BRANCH] = "base-sha"

    publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)

    assert ("GET", "/contents/environments/dev/terraform.tfvars?ref=" + BRANCH) in fake.calls


# --- convergence: the same run twice ------------------------------------------------


def test_publishing_twice_converges_on_one_pull_request():
    fake = FakeGitHub()

    first = publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)
    second = publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)

    assert len(fake.pulls) == 1
    assert second.pull.number == first.pull.number
    assert second.pull.adopted is True


def test_an_existing_branch_is_not_an_error():
    """A concurrent run computing the same signature computes the same branch, by design."""
    fake = FakeGitHub(branches={"main": "base-sha", BRANCH: "base-sha"})

    result = publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)

    assert result.pull.number == 100


def test_adoption_requires_the_matching_signature():
    """A 422 says only that something occupies the branch, not that this pipeline put it there."""
    other = "b" * 64
    fake = FakeGitHub(
        pulls=[
            {
                "number": 7,
                "html_url": "u",
                "head": BRANCH,
                "state": "open",
                "body": marker(other, WORKSPACE),
            }
        ]
    )

    with pytest.raises(AdoptionConflict, match="cannot share one review"):
        publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)


def test_adoption_requires_the_matching_workspace():
    """Identical drift in a sibling workspace is a different change."""
    fake = FakeGitHub(
        pulls=[
            {
                "number": 7,
                "html_url": "u",
                "head": BRANCH,
                "state": "open",
                "body": marker(SIGNATURE, "prod"),
            }
        ]
    )

    with pytest.raises(AdoptionConflict, match="sibling workspace"):
        publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)


def test_a_pull_request_from_outside_the_pipeline_is_never_adopted():
    fake = FakeGitHub(
        pulls=[{"number": 7, "html_url": "u", "head": BRANCH, "state": "open", "body": "hand-written"}]
    )

    with pytest.raises(AdoptionConflict, match="not opened by this pipeline"):
        publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)


def test_a_422_with_no_findable_pull_request_refuses_to_guess():
    fake = FakeGitHub()
    fake.fail_on["/pulls"] = (422, {"message": "already exists"})

    with pytest.raises(GitHubError, match="refusing to guess"):
        publish(client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE)


# --- routing: gates versus verification ---------------------------------------------


def test_a_failed_gate_still_opens_a_pull_request_but_labelled():
    """The dangerous configuration is already live; withholding the PR hides it."""
    fake = FakeGitHub()

    result = publish(
        client(fake), work_order(), edits(), "main", "base-sha", WORKSPACE,
        outcome="blocked",
        gate_results={"Gate B": {"verdict": "FAIL", "failures": ["CKV_AWS_24 on the SG"]}},
    )

    assert result.pull.number == 100
    assert result.labels == LABEL_BLOCKED
    assert "CKV_AWS_24" in fake.pulls[0]["body"]


def test_a_rejected_diff_opens_no_pull_request_at_all():
    """Different from a failed gate: the change is not the change that was authorized."""
    report = escalate_without_pull(
        work_order(), "verification rejected the diff", {"violations": [{"kind": "wrong_value"}]}
    )

    assert report["outcome"] == "escalate_no_pull"
    assert report["signature"] == SIGNATURE
    assert "still needs attention" in report["note"]


# --- guard rails --------------------------------------------------------------------


def test_publishing_without_a_signature_is_refused():
    order = work_order()
    del order["signature"]

    with pytest.raises(GitHubError, match="idempotent"):
        publish(client(FakeGitHub()), order, edits(), "main", "base-sha", WORKSPACE)


def test_publishing_without_a_branch_is_refused():
    order = work_order()
    del order["branch"]

    with pytest.raises(GitHubError, match="idempotent"):
        publish(client(FakeGitHub()), order, edits(), "main", "base-sha", WORKSPACE)


def test_publishing_no_edits_is_refused():
    with pytest.raises(GitHubError, match="nothing to publish"):
        publish(client(FakeGitHub()), work_order(), [], "main", "base-sha", WORKSPACE)


def test_a_branch_that_moved_is_not_force_updated():
    fake = FakeGitHub(branches={"main": "base-sha", BRANCH: "someone-elses-sha"})

    with pytest.raises(GitHubError, match="refusing to overwrite"):
        client(fake).update_branch(BRANCH, "new-sha", expected_sha="base-sha")


def test_a_missing_credential_says_so_rather_than_failing_later_as_a_401():
    with pytest.raises(GitHubError, match="no GitHub credential"):
        token_from_environment(lambda _: None)


@pytest.mark.parametrize("name", ["DRIFT_GITHUB_TOKEN", "GITHUB_TOKEN", "GIT_TOKEN"])
def test_the_credential_is_read_from_any_supported_variable(name: str):
    assert token_from_environment(lambda n: "secret" if n == name else None) == "secret"


# --- the review context -------------------------------------------------------------


def test_the_body_explains_where_the_value_lives():
    body = pull_body(work_order(), WORKSPACE)

    assert "environments/dev/terraform.tfvars:7" in body
    assert "workspace_tfvars" in body


def test_the_body_lists_what_was_not_codified():
    body = pull_body(work_order(), WORKSPACE)

    assert "latest_version" in body
    assert "Not codified" in body


def test_the_body_records_the_commit_reconciled_against():
    body = pull_body(work_order(), WORKSPACE, deployed_commit="abc1234")

    assert "abc1234" in body


def test_the_body_carries_the_full_signature_not_a_prefix():
    body = pull_body(work_order(), WORKSPACE)

    assert SIGNATURE in body


def test_the_commit_message_names_the_resource_and_attribute():
    assert commit_message(work_order()) == "chore(drift): codify app instance_type"


# --- client primitives --------------------------------------------------------------


def test_an_absent_branch_reads_as_none_not_an_error():
    assert client(FakeGitHub()).branch_sha("nope") is None


def test_an_absent_file_reads_as_none_not_an_error():
    assert client(FakeGitHub()).file_sha("nope.tf", "main") is None


def test_file_content_is_base64_encoded_on_write():
    fake = FakeGitHub()
    captured = {}

    def spy(method, url, body, headers):
        if method == "PUT":
            captured.update(body)
        return fake(method, url, body, headers)

    GitHub(repo=REPO, token="t", transport=spy).put_file(
        "a.tf", 'x = "y"\n', "main", "msg"
    )

    assert base64.b64decode(captured["content"]).decode() == 'x = "y"\n'


def test_the_token_is_sent_as_a_bearer_header_and_not_logged():
    seen = {}

    def spy(method, url, body, headers):
        seen.update(headers)
        return 200, {"object": {"sha": "s"}}

    gh = GitHub(repo=REPO, token="super-secret", transport=spy)
    gh.branch_sha("main")

    assert seen["Authorization"] == "Bearer super-secret"
    # The recorded call log is for auditing and must not carry the credential.
    assert "super-secret" not in json.dumps(gh.calls)


def test_marker_round_trips():
    text = f"preamble\n{marker(SIGNATURE, 'prod')}\ntrailer"

    assert read_marker(text) == (SIGNATURE, "prod")


def test_verify_adoptable_accepts_a_match():
    from driftcode.mcp.github import PullRequest

    pull = PullRequest(number=1, url="u", head=BRANCH, state="open", body=marker(SIGNATURE, WORKSPACE))

    verify_adoptable(pull, SIGNATURE, WORKSPACE)  # must not raise



# --- the transport asserts its scheme ---------------------------------------
# urlopen honours file://, so a non-HTTPS URL reaching the transport would read the local
# filesystem and hand the contents back as if they were an API response. The API root is a
# configurable field, so https is a property of the configuration rather than of the code,
# and the transport is the one place every request passes through.


def test_the_transport_refuses_a_file_url():
    from driftcode.mcp.github import urllib_transport

    with pytest.raises(GitHubError) as excinfo:
        urllib_transport("GET", "file:///etc/passwd", None, {})

    assert "non-HTTPS" in str(excinfo.value)
    assert "file" in str(excinfo.value)


def test_the_transport_refuses_plain_http():
    from driftcode.mcp.github import urllib_transport

    with pytest.raises(GitHubError):
        urllib_transport("GET", "http://api.github.com/repos/o/r", None, {})


def test_the_transport_rejects_before_opening_anything():
    """The guard must run before urlopen, or it is documentation rather than a control."""
    import driftcode.mcp.github as mod

    opened: list[object] = []

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        opened.append(args)
        raise AssertionError("urlopen must not be reached for a rejected scheme")

    original = mod.urllib.request.urlopen
    mod.urllib.request.urlopen = explode
    try:
        with pytest.raises(GitHubError):
            mod.urllib_transport("GET", "file:///etc/passwd", None, {})
    finally:
        mod.urllib.request.urlopen = original

    assert opened == []
