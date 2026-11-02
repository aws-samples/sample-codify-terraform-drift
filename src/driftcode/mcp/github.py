"""The single write path to GitHub, and the only component holding a write credential.

Everything upstream of this is read-only by construction: detection cannot write Terraform
state, the agent holds no AWS credentials, and the verifier only reads a diff. This module is
where the pipeline is finally allowed to change something, so it is deliberately the
narrowest surface in the system - a handful of operations against one repository, each of
which either succeeds idempotently or fails loudly.

Idempotency is the hard part, and it is not optional: a retried run, an overlapping run, or a
Step Functions redrive must converge on **one** pull request rather than opening a second one
for drift already under review. Three rules make that hold, and each rules out a specific
race:

  * **The branch name is derived from the drift signature**, not from a timestamp or a run
    id. Two runs that see the same drift compute the same branch, so they collide by design
    instead of forking.
  * **Never list-then-create.** Checking whether a pull request exists and then creating one
    is a time-of-check-to-time-of-use gap wide enough for a concurrent run to fit through.
    Creation is attempted unconditionally and the 422 that means "already exists" is treated
    as a normal outcome.
  * **Adopting an existing pull request requires proving it is the same drift.** A 422 alone
    says only that *something* occupies that head branch. Before adopting it, the full
    signature and the workspace are checked against the marker in its body. A branch name
    collision that is not the same drift is an error, not an adoption.

References are updated with a compare-and-swap on the expected sha, never a force push. An
unexpected sha means someone else moved the branch, which is a condition to report rather
than overwrite.

The transport is injected so the whole module is testable without a network, and the default
one uses only the standard library - the same reason the rest of the package has no runtime
dependencies.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

API = "https://api.github.com"

#: Marker embedded in every pull-request body. Adoption checks this rather than the branch
#: name alone, so a name collision cannot be mistaken for the same drift.
MARKER_PREFIX = "drift-signature:"
WORKSPACE_PREFIX = "drift-workspace:"


class GitHubError(Exception):
    """A GitHub API failure that the caller must not paper over."""

    def __init__(self, message: str, status: int | None = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class AdoptionConflict(GitHubError):
    """A pull request occupies the branch but describes different drift.

    Separate from GitHubError because the response is different: this is never retryable and
    always needs a human, since two distinct drifts have computed the same branch name or
    something outside the pipeline is using it.
    """


class Transport(Protocol):
    def __call__(
        self, method: str, url: str, body: dict[str, Any] | None, headers: dict[str, str]
    ) -> tuple[int, Any]: ...


def urllib_transport(
    method: str, url: str, body: dict[str, Any] | None, headers: dict[str, str]
) -> tuple[int, Any]:
    """Standard-library transport. Returns ``(status, parsed_body)`` without raising on 4xx.

    HTTP errors are returned rather than raised because several of them - notably the 422
    that means "already exists" and the 404 that means "not yet" - are expected control flow
    here, not failures.

    The scheme is asserted rather than assumed. ``urlopen`` honours ``file://``, so a URL
    reaching here with a non-HTTPS scheme would read from the local filesystem and return its
    contents to the caller. The API root is a configurable field, so "the scheme is always
    https" is a property of the configuration rather than of this code, and it is checked here
    because this is the single point every request passes through.
    """
    scheme = urllib.parse.urlparse(url).scheme
    if scheme != "https":
        raise GitHubError(f"refusing a non-HTTPS request URL: scheme {scheme!r} in {url!r}")

    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = {"message": raw}
        return exc.code, parsed
    except urllib.error.URLError as exc:
        raise GitHubError(f"could not reach GitHub: {exc.reason}") from exc


@dataclass
class PullRequest:
    number: int
    url: str
    head: str
    state: str
    adopted: bool = False
    body: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "url": self.url,
            "head": self.head,
            "state": self.state,
            "adopted": self.adopted,
        }


@dataclass
class GitHub:
    """Minimal GitHub client covering exactly the write path this pattern needs."""

    repo: str
    token: str
    transport: Transport = urllib_transport
    api: str = API
    #: Recorded so a caller can audit what was actually sent, without the token.
    calls: list[tuple[str, str]] = field(default_factory=list)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "driftcode",
        }

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> tuple[int, Any]:
        url = f"{self.api}/repos/{self.repo}{path}"
        self.calls.append((method, path))
        return self.transport(method, url, body, self._headers())

    # --- refs ----------------------------------------------------------------------

    def branch_sha(self, branch: str) -> str | None:
        """Head sha of a branch, or ``None`` when it does not exist."""
        status, body = self._request("GET", f"/git/ref/heads/{branch}")
        if status == 404:
            return None
        if status >= 300:
            raise GitHubError(f"could not read branch {branch}", status, body)
        return (body.get("object") or {}).get("sha")

    def create_branch(self, branch: str, from_sha: str) -> bool:
        """Create a branch. Returns False when it already existed.

        The 422 is expected: a concurrent run computing the same signature computes the same
        branch, which is the intended collision.
        """
        status, body = self._request(
            "POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": from_sha}
        )
        if status in (200, 201):
            return True
        if status == 422:
            return False
        raise GitHubError(f"could not create branch {branch}", status, body)

    def update_branch(self, branch: str, to_sha: str, expected_sha: str) -> None:
        """Move a branch, refusing if it is not at the expected sha.

        A compare-and-swap rather than a force push. An unexpected sha means another writer
        moved the branch; overwriting it would discard their work silently, so this reports
        instead. GitHub has no native compare-and-swap on refs, so the check is read-then-write
        with ``force: false`` as the backstop - it rejects a non-fast-forward, which covers the
        case that matters.
        """
        current = self.branch_sha(branch)
        if current != expected_sha:
            raise GitHubError(
                f"branch {branch} moved from {expected_sha} to {current}; refusing to "
                "overwrite another writer's commit"
            )
        status, body = self._request(
            "PATCH", f"/git/refs/heads/{branch}", {"sha": to_sha, "force": False}
        )
        if status >= 300:
            raise GitHubError(f"could not update branch {branch}", status, body)

    # --- contents ------------------------------------------------------------------

    def file_sha(self, path: str, ref: str) -> str | None:
        """Blob sha of a file at a ref, or ``None`` when absent."""
        status, body = self._request("GET", f"/contents/{path}?ref={ref}")
        if status == 404:
            return None
        if status >= 300:
            raise GitHubError(f"could not read {path} at {ref}", status, body)
        if isinstance(body, list):
            raise GitHubError(f"{path} is a directory, not a file")
        return body.get("sha")

    def put_file(
        self, path: str, content: str, branch: str, message: str, blob_sha: str | None = None
    ) -> str:
        """Write a file on a branch, returning the resulting commit sha.

        ``blob_sha`` is the sha of the version being replaced; GitHub rejects the write if it
        does not match, which is what makes a concurrent edit to the same file a failure
        rather than a lost update.
        """
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if blob_sha:
            payload["sha"] = blob_sha

        status, body = self._request("PUT", f"/contents/{path}", payload)
        if status not in (200, 201):
            raise GitHubError(f"could not write {path} on {branch}", status, body)
        return ((body or {}).get("commit") or {}).get("sha", "")

    # --- pull requests -------------------------------------------------------------

    def create_pull(
        self, title: str, body: str, head: str, base: str, draft: bool = False
    ) -> tuple[PullRequest | None, int]:
        """Attempt creation unconditionally. Returns ``(pull, status)``.

        ``pull`` is ``None`` on 422, which means something already occupies the head branch.
        Deciding whether that something describes this drift is the caller's job, and requires
        more than a branch-name match.
        """
        status, response = self._request(
            "POST",
            "/pulls",
            {"title": title, "body": body, "head": head, "base": base, "draft": draft},
        )
        if status in (200, 201):
            return (
                PullRequest(
                    number=response["number"],
                    url=response["html_url"],
                    head=head,
                    state=response.get("state", "open"),
                    body=response.get("body") or "",
                ),
                status,
            )
        if status == 422:
            return None, status
        raise GitHubError(f"could not create pull request for {head}", status, response)

    def pull_for_branch(self, head: str, state: str = "all") -> PullRequest | None:
        """Find the pull request whose head is this branch.

        Only ever called after a 422, never before creation - using it as a pre-check would
        reintroduce the time-of-check-to-time-of-use gap that creating unconditionally
        avoids.
        """
        owner = self.repo.split("/")[0]
        status, body = self._request("GET", f"/pulls?head={owner}:{head}&state={state}")
        if status >= 300:
            raise GitHubError(f"could not list pull requests for {head}", status, body)
        if not body:
            return None
        first = body[0]
        return PullRequest(
            number=first["number"],
            url=first["html_url"],
            head=head,
            state=first.get("state", "open"),
            body=first.get("body") or "",
        )

    def add_labels(self, number: int, labels: list[str]) -> None:
        if not labels:
            return
        status, body = self._request(
            "POST", f"/issues/{number}/labels", {"labels": labels}
        )
        if status >= 300:
            raise GitHubError(f"could not label pull request #{number}", status, body)

    def remove_label(self, number: int, label: str) -> bool:
        """Remove one label. Returns False when it was not present.

        A 404 is expected and not an error: labels are replaced on every finalize run, so most
        removals target something that is not there. Treating that as a failure would make an
        idempotent operation look broken.
        """
        status, body = self._request("DELETE", f"/issues/{number}/labels/{label}")
        if status in (200, 204):
            return True
        if status == 404:
            return False
        raise GitHubError(f"could not remove label {label} from #{number}", status, body)

    def comment(self, number: int, text: str) -> None:
        status, body = self._request("POST", f"/issues/{number}/comments", {"body": text})
        if status >= 300:
            raise GitHubError(f"could not comment on pull request #{number}", status, body)


# --- signature marker ---------------------------------------------------------------


def marker(signature: str, workspace_id: str) -> str:
    """The identity block embedded in a pull-request body.

    Both halves are required for adoption. The signature alone is not enough: the same drift
    in two workspaces is two different changes, and adopting across them would attach one
    estate's remediation to another's review.
    """
    return f"<!-- {MARKER_PREFIX}{signature} {WORKSPACE_PREFIX}{workspace_id} -->"


def read_marker(body: str) -> tuple[str | None, str | None]:
    """Extract ``(signature, workspace_id)`` from a pull-request body."""
    signature = workspace = None
    for token in (body or "").replace(">", " ").split():
        if token.startswith(MARKER_PREFIX):
            signature = token[len(MARKER_PREFIX) :] or None
        elif token.startswith(WORKSPACE_PREFIX):
            workspace = token[len(WORKSPACE_PREFIX) :] or None
    return signature, workspace


def verify_adoptable(pull: PullRequest, signature: str, workspace_id: str) -> None:
    """Confirm an existing pull request describes exactly this drift, or refuse.

    This is the check that makes idempotency safe rather than merely convenient. Without it,
    "the branch already exists" would be enough to attach a run's output to whatever happened
    to be there.
    """
    found_signature, found_workspace = read_marker(pull.body)

    if found_signature is None:
        raise AdoptionConflict(
            f"pull request #{pull.number} occupies branch {pull.head} but carries no drift "
            "signature; it was not opened by this pipeline and must not be adopted"
        )
    if found_signature != signature:
        raise AdoptionConflict(
            f"pull request #{pull.number} on branch {pull.head} carries signature "
            f"{found_signature[:12]}… but this run computed {signature[:12]}…; two different "
            "drifts cannot share one review"
        )
    if found_workspace != workspace_id:
        raise AdoptionConflict(
            f"pull request #{pull.number} belongs to workspace {found_workspace!r}, not "
            f"{workspace_id!r}; identical drift in a sibling workspace is a different change"
        )


def token_from_environment(getenv: Callable[[str], str | None]) -> str:
    """Read the write credential, refusing to run without one.

    Named separately so the failure is legible: an absent credential should say so, not
    surface later as a 401 from an operation the caller thought was permitted.
    """
    for name in ("DRIFT_GITHUB_TOKEN", "GITHUB_TOKEN", "GIT_TOKEN"):
        value = getenv(name)
        if value:
            return value
    raise GitHubError(
        "no GitHub credential found in DRIFT_GITHUB_TOKEN, GITHUB_TOKEN or GIT_TOKEN. This "
        "is the only component that holds a write credential, so it cannot proceed without "
        "one"
    )
