"""Mint short-lived, narrowly-scoped GitHub credentials from a GitHub App.

The write path needs a credential, and the question is what kind. A personal access token is
the easy answer and the wrong one: it authenticates as a human, it carries whatever scope that
human has across every repository they can reach, and it does not expire. In a pipeline where
one worker holds both a model and a write credential, that worker becomes the most valuable
thing in the system to compromise, and a PAT makes the reward for compromising it "everything
that person can touch".

A GitHub App installation token is the same three lines of HTTP with a different shape:

  * scoped to the repositories the App is *installed* on, not to an account
  * limited to the permissions the App declares - here Contents and Pull requests, nothing else
  * valid for one hour, so a leaked token is a bounded problem rather than a permanent one
  * identified as the App in the audit log, so a commit is attributable to the pipeline rather
    than appearing to come from a person who did not make it

The exchange is two steps. A JWT signed with the App's private key proves *who the App is*;
that JWT buys an installation token which proves *what it may do here*. Only the second one
ever touches a repository, and only the second one is passed to anything else.

RS256 signing needs a real asymmetric implementation, which the standard library does not
provide - so this module is the one place the package requires ``cryptography``. It is imported
lazily and lives behind the same optional extra as boto3, so nothing else in the package gains
a dependency because of it.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from .github import API, GitHubError, Transport, token_from_environment, urllib_transport

#: GitHub rejects a JWT valid for more than ten minutes. Nine leaves room for clock skew in
#: either direction without ever presenting one GitHub will refuse.
JWT_LIFETIME_SECONDS = 9 * 60

#: The only permissions this pipeline asks for. Named once so the request and the check on the
#: response cannot disagree: a check written against a second literal list would still pass while
#: the request quietly widened.
REQUESTED_PERMISSIONS = ("contents", "pull_requests")

#: An installation token lasts an hour. Anything approaching that is refreshed rather than
#: risked mid-operation - a token expiring between a commit and a pull request would leave a
#: branch pushed with no review attached to it.
TOKEN_REFRESH_MARGIN_SECONDS = 5 * 60


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_jwt(app_id: str, private_key_pem: str, now: int | None = None) -> str:
    """Sign the App-authentication JWT.

    ``iat`` is backdated by a minute. GitHub rejects a token issued in the future, and a
    worker whose clock runs slightly fast would otherwise fail in a way that looks like a
    credential problem rather than a clock problem.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise GitHubError(
            "signing a GitHub App JWT needs the 'cryptography' package; install the 'aws' "
            "extra (pip install '.[aws]'). RS256 cannot be done with the standard library"
        ) from exc

    issued = int(now if now is not None else time.time()) - 60
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iat": issued, "exp": issued + JWT_LIFETIME_SECONDS, "iss": str(app_id)}

    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode("utf-8"))
        for part in (header, claims)
    ).encode("ascii")

    try:
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise GitHubError(
            f"the GitHub App private key could not be read: {exc}. It should be the PEM file "
            "GitHub generated, unmodified and unencrypted"
        ) from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubError(
            "the GitHub App private key is not an RSA key; GitHub issues RSA keys and RS256 "
            "requires one"
        )

    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{_b64url(signature)}"


@dataclass
class InstallationToken:
    """A repository-scoped credential and the moment it stops being valid."""

    token: str
    expires_at: int
    installation_id: int
    permissions: dict[str, str]
    repositories: list[str]

    def expiring_within(self, seconds: int, now: int | None = None) -> bool:
        return (int(now if now is not None else time.time()) + seconds) >= self.expires_at

    def as_dict(self) -> dict[str, Any]:
        """Everything except the token. Deliberate: this is what gets logged."""
        return {
            "installation_id": self.installation_id,
            "expires_at": self.expires_at,
            "permissions": self.permissions,
            "repositories": self.repositories,
        }


def _parse_expiry(value: str) -> int:
    # GitHub returns RFC3339 with a trailing Z, which fromisoformat rejects before 3.11.
    from datetime import datetime, timezone

    cleaned = value.replace("Z", "+00:00")
    try:
        return int(datetime.fromisoformat(cleaned).timestamp())
    except ValueError:
        # An unreadable expiry must not read as "never expires". Assume the shortest plausible
        # life so the caller refreshes rather than trusting a token it cannot date.
        return int(datetime.now(tz=timezone.utc).timestamp())


class GitHubAppAuth:
    """Exchanges an App private key for repository-scoped installation tokens."""

    def __init__(
        self,
        app_id: str,
        private_key_pem: str,
        transport: Transport = urllib_transport,
        api: str = API,
    ):
        if not app_id or not private_key_pem:
            raise GitHubError("both an App ID and a private key are required")
        self.app_id = str(app_id)
        self._private_key = private_key_pem
        self.transport = transport
        self.api = api
        self._cached: InstallationToken | None = None

    def _app_request(self, method: str, path: str, body: dict[str, Any] | None = None):
        headers = {
            "Authorization": f"Bearer {build_jwt(self.app_id, self._private_key)}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "driftcode",
        }
        return self.transport(method, f"{self.api}{path}", body, headers)

    def installations(self) -> list[dict[str, Any]]:
        status, body = self._app_request("GET", "/app/installations")
        if status >= 300:
            raise GitHubError("could not list App installations", status, body)
        return body or []

    def installation_for(self, repo: str) -> int:
        """Find the installation covering ``owner/name``.

        Resolved rather than configured, so an installation moved or reinstalled does not
        require a redeployment - and so a stale hard-coded id cannot silently point at a
        different account's installation.
        """
        owner = repo.split("/")[0].lower()
        for installation in self.installations():
            account = (installation.get("account") or {}).get("login", "")
            if account.lower() == owner:
                return int(installation["id"])

        seen = ", ".join(
            (i.get("account") or {}).get("login", "?") for i in self.installations()
        ) or "none"
        raise GitHubError(
            f"the App is not installed on {owner!r}. Installed on: {seen}. Creating an App is "
            "not installing it - it has to be installed on the account and granted the "
            "repository"
        )

    def token(
        self,
        repo: str,
        installation_id: int | None = None,
        now: int | None = None,
    ) -> InstallationToken:
        """Mint an installation token scoped to one repository.

        Scoped by ``repositories`` even when the installation covers more: the App may
        legitimately be installed on several repositories, and this pipeline has business with
        exactly one. A token that can reach the others is a wider credential than the task
        needs.
        """
        if self._cached and not self._cached.expiring_within(TOKEN_REFRESH_MARGIN_SECONDS, now):
            return self._cached

        target = installation_id or self.installation_for(repo)
        owner, name = repo.split("/", 1)

        status, body = self._app_request(
            "POST",
            f"/app/installations/{target}/access_tokens",
            {
                "repositories": [name],
                "permissions": {p: "write" for p in REQUESTED_PERMISSIONS},
            },
        )
        if status not in (200, 201):
            raise GitHubError(
                f"could not mint an installation token for {repo}", status, body
            )

        granted = (body or {}).get("permissions") or {}
        for required in ("contents", "pull_requests"):
            if granted.get(required) != "write":
                raise GitHubError(
                    f"the installation grants {required}={granted.get(required)!r}, but this "
                    "pipeline needs write. Grant it in the App's repository permissions and "
                    "accept the update on the installation - a permission added to the App is "
                    "not live until the installation accepts it"
                )

        # The response is also checked for being WIDER than asked for. GitHub is expected to
        # honour the requested scope, but a credential is not something to accept on trust: if a
        # token arrives carrying permissions this pipeline did not request, the safe reading is
        # that the request was not applied, and using it anyway would mean the write path holds
        # more authority than its own code asked for.
        unexpected = sorted(set(granted) - set(REQUESTED_PERMISSIONS) - {"metadata"})
        if unexpected:
            raise GitHubError(
                f"the installation token was granted permissions this pipeline did not request: "
                f"{', '.join(unexpected)}. Only {', '.join(REQUESTED_PERMISSIONS)} were asked "
                "for, so the requested scope was not applied and the token is wider than the "
                "code that uses it"
            )

        scoped = [r.get("full_name", "") for r in (body.get("repositories") or [])]
        if scoped and scoped != [repo]:
            raise GitHubError(
                f"the installation token reaches {scoped} but only {repo} was requested; a token "
                "that can write to a repository this run has no business in is wider than the "
                "task"
            )

        self._cached = InstallationToken(
            token=body["token"],
            expires_at=_parse_expiry(body.get("expires_at", "")),
            installation_id=target,
            permissions=granted,
            repositories=scoped or [repo],
        )
        return self._cached


def from_environment(
    getenv: Callable[[str], str | None],
    read_secret: Callable[[str], str] | None = None,
) -> GitHubAppAuth | None:
    """Build App auth from the environment, or return None when it is not configured.

    Returning None rather than raising lets the caller fall back to a token, so an estate can
    move to App auth without a flag day. The App is preferred when present because it is the
    narrower credential.
    """
    app_id = getenv("DRIFT_GITHUB_APP_ID")
    if not app_id:
        return None

    key = getenv("DRIFT_GITHUB_APP_KEY")
    if not key and read_secret is not None:
        secret_id = getenv("DRIFT_GITHUB_APP_KEY_SECRET_ID")
        if secret_id:
            key = read_secret(secret_id)

    if not key:
        raise GitHubError(
            "DRIFT_GITHUB_APP_ID is set but no private key was found. Supply "
            "DRIFT_GITHUB_APP_KEY, or DRIFT_GITHUB_APP_KEY_SECRET_ID with a readable secret"
        )

    return GitHubAppAuth(app_id, key)


def read_secret_value(secret_id: str, region: str | None = None) -> str:
    """Read a secret, importing boto3 lazily like the rest of the package's AWS paths."""
    try:
        import boto3  # noqa: PLC0415 - deliberately lazy
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise GitHubError(
            "reading the App key from Secrets Manager needs boto3; install the 'aws' extra"
        ) from exc

    import os

    client = boto3.client("secretsmanager", region_name=region or os.environ.get("AWS_REGION"))
    return client.get_secret_value(SecretId=secret_id)["SecretString"]


def credential_for(
    repo: str,
    getenv: Callable[[str], str | None],
    read_secret: Callable[[str], str] | None = None,
) -> tuple[str, dict[str, Any]]:
    """The credential to use for ``repo``, and a description of it that omits the value.

    App authentication is preferred when configured, because it is strictly narrower: scoped to
    this one repository, limited to two permissions, and valid for an hour. A personal access
    token remains the fallback so an estate can adopt the App without a flag day - but the
    description says which was used, so a run's audit trail records the kind of credential that
    wrote to the repository rather than leaving it to be inferred.
    """
    app = from_environment(getenv, read_secret or read_secret_value)

    if app is not None:
        token = app.token(repo)
        return token.token, {"kind": "github_app", **token.as_dict()}

    return token_from_environment(getenv), {
        "kind": "personal_access_token",
        "note": (
            "A personal access token authenticates as a person, carries that person's scope "
            "across every repository they can reach, and does not expire. Prefer a GitHub App: "
            "set DRIFT_GITHUB_APP_ID and DRIFT_GITHUB_APP_KEY_SECRET_ID."
        ),
    }


__all__ = [
    "JWT_LIFETIME_SECONDS",
    "REQUESTED_PERMISSIONS",
    "TOKEN_REFRESH_MARGIN_SECONDS",
    "GitHubAppAuth",
    "InstallationToken",
    "build_jwt",
    "credential_for",
    "from_environment",
    "read_secret_value",
]
