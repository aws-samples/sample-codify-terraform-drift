"""GitHub App authentication: a narrower credential than a personal access token.

The properties worth testing are the ones that make it narrower — the token is scoped to one
repository, limited to two permissions, and short-lived — plus the failure modes that would
quietly widen it: a token whose granted permissions fall short being used anyway, an unreadable
expiry being treated as "never expires", and the credential value leaking into anything logged.

Signing is exercised against a real generated key, so the JWT is a real RS256 signature rather
than a shape.
"""

from __future__ import annotations

import base64
import json

import pytest

from driftcode.mcp.github import GitHubError
from driftcode.mcp.github_app import (
    JWT_LIFETIME_SECONDS,
    REQUESTED_PERMISSIONS,
    TOKEN_REFRESH_MARGIN_SECONDS,
    GitHubAppAuth,
    InstallationToken,
    build_jwt,
    credential_for,
    from_environment,
)

cryptography = pytest.importorskip("cryptography", reason="RS256 needs the 'aws' extra")

REPO = "acme/infra"
APP_ID = "1000001"


@pytest.fixture(scope="module")
def private_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def decode_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class FakeGitHub:
    """Serves the two App endpoints, recording what it was asked."""

    extra_repositories = False

    def __init__(self, installations=None, permissions=None, expires="2026-09-14T20:00:00Z"):
        self.installations = installations if installations is not None else [
            {"id": 2000002, "account": {"login": "acme"}, "repository_selection": "selected"}
        ]
        self.permissions = permissions or {"contents": "write", "pull_requests": "write"}
        self.expires = expires
        self.requests: list[tuple[str, str, dict | None]] = []
        self.mint_status = 201

    def __call__(self, method, url, body, headers):
        path = url.replace("https://api.github.com", "")
        self.requests.append((method, path, body))
        self.last_auth = headers.get("Authorization", "")

        if path == "/app/installations":
            return 200, self.installations
        if path.endswith("/access_tokens"):
            if self.mint_status >= 300:
                return self.mint_status, {"message": "nope"}
            return 201, {
                "token": "ghs_installationtokenvalue",
                "expires_at": self.expires,
                "permissions": self.permissions,
                "repositories": (
                    [{"full_name": REPO}, {"full_name": "acme/unrelated"}]
                    if self.extra_repositories
                    else [{"full_name": REPO}]
                ),
            }
        return 404, {"message": "not found"}


def auth(private_key, fake) -> GitHubAppAuth:
    return GitHubAppAuth(APP_ID, private_key, transport=fake)


# --- the JWT --------------------------------------------------------------------------


def test_the_jwt_is_a_real_rs256_signature(private_key):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    token = build_jwt(APP_ID, private_key, now=1_700_000_000)
    header_b64, claims_b64, signature_b64 = token.split(".")

    key = serialization.load_pem_private_key(private_key.encode(), password=None)
    signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))

    # Raises on a bad signature; reaching the assert means it verified.
    key.public_key().verify(
        signature,
        f"{header_b64}.{claims_b64}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    assert decode_segment(header_b64) == {"alg": "RS256", "typ": "JWT"}


def test_the_jwt_is_backdated_so_a_fast_clock_does_not_look_like_a_bad_credential(private_key):
    claims = decode_segment(build_jwt(APP_ID, private_key, now=1_700_000_000).split(".")[1])

    assert claims["iat"] == 1_700_000_000 - 60


def test_the_jwt_lifetime_stays_inside_githubs_limit(private_key):
    """GitHub rejects a JWT valid for more than ten minutes."""
    claims = decode_segment(build_jwt(APP_ID, private_key, now=1_700_000_000).split(".")[1])

    assert claims["exp"] - claims["iat"] == JWT_LIFETIME_SECONDS
    assert JWT_LIFETIME_SECONDS < 600


def test_the_issuer_is_the_app_id(private_key):
    claims = decode_segment(build_jwt(12345, private_key).split(".")[1])

    assert claims["iss"] == "12345"


def test_an_unreadable_key_says_so_plainly():
    with pytest.raises(GitHubError, match="could not be read"):
        build_jwt(APP_ID, "not a pem")


def test_a_non_rsa_key_is_refused():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    with pytest.raises(GitHubError, match="not an RSA key"):
        build_jwt(APP_ID, pem)


# --- minting a token ------------------------------------------------------------------


def test_the_token_is_scoped_to_one_repository(private_key):
    """The installation may cover several; this pipeline has business with one."""
    fake = FakeGitHub()

    auth(private_key, fake).token(REPO)

    mint = next(b for m, p, b in fake.requests if p.endswith("/access_tokens"))
    assert mint["repositories"] == ["infra"]


def test_the_token_requests_only_two_permissions(private_key):
    """Narrower than the installation even when the installation grants more."""
    fake = FakeGitHub()

    auth(private_key, fake).token(REPO)

    mint = next(b for m, p, b in fake.requests if p.endswith("/access_tokens"))
    assert mint["permissions"] == {"contents": "write", "pull_requests": "write"}


def test_the_installation_is_resolved_not_configured(private_key):
    """A hard-coded id cannot silently point at a different account's installation."""
    fake = FakeGitHub()

    token = auth(private_key, fake).token(REPO)

    assert token.installation_id == 2000002
    assert ("GET", "/app/installations", None) in fake.requests


def test_a_supplied_installation_id_skips_the_lookup(private_key):
    fake = FakeGitHub()

    auth(private_key, fake).token(REPO, installation_id=999)

    assert not any(p == "/app/installations" for _, p, _ in fake.requests)


def test_an_app_not_installed_says_creating_is_not_installing(private_key):
    fake = FakeGitHub(installations=[])

    with pytest.raises(GitHubError, match="not installing it"):
        auth(private_key, fake).token(REPO)


def test_insufficient_granted_permissions_are_refused_rather_than_used(private_key):
    """A token that cannot open a pull request must fail here, not three calls later."""
    fake = FakeGitHub(permissions={"contents": "write", "pull_requests": "read"})

    with pytest.raises(GitHubError, match="needs write"):
        auth(private_key, fake).token(REPO)


def test_the_refusal_explains_that_an_installation_must_accept_a_permission_change(private_key):
    fake = FakeGitHub(permissions={"contents": "read", "pull_requests": "write"})

    with pytest.raises(GitHubError, match="not live until the installation accepts"):
        auth(private_key, fake).token(REPO)


def test_a_mint_failure_is_reported(private_key):
    fake = FakeGitHub()
    fake.mint_status = 403

    with pytest.raises(GitHubError, match="could not mint"):
        auth(private_key, fake).token(REPO)


def test_the_jwt_authenticates_the_mint_call(private_key):
    fake = FakeGitHub()

    auth(private_key, fake).token(REPO)

    assert fake.last_auth.startswith("Bearer ")
    assert fake.last_auth.count(".") == 2, "a JWT, not the installation token"


# --- expiry and caching ---------------------------------------------------------------


def test_a_token_is_reused_while_it_has_life_left(private_key):
    fake = FakeGitHub(expires="2099-01-01T00:00:00Z")
    a = auth(private_key, fake)

    a.token(REPO)
    a.token(REPO)

    assert sum(1 for _, p, _ in fake.requests if p.endswith("/access_tokens")) == 1


def test_a_token_near_expiry_is_reminted(private_key):
    """A token expiring between the commit and the pull request would leave a branch pushed
    with no review attached to it."""
    fake = FakeGitHub(expires="2099-01-01T00:00:00Z")
    a = auth(private_key, fake)

    a.token(REPO)
    near = 4102444800 - TOKEN_REFRESH_MARGIN_SECONDS + 1
    a.token(REPO, now=near)

    assert sum(1 for _, p, _ in fake.requests if p.endswith("/access_tokens")) == 2


def test_an_unreadable_expiry_is_treated_as_expired_not_eternal(private_key):
    fake = FakeGitHub(expires="not a timestamp")

    token = auth(private_key, fake).token(REPO)

    assert token.expiring_within(0)


def test_expiring_within_is_a_margin_not_a_deadline():
    token = InstallationToken("t", expires_at=1000, installation_id=1, permissions={}, repositories=[])

    assert token.expiring_within(100, now=901) is True
    assert token.expiring_within(100, now=899) is False


# --- the value must not leak ----------------------------------------------------------


def test_the_description_omits_the_token_value(private_key):
    """as_dict is what gets logged, so it carries everything except the credential."""
    fake = FakeGitHub()

    token = auth(private_key, fake).token(REPO)
    described = token.as_dict()

    assert token.token not in json.dumps(described)
    assert set(described) == {"installation_id", "expires_at", "permissions", "repositories"}


def test_credential_for_reports_which_kind_was_used_without_the_value(private_key):
    fake = FakeGitHub()
    env = {"DRIFT_GITHUB_APP_ID": APP_ID, "DRIFT_GITHUB_APP_KEY": private_key}

    # Patch the transport in by constructing the auth the same way credential_for does.
    import driftcode.mcp.github_app as module

    original = module.GitHubAppAuth
    module.GitHubAppAuth = lambda app_id, key: original(app_id, key, transport=fake)
    try:
        token, described = credential_for(REPO, env.get)
    finally:
        module.GitHubAppAuth = original

    assert described["kind"] == "github_app"
    assert token not in json.dumps(described)


# --- configuration and fallback -------------------------------------------------------


def test_no_app_configured_returns_none_so_a_token_can_be_used(private_key):
    """Returning None rather than raising lets an estate adopt the App without a flag day."""
    assert from_environment(lambda _: None) is None


def test_an_app_id_without_a_key_is_an_error_not_a_silent_fallback():
    with pytest.raises(GitHubError, match="no private key was found"):
        from_environment(lambda n: APP_ID if n == "DRIFT_GITHUB_APP_ID" else None)


def test_the_key_can_come_from_a_secret_id(private_key):
    env = {"DRIFT_GITHUB_APP_ID": APP_ID, "DRIFT_GITHUB_APP_KEY_SECRET_ID": "drift/app-key"}
    read = {"drift/app-key": private_key}

    app = from_environment(env.get, read.__getitem__)

    assert app is not None
    assert app.app_id == APP_ID


def test_falling_back_to_a_token_says_why_an_app_is_better(private_key):
    env = {"GITHUB_TOKEN": "ghp_classic"}

    token, described = credential_for(REPO, env.get)

    assert token == "ghp_classic"
    assert described["kind"] == "personal_access_token"
    assert "does not expire" in described["note"]


def test_missing_both_is_an_error():
    with pytest.raises(GitHubError, match="no GitHub credential"):
        credential_for(REPO, lambda _: None)


def test_an_app_without_an_id_or_key_is_refused(private_key):
    with pytest.raises(GitHubError, match="both an App ID and a private key"):
        GitHubAppAuth("", private_key)
    with pytest.raises(GitHubError, match="both an App ID and a private key"):
        GitHubAppAuth(APP_ID, "")



# --- the response must not be wider than the request --------------------------------
#
# Checking that granted permissions are not NARROWER catches a misconfigured App. Checking they
# are not WIDER catches a request that was not applied — and the consequence of missing that is a
# write path holding more authority than the code asking for it. A credential is not something to
# accept on trust just because it arrived.


def test_a_token_granted_more_than_was_requested_is_refused(private_key):
    fake = FakeGitHub(
        permissions={
            "contents": "write",
            "pull_requests": "write",
            "administration": "write",
        }
    )

    with pytest.raises(GitHubError, match="did not request"):
        auth(private_key, fake).token(REPO)


def test_the_refusal_names_the_unexpected_permission(private_key):
    fake = FakeGitHub(
        permissions={"contents": "write", "pull_requests": "write", "workflows": "write"}
    )

    with pytest.raises(GitHubError, match="workflows"):
        auth(private_key, fake).token(REPO)


def test_metadata_is_tolerated_because_github_always_grants_it(private_key):
    fake = FakeGitHub(
        permissions={"contents": "write", "pull_requests": "write", "metadata": "read"}
    )

    token = auth(private_key, fake).token(REPO)

    assert token.permissions["metadata"] == "read"


def test_the_requested_set_is_defined_once(private_key):
    """A check written against a second literal list would pass while the request widened."""
    fake = FakeGitHub()

    auth(private_key, fake).token(REPO)

    mint = next(b for m, p, b in fake.requests if p.endswith("/access_tokens"))
    assert set(mint["permissions"]) == set(REQUESTED_PERMISSIONS)


def test_a_token_reaching_more_repositories_than_requested_is_refused(private_key):
    """An installation may legitimately cover several; this run has business with one."""
    fake = FakeGitHub()
    fake.extra_repositories = True

    with pytest.raises(GitHubError, match="no business in"):
        auth(private_key, fake).token(REPO)


# --- the credential must not reach a log --------------------------------------------


def test_the_jwt_is_absent_from_the_recorded_call_log(private_key):
    """The App key signs the JWT, so a JWT in a log is a replayable credential for ten minutes."""
    from driftcode.mcp.github import GitHub

    seen: list[str] = []

    def spy(method, url, body, headers):
        seen.append(headers.get("Authorization", ""))
        return 200, {"object": {"sha": "s"}}

    client = GitHub(repo=REPO, token=build_jwt(APP_ID, private_key), transport=spy)
    client.branch_sha("main")

    assert seen and seen[0].count(".") == 2, "the JWT was sent"
    assert "." not in json.dumps(client.calls), "and must not appear in the audit log"


def test_the_private_key_never_appears_in_a_repr(private_key):
    """A traceback rendering the auth object would otherwise print the signing key."""
    a = GitHubAppAuth(APP_ID, private_key)

    assert "PRIVATE KEY" not in repr(a)
    assert "PRIVATE KEY" not in str(a.__dict__.get("app_id", ""))
