"""The drift signature H: one stable identity per drifted resource instance.

Everything downstream that has to be idempotent keys on H - the observation ledger that
counts consecutive samples, the branch name, and the pull-request adoption check on retry.
Two runs that see the same drift must produce the same H, and two runs that see *different*
drift must not, or a retry silently adopts the wrong pull request.

The construction encodes several choices that each rule out a specific failure:

  * **Per resource instance, never per detection cycle.** A cycle-scoped identity means
    one resource's resolution closes another resource's pull request.
  * **Over the reconciled before/after values**, minus a small denylist of genuinely
    volatile fields. Two things are deliberately *not* done here. A per-type attribute
    *allowlist* is rejected: any attribute it fails to model is drift that silently
    disappears, and the set worth watching is not knowable in advance. Signing the
    *entire* resource projection is rejected too, because a real provider makes it
    unworkable: a resource can carry real drift and provider normalization noise at the
    same time, and the noise disappears once an apply persists the normalized
    representation. H over the whole projection would change between cycles for that
    reason alone, resetting the consecutive-sample count every time and guaranteeing the
    debounce never confirms. So H is taken over the attribute paths reconciliation
    confirmed. That is a *diff*, not a model - it has no allowlist failure mode, because
    nothing decides in advance which attributes count.
  * **Tags are included** when they drifted. A tag edit can be a privilege change wherever
    ABAC is in use, so treating tags as excludable metadata would drop a class of
    security-relevant drift.
  * **Collections are not sorted by default.** Blanket sorting erases order-only drift on
    lists, where order is meaningful. Sorting is applied only to paths the caller confirms
    are unordered sets from the provider schema.
  * **Keyed on the configuration address with any index stripped**, matching the
    file-location model: an instance address is not a file location.
  * **Salted with workspace and repository**, so identical drift in two workspaces cannot
    collide, and taken at the **full sha256**. A truncated prefix is a birthday-attackable
    dedup key, and the thing it keys is which pull request gets adopted.

Canonicalization is explicit rather than delegated to ``json.dumps`` defaults: sorted keys,
no insignificant whitespace, and a stable representation for floats that happen to be
integral, so ``1`` and ``1.0`` from two different provider versions do not fork the
identity of the same drift.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from .classify import config_address

#: Fields excluded from the projection because they change without the resource changing.
#: Deliberately short. Every entry is a decision that drift in that field is not drift, so
#: the bar is "changes on its own with no operator action".
DEFAULT_VOLATILE_PATHS = frozenset(
    {
        # Terraform's own bookkeeping, not cloud configuration.
        "id",
        "arn",
        # Timestamps the provider refreshes on read.
        "last_modified",
        "last_updated_time",
        "last_modified_date",
        # Monotonic counters maintained by the service, covered by Gate A as computed.
        "latest_version",
        "default_version",
        "version_id",
        "etag",
        # AWS-managed tag propagation.
        "tags_all",
    }
)

_HASH_LENGTH = 64


def _canonical(value: Any, path: str, volatile: frozenset[str], set_paths: frozenset[str]) -> Any:
    """Normalize a plan value for hashing, dropping volatile fields.

    ``path`` is the dotted attribute path so far, so a volatile name is only dropped where
    it actually appears rather than everywhere a key of that name occurs.
    """
    if isinstance(value, dict):
        out = {}
        for key in sorted(value):
            child = f"{path}.{key}" if path else key
            if key in volatile or child in volatile:
                continue
            out[key] = _canonical(value[key], child, volatile, set_paths)
        return out

    if isinstance(value, list):
        items = [_canonical(v, path, volatile, set_paths) for v in value]
        if path in set_paths:
            # Only where the schema confirms an unordered set. Sorting anything else
            # erases order-only drift on lists where order is meaningful.
            return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, default=str))
        return items

    if isinstance(value, float) and value.is_integer():
        # A provider upgrade that starts emitting 1.0 where it emitted 1 must not fork the
        # identity of the same drift.
        return int(value)
    return value


def attribute_at(values: Any, path: str) -> Any:
    """Read a dotted attribute path out of a plan value representation.

    Numeric segments index into lists, matching the paths the reconciler emits for nested
    blocks (``ingress.0.cidr_blocks``). A path that does not resolve yields ``None``, which
    is a real possibility: an attribute present in ``after`` may be absent from ``before``.
    """
    current = values
    for segment in path.split("."):
        if isinstance(current, dict):
            if segment not in current:
                return None
            current = current[segment]
        elif isinstance(current, list):
            if not segment.isdigit() or int(segment) >= len(current):
                return None
            current = current[int(segment)]
        else:
            return None
    return current


def projection(
    plan_entry: dict[str, Any],
    changed_attributes: Iterable[str],
    volatile_paths: Iterable[str] | None = None,
    set_paths: Iterable[str] | None = None,
) -> dict[str, Any]:
    """The normalized before/after projection H is taken over.

    ``plan_entry`` is the refresh-only plan's ``resource_drift`` entry, which carries the
    values; ``changed_attributes`` is the reconciled set of paths that genuinely changed.
    Reconciliation output alone is not enough to sign - it deliberately carries descriptors
    and no values - so both halves are required.

    ``set_paths`` are attribute paths the provider schema confirms are unordered sets; only
    those are sorted. ``volatile_paths`` overrides the default denylist.
    """
    volatile = frozenset(volatile_paths) if volatile_paths is not None else DEFAULT_VOLATILE_PATHS
    sets = frozenset(set_paths or ())
    change = plan_entry.get("change") or {}
    before = change.get("before")
    after = change.get("after")

    attributes: dict[str, Any] = {}
    for path in sorted(set(changed_attributes)):
        root = path.split(".")[0]
        if path in volatile or root in volatile:
            continue
        attributes[path] = {
            "before": _canonical(attribute_at(before, path), path, volatile, sets),
            "after": _canonical(attribute_at(after, path), path, volatile, sets),
        }

    return {
        "address": config_address(plan_entry.get("address", "")),
        "type": plan_entry.get("type", ""),
        "actions": list(change.get("actions") or plan_entry.get("actions") or []),
        "attributes": attributes,
    }


def canonical_json(payload: Any) -> str:
    """A byte-stable rendering: sorted keys, no insignificant whitespace, no ASCII escapes."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def signature(
    plan_entry: dict[str, Any],
    changed_attributes: Iterable[str],
    workspace_id: str,
    repo: str,
    volatile_paths: Iterable[str] | None = None,
    set_paths: Iterable[str] | None = None,
) -> str:
    """The full sha256 of the salted projection, as a 64-character hex string.

    Never truncate the result. It selects which pull request a retry adopts, so a short
    prefix is a birthday-attackable key on a decision about writing to a repository.
    """
    if not workspace_id or not repo:
        # A salt-free signature collides across workspaces that share a module, which is
        # the common case, so this is a hard error rather than a default.
        raise ValueError(
            "workspace_id and repo are both required as salt: identical drift in two "
            "workspaces would otherwise share one signature and one pull request"
        )

    payload = {
        "salt": {"workspace_id": workspace_id, "repo": repo},
        "drift": projection(plan_entry, changed_attributes, volatile_paths, set_paths),
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def branch_name(signature_hex: str, workspace_id: str, prefix: str = "drift") -> str:
    """The deterministic branch for a signature, so retries converge instead of forking."""
    if len(signature_hex) != _HASH_LENGTH:
        raise ValueError(
            f"expected a full sha256 ({_HASH_LENGTH} hex chars), got {len(signature_hex)}; "
            "a truncated signature is not a safe branch key"
        )
    slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in workspace_id).strip("-")
    return f"{prefix}/{slug}-{signature_hex}"


def sign_all(
    reconciled: dict[str, Any],
    refresh_only_plan: dict[str, Any],
    workspace_id: str,
    repo: str,
    **kwargs: Any,
) -> dict[str, str]:
    """Map each real-drift resource address to its signature.

    Joins the reconciled attribute paths to the plan entry that holds the values. An
    address present in reconciliation but absent from the plan is skipped rather than
    signed over nothing - an empty projection would give every such resource the same H.
    """
    by_address = {
        e.get("address"): e
        for e in (refresh_only_plan.get("resource_drift") or [])
        if e.get("address")
    }

    signatures: dict[str, str] = {}
    for entry in reconciled.get("real_drift") or []:
        address = entry.get("address")
        plan_entry = by_address.get(address)
        if not address or plan_entry is None:
            continue
        signatures[address] = signature(
            plan_entry,
            entry.get("changed_attributes") or [],
            workspace_id,
            repo,
            **kwargs,
        )
    return signatures
