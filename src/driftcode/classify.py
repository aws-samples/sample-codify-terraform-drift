"""Scope guard: decide whether a drifted attribute may be codified at all.

The pattern codifies a deliberately narrow class of drift. Everything else is routed to
a human rather than auto-changed. This module is where that boundary is enforced, and it
runs *before* the agent so the agent is never asked to attempt something out of scope.

Codification requires all of:

  * action is exactly ``["update"]`` - an in-place change. Anything containing
    ``create`` or ``delete`` has no single attribute to edit; a deleted resource needs a
    block removal or a ``moved``/``import`` block, which is a different operation with a
    different risk profile.
  * a single-instance resource - no ``for_each``/``count`` index. An instance address is
    not a file location: the source declares one block with no per-key text, so editing
    "the block for key C" either fails or silently changes every key.
  * the attribute is codifiable per the provider schema - not provider-computed and not
    write-only. Gate A determines this; a computed value can differ legitimately yet be
    impossible to set in configuration.
  * the attribute is operator-owned, not reconciled by a controller. Codifying an
    autoscaler's ``desired_capacity`` produces a detect -> PR -> merge -> re-drift loop.
  * the value's source layer is local to this workspace. A value resolved from shared or
    environment ``tfvars`` is consumed by sibling workspaces, so codifying it changes
    estates nobody asked about.

Verdicts are ``codify``, ``escalate`` or ``suppress``. Escalation is not failure: it is
the pattern working as designed, and is reported as prominently as a successful pull
request.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from .resolve import WORKSPACE_LOCAL_LAYERS, explain

CODIFY = "codify"
ESCALATE = "escalate"
SUPPRESS = "suppress"

# Stable machine-readable reasons. Every decision and every attribute rejection carries
# one, so a caller - or a test - can assert on the cause without depending on the prose
# that explains it. Rewording a message must not change behaviour, and two unrelated
# failures with overlapping phrasing must not be indistinguishable.
ACTION_NOT_PURE_UPDATE = "action_not_pure_update"
INSTANCE_INDEXED = "instance_indexed"
UNCONFIRMED_OBSERVATION = "unconfirmed_observation"
NO_CHANGED_ATTRIBUTES = "no_changed_attributes"
NO_ELIGIBLE_ATTRIBUTE = "no_eligible_attribute"
CODIFIABLE = "codifiable"

NOT_CODIFIABLE_BY_SCHEMA = "not_codifiable_by_schema"
CONTROLLER_OWNED = "controller_owned"
#: Suffixed with the layer from :mod:`driftcode.resolve`, e.g. source_layer_shared_tfvars.
SOURCE_LAYER_PREFIX = "source_layer_"

#: An address carries an index when a resource is declared with for_each or count:
#: aws_instance.web["prod"] or aws_instance.web[0].
_INDEXED = re.compile(r"\[[^\]]+\]\s*$")

#: Attributes reconciled by a controller rather than an operator. Codifying these loops.
#: Extend per estate; the oscillation heuristic in the ledger augments it at runtime.
DEFAULT_CONTROLLER_OWNED: dict[str, set[str]] = {
    "aws_autoscaling_group": {
        "desired_capacity",
        "enabled_metrics",
        "suspended_processes",
        "termination_policies",
    },
    "aws_ecs_service": {"desired_count"},
    "aws_appautoscaling_target": {"min_capacity", "max_capacity"},
}

#: Source layers whose values are safe to edit from this workspace. Defined in
#: :mod:`driftcode.resolve`, which produces them, so the two cannot drift apart.
LOCAL_SOURCE_LAYERS = WORKSPACE_LOCAL_LAYERS


def config_address(address: str) -> str:
    """Strip any instance index, yielding the address the *configuration* declares.

    ``module.compute.aws_launch_template.app["a"]`` -> ``module.compute.aws_launch_template.app``
    """
    return _INDEXED.sub("", address).strip()


def is_indexed(address: str) -> bool:
    return bool(_INDEXED.search(address))


def _decision(verdict: str, reason: str, code: str, **extra: Any) -> dict[str, Any]:
    """A verdict, a stable code, and prose. The code is the contract; the prose explains."""
    return {"verdict": verdict, "code": code, "reason": reason, **extra}


def classify_resource(
    entry: dict[str, Any],
    codifiable_attributes: Iterable[str] | None = None,
    controller_owned: dict[str, set[str]] | None = None,
    source_layers: dict[str, str] | None = None,
    confirmed_samples: int = 1,
    required_samples: int = 2,
) -> dict[str, Any]:
    """Decide what to do with one reconciled drift entry.

    ``codifiable_attributes`` comes from Gate A's schema classification. Passing ``None``
    means no schema was available, which is treated as unknown - and unknown is not
    codifiable.

    ``source_layers`` maps attribute path to source layer, as resolved by tracing the
    value through variables. Unknown layers are treated as non-local.

    ``confirmed_samples`` is how many consecutive runs have observed this drift, which an
    observation ledger supplies. It defaults to **1 - unconfirmed** rather than to the
    required count, so an estate with no ledger suppresses and says why instead of
    treating every first sighting as settled drift. Defaulting the other way makes the
    debounce a no-op that is invisible in the output, and the failure it admits is
    permanently codifying a transient flap.
    """
    registry = controller_owned if controller_owned is not None else DEFAULT_CONTROLLER_OWNED
    address = entry.get("address", "")
    rtype = entry.get("type", "")
    actions = list(entry.get("actions") or [])

    # 1. action gate - must be a pure in-place update
    if actions != ["update"]:
        return _decision(
            ESCALATE,
            f"action {actions} is not a pure in-place update; a create/delete/replace has "
            "no single attribute to edit and needs block-level remediation",
            code=ACTION_NOT_PURE_UPDATE,
            address=address,
        )

    # 2. single-instance only
    if is_indexed(address):
        return _decision(
            ESCALATE,
            "resource is a for_each/count instance; an instance address is not a file "
            "location and per-instance values cannot be edited in a shared block",
            code=INSTANCE_INDEXED,
            address=address,
            config_address=config_address(address),
        )

    # 3. transient-drift debounce - do not codify a single observation
    if confirmed_samples < required_samples:
        return _decision(
            SUPPRESS,
            f"observed in {confirmed_samples} sample(s), need {required_samples}; a single "
            "observation may be a transient flap rather than settled drift",
            code=UNCONFIRMED_OBSERVATION,
            address=address,
            confirmed_samples=confirmed_samples,
            required_samples=required_samples,
        )

    attributes = list(entry.get("changed_attributes") or [])
    if not attributes:
        return _decision(
            SUPPRESS,
            "no changed attributes survived reconciliation",
            code=NO_CHANGED_ATTRIBUTES,
            address=address,
        )

    codifiable = set(codifiable_attributes) if codifiable_attributes is not None else set()
    owned_by_controller = registry.get(rtype, set())
    layers = source_layers or {}

    eligible: list[str] = []
    rejected: list[dict[str, str]] = []

    for attr in attributes:
        root = attr.split(".")[0]

        if attr not in codifiable:
            rejected.append(
                {
                    "attribute": attr,
                    "code": NOT_CODIFIABLE_BY_SCHEMA,
                    "reason": "not codifiable per the provider schema (computed, write-only, "
                    "or no schema available)",
                }
            )
            continue

        if root in owned_by_controller:
            rejected.append(
                {
                    "attribute": attr,
                    "code": CONTROLLER_OWNED,
                    "reason": f"{rtype}.{root} is controller-owned; codifying it creates a "
                    "detect-PR-merge-redrift loop",
                }
            )
            continue

        layer = layers.get(attr, "unknown")
        if layer not in LOCAL_SOURCE_LAYERS:
            rejected.append(
                {
                    "attribute": attr,
                    "code": f"{SOURCE_LAYER_PREFIX}{layer}",
                    "source_layer": layer,
                    "reason": f"not editable from this workspace: {explain(layer)}",
                }
            )
            continue

        eligible.append(attr)

    if not eligible:
        return _decision(
            ESCALATE,
            "no attribute is eligible for codification",
            code=NO_ELIGIBLE_ATTRIBUTE,
            address=address,
            rejected_attributes=rejected,
        )

    return _decision(
        CODIFY,
        f"{len(eligible)} attribute(s) eligible for in-place codification",
        code=CODIFIABLE,
        address=address,
        config_address=config_address(address),
        type=rtype,
        authorized_attributes=eligible,
        rejected_attributes=rejected,
    )


def classify_all(
    reconciled: dict[str, Any],
    gate_a: dict[str, Any] | None = None,
    layer_resolver: Callable[[dict[str, Any]], dict[str, str]] | None = None,
    sample_resolver: Callable[[dict[str, Any]], int] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Classify every reconciled drift entry, grouped by verdict.

    Gate A's ``attribute_classification`` supplies the codifiable set per address, so the
    schema decision is made once and reused rather than re-derived here.

    ``layer_resolver`` is called per entry to obtain that entry's attribute-to-source-layer
    mapping, normally :func:`driftcode.resolve.source_layers` bound to the checked-out
    repository. ``sample_resolver`` returns that entry's consecutive-observation count from
    the ledger. Both are injected rather than imported here so this module stays a pure
    function over plan data and remains testable without a filesystem or a database.
    ``layer_resolver`` is called only for entries that survive the cheap gates, since
    tracing an entry already destined to escalate would read files for nothing.
    """
    codifiable_by_address: dict[str, list[str]] = {}
    for c in (gate_a or {}).get("attribute_classification", []):
        codifiable_by_address[c.get("address", "")] = list(c.get("codifiable") or [])

    grouped: dict[str, list[dict[str, Any]]] = {CODIFY: [], ESCALATE: [], SUPPRESS: []}
    for entry in reconciled.get("real_drift", []):
        per_entry = dict(kwargs)
        address = entry.get("address", "")
        cheap_gates_passed = list(entry.get("actions") or []) == ["update"] and not is_indexed(address)

        if sample_resolver is not None:
            per_entry["confirmed_samples"] = sample_resolver(entry)
        if layer_resolver is not None and cheap_gates_passed:
            per_entry["source_layers"] = layer_resolver(entry)

        decision = classify_resource(
            entry,
            codifiable_attributes=codifiable_by_address.get(address),
            **per_entry,
        )
        grouped[decision["verdict"]].append(decision)

    return {
        "codify": grouped[CODIFY],
        "escalate": grouped[ESCALATE],
        "suppress": grouped[SUPPRESS],
        "counts": {k: len(v) for k, v in grouped.items()},
        "has_work": bool(grouped[CODIFY]),
    }
