"""Scope-guard tests.

Escalation is the expected outcome for most drift shapes. These tests exist to prove the
boundary holds, since a guard that quietly widens is worse than no guard.
"""

from __future__ import annotations

import pytest

from driftcode.classify import (
    ACTION_NOT_PURE_UPDATE,
    CODIFIABLE,
    CODIFY,
    CONTROLLER_OWNED,
    ESCALATE,
    INSTANCE_INDEXED,
    NOT_CODIFIABLE_BY_SCHEMA,
    NO_CHANGED_ATTRIBUTES,
    NO_ELIGIBLE_ATTRIBUTE,
    SUPPRESS,
    UNCONFIRMED_OBSERVATION,
    classify_all,
    classify_resource,
    config_address,
    is_indexed,
)

LOCAL = {"instance_type": "workspace_tfvars", "description": "resource_literal"}


def entry(**overrides):
    base = {
        "address": "module.compute.aws_launch_template.app",
        "type": "aws_launch_template",
        "actions": ["update"],
        "changed_attributes": ["instance_type"],
    }
    base.update(overrides)
    return base

def classify(drift_entry, **kwargs):
    """Classify with the debounce satisfied unless a test overrides it.

    In production ``confirmed_samples`` defaults to 1 - unconfirmed - so an estate with no
    observation ledger suppresses rather than treating a first sighting as settled. These
    tests exercise the other gates, so they assert confirmation explicitly.
    """
    kwargs.setdefault("confirmed_samples", 2)
    return classify_resource(drift_entry, **kwargs)



# --- the in-scope case -----------------------------------------------------

def test_scalar_in_place_update_is_codified():
    d = classify(entry(), codifiable_attributes=["instance_type"], source_layers=LOCAL)
    assert d["verdict"] == CODIFY
    assert d["authorized_attributes"] == ["instance_type"]


def test_multiple_eligible_attributes_are_all_authorized():
    d = classify(
        entry(changed_attributes=["instance_type", "description"]),
        codifiable_attributes=["instance_type", "description"],
        source_layers=LOCAL,
    )
    assert d["verdict"] == CODIFY
    assert set(d["authorized_attributes"]) == {"instance_type", "description"}


# --- action gate -----------------------------------------------------------

def test_delete_escalates():
    d = classify(entry(actions=["delete"]), codifiable_attributes=["instance_type"])
    assert d["verdict"] == ESCALATE
    assert "no single attribute to edit" in d["reason"]


def test_replace_escalates():
    d = classify(entry(actions=["delete", "create"]), codifiable_attributes=["instance_type"])
    assert d["verdict"] == ESCALATE


def test_create_escalates():
    assert classify(entry(actions=["create"]))["verdict"] == ESCALATE


# --- for_each / count ------------------------------------------------------

def test_for_each_instance_escalates():
    d = classify(
        entry(address='module.compute.aws_launch_template.app["us-west-2"]'),
        codifiable_attributes=["instance_type"],
        source_layers=LOCAL,
    )
    assert d["verdict"] == ESCALATE
    assert "not a file location" in d["reason"]
    # The config address is still reported, so a human sees which block is involved.
    assert d["config_address"] == "module.compute.aws_launch_template.app"


def test_count_index_escalates():
    d = classify(entry(address="aws_instance.web[0]"), codifiable_attributes=["instance_type"])
    assert d["verdict"] == ESCALATE


def test_index_detection_and_stripping():
    assert is_indexed('aws_x.y["k"]') and is_indexed("aws_x.y[2]")
    assert not is_indexed("aws_x.y")
    assert config_address('module.m.aws_x.y["k"]') == "module.m.aws_x.y"


# --- schema eligibility ----------------------------------------------------

def test_computed_attribute_is_not_codifiable():
    """latest_version differs legitimately but cannot be set in configuration."""
    d = classify(
        entry(changed_attributes=["latest_version"]),
        codifiable_attributes=[],  # Gate A classified it as computed
        source_layers={"latest_version": "resource_literal"},
    )
    assert d["verdict"] == ESCALATE
    assert "provider schema" in d["rejected_attributes"][0]["reason"]


def test_absent_schema_authorizes_nothing():
    """No schema means unknown, and unknown is not codifiable."""
    d = classify(entry(), codifiable_attributes=None, source_layers=LOCAL)
    assert d["verdict"] == ESCALATE


# --- controller-owned attributes -------------------------------------------

def test_controller_owned_attribute_escalates():
    d = classify(
        entry(
            address="module.compute.aws_autoscaling_group.app",
            type="aws_autoscaling_group",
            changed_attributes=["desired_capacity"],
        ),
        codifiable_attributes=["desired_capacity"],
        source_layers={"desired_capacity": "workspace_tfvars"},
    )
    assert d["verdict"] == ESCALATE
    assert "redrift loop" in d["rejected_attributes"][0]["reason"]


def test_registry_is_overridable_per_estate():
    d = classify(
        entry(changed_attributes=["instance_type"]),
        codifiable_attributes=["instance_type"],
        controller_owned={"aws_launch_template": {"instance_type"}},
        source_layers=LOCAL,
    )
    assert d["verdict"] == ESCALATE


# --- source layer ----------------------------------------------------------

def test_shared_tfvars_escalates():
    d = classify(
        entry(),
        codifiable_attributes=["instance_type"],
        source_layers={"instance_type": "shared_tfvars"},
    )
    assert d["verdict"] == ESCALATE
    assert d["code"] == NO_ELIGIBLE_ATTRIBUTE
    assert d["rejected_attributes"][0]["code"] == "source_layer_shared_tfvars"
    assert d["rejected_attributes"][0]["source_layer"] == "shared_tfvars"


def test_unknown_source_layer_escalates():
    d = classify(entry(), codifiable_attributes=["instance_type"], source_layers={})
    assert d["verdict"] == ESCALATE


# --- debounce --------------------------------------------------------------

def test_single_observation_is_suppressed_not_codified():
    d = classify_resource(
        entry(), codifiable_attributes=["instance_type"], source_layers=LOCAL, confirmed_samples=1
    )
    assert d["verdict"] == SUPPRESS
    assert d["code"] == UNCONFIRMED_OBSERVATION
    assert d["confirmed_samples"] == 1
    assert d["required_samples"] == 2


def test_no_attributes_is_suppressed():
    d = classify(entry(changed_attributes=[]), codifiable_attributes=[])
    assert d["verdict"] == SUPPRESS


# --- aggregation -----------------------------------------------------------

def test_classify_all_groups_by_verdict():
    reconciled = {
        "real_drift": [
            entry(),
            entry(address="module.compute.aws_autoscaling_group.app", type="aws_autoscaling_group",
                  changed_attributes=["desired_capacity"]),
            entry(address="aws_log_group.x", actions=["delete"]),
        ]
    }
    gate_a = {
        "attribute_classification": [
            {"address": "module.compute.aws_launch_template.app", "codifiable": ["instance_type"]},
            {"address": "module.compute.aws_autoscaling_group.app", "codifiable": ["desired_capacity"]},
        ]
    }
    result = classify_all(reconciled, gate_a, source_layers=LOCAL | {"desired_capacity": "workspace_tfvars"}, confirmed_samples=2)
    assert result["counts"]["codify"] == 1
    assert result["counts"]["escalate"] == 2
    assert result["has_work"] is True


def test_nothing_codifiable_reports_no_work():
    reconciled = {"real_drift": [entry(actions=["delete"])]}
    assert classify_all(reconciled, {})["has_work"] is False



# --- every outcome carries a stable code ---------------------------------------------
#
# Prose explains; the code is the contract. Asserting on wording couples tests to sentences
# the implementation happens to use, so a correct rewording breaks them - and worse, two
# unrelated failure paths with overlapping phrasing can pass for the wrong reason.


@pytest.mark.parametrize(
    "kwargs,expected_verdict,expected_code",
    [
        ({}, CODIFY, CODIFIABLE),
        ({"entry_overrides": {"actions": ["delete", "create"]}}, ESCALATE, ACTION_NOT_PURE_UPDATE),
        ({"entry_overrides": {"actions": ["create"]}}, ESCALATE, ACTION_NOT_PURE_UPDATE),
        (
            {"entry_overrides": {"address": 'module.compute.aws_launch_template.app["a"]'}},
            ESCALATE,
            INSTANCE_INDEXED,
        ),
        ({"confirmed_samples": 1}, SUPPRESS, UNCONFIRMED_OBSERVATION),
        ({"entry_overrides": {"changed_attributes": []}}, SUPPRESS, NO_CHANGED_ATTRIBUTES),
        ({"codifiable_attributes": []}, ESCALATE, NO_ELIGIBLE_ATTRIBUTE),
        ({"source_layers": {}}, ESCALATE, NO_ELIGIBLE_ATTRIBUTE),
    ],
)
def test_each_decision_path_has_its_own_code(kwargs, expected_verdict, expected_code):
    overrides = kwargs.pop("entry_overrides", {})
    kwargs.setdefault("codifiable_attributes", ["instance_type"])
    kwargs.setdefault("source_layers", LOCAL)
    kwargs.setdefault("confirmed_samples", 2)

    d = classify_resource(entry(**overrides), **kwargs)

    assert d["verdict"] == expected_verdict
    assert d["code"] == expected_code


@pytest.mark.parametrize(
    "kwargs,expected_code",
    [
        ({"codifiable_attributes": []}, NOT_CODIFIABLE_BY_SCHEMA),
        ({"codifiable_attributes": None}, NOT_CODIFIABLE_BY_SCHEMA),
        ({"source_layers": {"instance_type": "shared_tfvars"}}, "source_layer_shared_tfvars"),
        ({"source_layers": {"instance_type": "module_variable_default"}}, "source_layer_module_variable_default"),
        ({"source_layers": {"instance_type": "external_variable"}}, "source_layer_external_variable"),
        ({"source_layers": {}}, "source_layer_unknown"),
    ],
)
def test_each_attribute_rejection_has_its_own_code(kwargs, expected_code):
    kwargs.setdefault("codifiable_attributes", ["instance_type"])
    kwargs.setdefault("source_layers", LOCAL)

    d = classify(entry(), **kwargs)

    assert [r["code"] for r in d["rejected_attributes"]] == [expected_code]


def test_a_controller_owned_rejection_is_distinguishable_from_a_layer_rejection():
    """Both escalate; the codes say which, which prose overlap could obscure."""
    d = classify(
        entry(
            address="module.compute.aws_autoscaling_group.app",
            type="aws_autoscaling_group",
            changed_attributes=["desired_capacity"],
        ),
        codifiable_attributes=["desired_capacity"],
        source_layers={"desired_capacity": "workspace_tfvars"},
    )

    assert d["rejected_attributes"][0]["code"] == CONTROLLER_OWNED


def test_codes_are_unique_across_decision_paths():
    """Two paths sharing a code would make them indistinguishable to a caller."""
    codes = {
        ACTION_NOT_PURE_UPDATE,
        INSTANCE_INDEXED,
        UNCONFIRMED_OBSERVATION,
        NO_CHANGED_ATTRIBUTES,
        NO_ELIGIBLE_ATTRIBUTE,
        CODIFIABLE,
        NOT_CODIFIABLE_BY_SCHEMA,
        CONTROLLER_OWNED,
    }

    assert len(codes) == 8
