"""Reconciliation tests.

Fixtures reproduce the shapes observed on a real applied stack carrying exactly one
induced drift, where a locked ``plan -refresh-only`` reported FOUR changed resources
while the full plan reported ONE. Captured plan JSON is not committed (it is large
and carries account identifiers); see ``test/fixtures/README.md`` to capture it
locally. Real provider output is covered in test_real_fixtures.py, which runs always.
"""

from __future__ import annotations

import json

from driftcode.detect.reconcile import (
    changed_attributes,
    reconcile,
    reconcile_attributes,
)

from .plan_fixtures import PHANTOMS, REAL, full_plan, refresh_only_plan



def _fixtures() -> tuple[dict, dict]:
    return refresh_only_plan(), full_plan()


# --- the over-reporting premise ---------------------------------------------

def test_refresh_only_alone_would_overreport():
    """Guards the premise: refresh-only really does report more than reality."""
    ro, full = _fixtures()
    drift = {e["address"] for e in ro["resource_drift"]}
    changed = {
        e["address"]
        for e in full["resource_changes"]
        if e["change"]["actions"] != ["no-op"]
    }
    assert len(drift) == 4, f"expected 4 reported drift entries, got {sorted(drift)}"
    assert changed == {REAL}, f"full plan should report only the launch template, got {changed}"


def test_reconciliation_keeps_only_real_drift():
    ro, full = _fixtures()
    result = reconcile(ro, full)
    assert [r["address"] for r in result["real_drift"]] == [REAL]
    assert result["has_real_drift"] is True


def test_phantom_normalization_is_suppressed():
    ro, full = _fixtures()
    result = reconcile(ro, full)
    assert {r["address"] for r in result["suppressed"]} == PHANTOMS


def test_no_pending_verification_in_this_fixture():
    ro, full = _fixtures()
    assert reconcile(ro, full)["pending_verification"] == []


def test_phantoms_are_indistinguishable_by_action_alone():
    """Why an action gate cannot do this job: every entry is an ["update"]."""
    ro, _ = _fixtures()
    actions = {e["address"]: e["change"]["actions"] for e in ro["resource_drift"]}
    assert all(a == ["update"] for a in actions.values()), actions


def test_real_drift_identifies_the_drifted_attribute():
    ro, full = _fixtures()
    entry = reconcile(ro, full)["real_drift"][0]
    assert "instance_type" in entry["changed_attributes"]
    assert entry["type"] == "aws_launch_template"
    assert entry["actions"] == ["update"]


def test_attribute_level_noise_is_separated_from_candidates():
    """Resource-level intersection is not sufficient: even a genuinely drifted
    resource reports null->empty normalization among its attributes."""
    ro, full = _fixtures()
    entry = reconcile(ro, full)["real_drift"][0]
    # the operator really did change these
    assert "instance_type" in entry["changed_attributes"]
    assert "description" in entry["changed_attributes"]
    # pure representation normalization, must not reach the agent
    assert "security_group_names" in entry["attribute_noise"]
    assert "tags" in entry["attribute_noise"]
    assert not set(entry["changed_attributes"]) & set(entry["attribute_noise"])


def test_attribute_reconciliation_matches_on_path_not_direction():
    """refresh-only reports state->live; the full plan reports the proposed revert.
    The directions are opposite, so only the path can be intersected."""
    drift = _entry("aws_launch_template.app",
                   before={"instance_type": "t3.micro"}, after={"instance_type": "t2.micro"})
    plan = _entry("aws_launch_template.app",
                  before={"instance_type": "t2.micro"}, after={"instance_type": "t3.micro"})
    out = reconcile_attributes(drift, plan)
    assert out["candidates"] == ["instance_type"] and out["noise"] == []


def test_null_to_empty_collection_is_attribute_noise():
    drift = _entry("x.y", before={"tags": None, "name": "a"}, after={"tags": {}, "name": "b"})
    plan = _entry("x.y", before={"name": "b"}, after={"name": "a"})
    out = reconcile_attributes(drift, plan)
    assert out["candidates"] == ["name"] and out["noise"] == ["tags"]


# --- quadrant behaviour -----------------------------------------------------

def _entry(address, actions=("update",), before=None, after=None, mode="managed"):
    return {
        "address": address,
        "mode": mode,
        "type": address.split(".")[-2] if "." in address else address,
        "name": address.split(".")[-1],
        "change": {"actions": list(actions), "before": before or {}, "after": after or {}},
    }


def test_full_plan_only_is_not_treated_as_drift():
    """Un-applied code changes must not be admitted as drift."""
    ro = {"resource_drift": []}
    full = {"resource_changes": [_entry("aws_s3_bucket.new")]}
    result = reconcile(ro, full)
    assert result["real_drift"] == []
    assert result["has_real_drift"] is False
    assert [r["address"] for r in result["pending_verification"]] == ["aws_s3_bucket.new"]


def test_no_op_entries_are_ignored():
    ro = {"resource_drift": [_entry("aws_vpc.main", actions=["no-op"])]}
    full = {"resource_changes": [_entry("aws_vpc.main", actions=["no-op"])]}
    counts = reconcile(ro, full)["counts"]
    assert counts["refresh_only_reported"] == 0 and counts["full_plan_reported"] == 0


def test_data_sources_are_ignored():
    ro = {"resource_drift": [_entry("data.aws_ami.x", mode="data")]}
    full = {"resource_changes": [_entry("data.aws_ami.x", mode="data")]}
    assert reconcile(ro, full)["counts"]["refresh_only_reported"] == 0


def test_missing_keys_are_tolerated():
    assert reconcile({}, {})["counts"]["real_drift"] == 0


def test_delete_actions_survive_reconciliation_for_the_action_gate():
    """Reconciliation must not silently drop non-update actions; the action gate
    downstream is responsible for refusing them."""
    ro = {"resource_drift": [_entry("aws_log_group.x", actions=["delete"])]}
    full = {"resource_changes": [_entry("aws_log_group.x", actions=["delete", "create"])]}
    entry = reconcile(ro, full)["real_drift"][0]
    assert entry["actions"] == ["delete"]
    assert entry["full_plan_actions"] == ["delete", "create"]


# --- attribute diffing ------------------------------------------------------

def test_nested_paths_are_reported():
    e = _entry(
        "aws_security_group.web",
        before={"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
        after={"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
    )
    assert changed_attributes(e) == ["ingress.0.cidr_blocks.0"]


def test_identical_values_produce_no_paths():
    assert changed_attributes(_entry("x.y", before={"a": 1}, after={"a": 1})) == []


# Real provider output is covered unconditionally in test_real_fixtures.py, against
# reduced and redacted fixtures committed under tests/fixtures/real-*.json. A conditional
# test here, skipped unless plans have been captured locally, is a permanent no-op for
# anyone running the suite in CI - which would leave the reconciliation logic checked only
# against fixtures written alongside it.
