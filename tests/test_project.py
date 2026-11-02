"""The drift projection: making live values scannable by a plan-based policy engine.

The behaviour these tests pin is measured against captured real plans with Checkov 3.3.17.
On the refresh-only plan Checkov evaluates 0 resources and reports 0 findings; on the
projection built from the same document it evaluates 9 and reports 9, and with a security
group opened to the world it reports the one additional finding the pattern's Case B
claims. Those numbers are what make the projection worth having, so the shape it produces
is worth protecting.
"""

from __future__ import annotations

import json

import pytest

from driftcode.project import (
    PROJECTION_MARKER,
    ProjectionError,
    count_resources,
    drift_projection,
    main,
)


def plan(*, managed=True, data=True, nested=True, prior=True) -> dict:
    root: dict = {"resources": [], "child_modules": []}

    if managed:
        root["resources"].append(
            {
                "address": "aws_s3_bucket.root",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "root",
                "values": {"bucket": "demo", "acl": "private"},
            }
        )
    if data:
        root["resources"].append(
            {
                "address": "data.aws_region.current",
                "mode": "data",
                "type": "aws_region",
                "name": "current",
                "values": {"name": "us-east-1"},
            }
        )
    if nested:
        root["child_modules"].append(
            {
                "address": "module.compute",
                "resources": [
                    {
                        "address": "module.compute.aws_launch_template.app",
                        "mode": "managed",
                        "type": "aws_launch_template",
                        "name": "app",
                        # The live, drifted value.
                        "values": {"instance_type": "t2.micro"},
                    },
                    {
                        "address": "module.compute.data.aws_ami.latest",
                        "mode": "data",
                        "type": "aws_ami",
                        "name": "latest",
                        "values": {},
                    },
                ],
            }
        )

    document: dict = {
        "format_version": "1.2",
        "terraform_version": "1.9.8",
        # Empty, exactly as terraform emits it for a refresh-only plan. This is why the
        # projection is needed: a plan-based scanner has nothing to evaluate here.
        "planned_values": {"root_module": {}},
        "resource_drift": [],
        "configuration": {"root_module": {"module_calls": {}}},
        "variables": {"instance_type": {"value": "t3.micro"}},
    }
    if prior:
        document["prior_state"] = {"values": {"root_module": root}}
    return document


# --- the transplant -----------------------------------------------------------------


def test_live_values_land_where_a_plan_scanner_reads_them():
    projected = drift_projection(plan())

    assert count_resources(plan(), "planned_values") == 0
    assert count_resources(projected, "planned_values") == 2


def test_the_drifted_value_survives_the_transplant():
    projected = drift_projection(plan())
    module = projected["planned_values"]["root_module"]["child_modules"][0]

    assert module["resources"][0]["values"]["instance_type"] == "t2.micro"


def test_data_sources_are_dropped():
    """They cannot drift and cannot be remediated, matching the reconciler's filter."""
    projected = drift_projection(plan())

    addresses = {r["address"] for r in projected["planned_values"]["root_module"]["resources"]}
    nested = {
        r["address"]
        for r in projected["planned_values"]["root_module"]["child_modules"][0]["resources"]
    }

    assert addresses == {"aws_s3_bucket.root"}
    assert nested == {"module.compute.aws_launch_template.app"}


def test_nothing_is_synthesized():
    """Only copied values, so a finding is a finding about real live configuration."""
    projected = drift_projection(plan())

    assert projected["planned_values"]["root_module"]["resources"][0]["values"] == {
        "bucket": "demo",
        "acl": "private",
    }


def test_the_document_is_marked_as_a_projection():
    """A scan result must be attributable to this, not mistaken for a terraform plan."""
    projected = drift_projection(plan())

    assert PROJECTION_MARKER in projected
    assert "never apply this" in projected[PROJECTION_MARKER]["note"]


def test_configuration_and_variables_are_carried_for_reference_resolution():
    projected = drift_projection(plan())

    assert projected["configuration"] == {"root_module": {"module_calls": {}}}
    assert projected["variables"] == {"instance_type": {"value": "t3.micro"}}


def test_terraform_version_is_preserved():
    assert drift_projection(plan())["terraform_version"] == "1.9.8"


def test_a_module_holding_only_data_sources_is_pruned_entirely():
    document = plan(managed=True, data=False, nested=True)
    document["prior_state"]["values"]["root_module"]["child_modules"][0]["resources"] = [
        {"address": "module.x.data.aws_ami.a", "mode": "data", "type": "aws_ami", "values": {}}
    ]

    projected = drift_projection(document)

    assert "child_modules" not in projected["planned_values"]["root_module"]


# --- refusing to emit an empty document ---------------------------------------------


def test_no_prior_state_is_an_error_not_an_empty_document():
    """An empty projection would scan clean and reintroduce the failure being fixed."""
    with pytest.raises(ProjectionError, match="no live values to scan"):
        drift_projection(plan(prior=False))


def test_prior_state_of_only_data_sources_is_an_error():
    with pytest.raises(ProjectionError, match="no managed resources"):
        drift_projection(plan(managed=False, data=True, nested=False))


def test_empty_prior_state_is_an_error():
    with pytest.raises(ProjectionError, match="no live values to scan"):
        drift_projection({"prior_state": {"values": {}}})


# --- the command-line surface -------------------------------------------------------


def test_cli_writes_a_scannable_document(tmp_path):
    source = tmp_path / "refresh-only.plan.json"
    source.write_text(json.dumps(plan()), encoding="utf-8")
    out = tmp_path / "projection.json"

    assert main(["--refresh-only-plan", str(source), "--out", str(out)]) == 0
    assert count_resources(json.loads(out.read_text(encoding="utf-8"))) == 2


def test_cli_fails_rather_than_writing_an_unscannable_document(tmp_path):
    source = tmp_path / "refresh-only.plan.json"
    source.write_text(json.dumps(plan(prior=False)), encoding="utf-8")
    out = tmp_path / "projection.json"

    assert main(["--refresh-only-plan", str(source), "--out", str(out)]) == 1
    assert not out.exists()
