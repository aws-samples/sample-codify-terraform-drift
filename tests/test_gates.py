"""Gates B and C: does the codified result introduce a finding the baseline did not have?

The shape is the same as Gate A's, for the same reason: a real estate carries pre-existing
findings this change did not cause, and a gate that fails on those fails every run and gets
switched off. So the tests concentrate on the distinction between *introduced* and *present*,
and on the two ways a gate can appear to pass without having looked at anything.
"""

from __future__ import annotations

import json

import pytest

from driftcode.gates import (
    FAIL,
    GATE_B,
    GATE_C,
    PASS,
    evaluate,
    evaluate_gate,
    main,
)

SG = "module.networking.aws_security_group.web_prod"
LT = "module.compute.aws_launch_template.app"


def scan(*failures, passed=9):
    return {
        "results": {
            "passed_checks": [{"check_id": f"CKV_PASS_{i}"} for i in range(passed)],
            "failed_checks": [
                {"check_id": check, "resource": resource} for check, resource in failures
            ],
        }
    }


PRE_EXISTING = (("CKV_AWS_79", LT), ("CKV_AWS_382", SG))


# --- the delta, not the count -------------------------------------------------------


def test_no_new_finding_passes_despite_pre_existing_ones():
    result = evaluate_gate(GATE_B, scan(*PRE_EXISTING), scan(*PRE_EXISTING))

    assert result.verdict == PASS
    assert result.introduced == []
    assert result.pre_existing == 2
    assert any("not grounds for refusing" in w for w in result.warnings)


def test_an_introduced_finding_fails():
    result = evaluate_gate(GATE_B, scan(*PRE_EXISTING), scan(*PRE_EXISTING, ("CKV_AWS_24", SG)))

    assert result.verdict == FAIL
    assert result.introduced == [{"check_id": "CKV_AWS_24", "resource": SG}]
    assert any("CKV_AWS_24" in f for f in result.failures)


def test_a_resolved_finding_does_not_fail_but_is_recorded():
    """Fewer findings is not a reason to refuse, but a reviewer should know."""
    result = evaluate_gate(GATE_B, scan(*PRE_EXISTING), scan(PRE_EXISTING[0]))

    assert result.verdict == PASS
    assert result.resolved == [{"check_id": "CKV_AWS_382", "resource": SG}]
    assert any("absent after the change" in w for w in result.warnings)


def test_swapping_one_finding_for_another_fails():
    """A count comparison would call this unchanged."""
    result = evaluate_gate(GATE_B, scan(("CKV_AWS_79", LT)), scan(("CKV_AWS_24", SG)))

    assert result.verdict == FAIL
    assert [f["check_id"] for f in result.introduced] == ["CKV_AWS_24"]
    assert [f["check_id"] for f in result.resolved] == ["CKV_AWS_79"]


def test_the_same_check_on_a_different_resource_is_a_new_finding():
    """Keyed on (check, resource) — the same rule failing somewhere new is new."""
    result = evaluate_gate(GATE_B, scan(("CKV_AWS_24", LT)), scan(("CKV_AWS_24", LT), ("CKV_AWS_24", SG)))

    assert result.verdict == FAIL
    assert result.introduced == [{"check_id": "CKV_AWS_24", "resource": SG}]


# --- the two ways a gate can look like it passed without looking --------------------


def test_a_scan_that_evaluated_nothing_fails():
    empty = {"results": {"passed_checks": [], "failed_checks": []}}

    result = evaluate_gate(GATE_B, scan(*PRE_EXISTING), empty)

    assert result.verdict == FAIL
    assert any("evaluated 0 checks" in f for f in result.failures)


def test_an_empty_baseline_fails_rather_than_blaming_the_change_for_everything():
    empty = {"results": {"passed_checks": [], "failed_checks": []}}

    result = evaluate_gate(GATE_B, empty, scan(*PRE_EXISTING))

    assert result.verdict == FAIL
    assert any("nothing to compare against" in f for f in result.failures)
    assert result.introduced == []


# --- both gates are required -------------------------------------------------------


def test_both_gates_passing_passes():
    result = evaluate(
        plan_before=scan(*PRE_EXISTING),
        plan_after=scan(*PRE_EXISTING),
        source_before=scan(*PRE_EXISTING),
        source_after=scan(*PRE_EXISTING),
    )

    assert result["verdict"] == PASS
    assert result["counts"]["gates_failed"] == 0


def test_a_missing_source_scan_fails_because_gate_c_is_mandatory():
    """A plan-only regime is blinded by ignore_changes — the very mechanism that holds a
    merge window open."""
    result = evaluate(plan_before=scan(*PRE_EXISTING), plan_after=scan(*PRE_EXISTING))

    assert result["verdict"] == FAIL
    assert any("mandatory" in f for f in result["gates"][GATE_C]["failures"])


def test_a_missing_plan_scan_fails_gate_b():
    result = evaluate(source_before=scan(*PRE_EXISTING), source_after=scan(*PRE_EXISTING))

    assert result["verdict"] == FAIL
    assert any("var/tfvars" in f for f in result["gates"][GATE_B]["failures"])


def test_gate_c_catching_what_gate_b_missed_fails_the_whole_thing():
    """The case the two-scan design exists for: a value hidden from the plan by a freeze."""
    result = evaluate(
        plan_before=scan(*PRE_EXISTING),
        plan_after=scan(*PRE_EXISTING),
        source_before=scan(*PRE_EXISTING),
        source_after=scan(*PRE_EXISTING, ("CKV_AWS_24", SG)),
        frozen_attributes=["ingress"],
    )

    assert result["verdict"] == FAIL
    assert result["gates"][GATE_B]["verdict"] == PASS
    assert result["gates"][GATE_C]["verdict"] == FAIL
    assert result["introduced"] == [{"check_id": "CKV_AWS_24", "resource": SG}]


def test_a_frozen_attribute_is_flagged_on_the_plan_gate():
    """The gate cannot speak to a frozen attribute, and saying so beats a pass that looks
    like it covered it."""
    result = evaluate_gate(
        GATE_B, scan(*PRE_EXISTING), scan(*PRE_EXISTING), frozen_attributes=["ingress"]
    )

    assert result.verdict == PASS
    assert any("cannot speak to its value" in w for w in result.warnings)
    assert any("Gate C covers it" in w for w in result.warnings)


def test_the_same_finding_from_both_gates_is_reported_once():
    result = evaluate(
        plan_before=scan(*PRE_EXISTING),
        plan_after=scan(*PRE_EXISTING, ("CKV_AWS_24", SG)),
        source_before=scan(*PRE_EXISTING),
        source_after=scan(*PRE_EXISTING, ("CKV_AWS_24", SG)),
    )

    assert result["introduced"] == [{"check_id": "CKV_AWS_24", "resource": SG}]
    assert result["counts"]["gates_failed"] == 2


def test_shape_tolerance_carries_over_from_gate_a():
    """Checkov emits a list when more than one runner reports."""
    result = evaluate_gate(GATE_B, [scan(*PRE_EXISTING)], [scan(*PRE_EXISTING)])

    assert result.verdict == PASS


# --- the command-line surface ------------------------------------------------------


def write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_cli_passes_with_a_zero_exit(tmp_path):
    out = tmp_path / "gates.json"
    code = main(
        [
            "--plan-before", write(tmp_path, "pb.json", scan(*PRE_EXISTING)),
            "--plan-after", write(tmp_path, "pa.json", scan(*PRE_EXISTING)),
            "--source-before", write(tmp_path, "sb.json", scan(*PRE_EXISTING)),
            "--source-after", write(tmp_path, "sa.json", scan(*PRE_EXISTING)),
            "--out", str(out),
        ]
    )

    assert code == 0
    assert json.loads(out.read_text())["verdict"] == PASS


def test_cli_fails_non_zero_when_the_change_introduces_a_finding(tmp_path):
    out = tmp_path / "gates.json"
    code = main(
        [
            "--plan-before", write(tmp_path, "pb.json", scan(*PRE_EXISTING)),
            "--plan-after", write(tmp_path, "pa.json", scan(*PRE_EXISTING, ("CKV_AWS_24", SG))),
            "--source-before", write(tmp_path, "sb.json", scan(*PRE_EXISTING)),
            "--source-after", write(tmp_path, "sa.json", scan(*PRE_EXISTING, ("CKV_AWS_24", SG))),
            "--out", str(out),
        ]
    )

    assert code == 1
    assert json.loads(out.read_text())["counts"]["introduced"] == 1


def test_cli_records_frozen_attributes(tmp_path):
    out = tmp_path / "gates.json"
    main(
        [
            "--plan-before", write(tmp_path, "pb.json", scan(*PRE_EXISTING)),
            "--plan-after", write(tmp_path, "pa.json", scan(*PRE_EXISTING)),
            "--source-before", write(tmp_path, "sb.json", scan(*PRE_EXISTING)),
            "--source-after", write(tmp_path, "sa.json", scan(*PRE_EXISTING)),
            "--frozen-attribute", "ingress",
            "--frozen-attribute", "instance_type",
            "--out", str(out),
        ]
    )

    warnings = json.loads(out.read_text())["gates"][GATE_B]["warnings"]
    assert sum("ignore_changes" in w for w in warnings) == 2


def test_cli_treats_an_unreadable_scan_as_missing(tmp_path):
    """A corrupt file must not read as an empty pass."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    out = tmp_path / "gates.json"

    code = main(["--plan-before", str(bad), "--plan-after", str(bad), "--out", str(out)])

    assert code == 1
