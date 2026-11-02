"""Checkov output is read shape-tolerantly, because the gate does not choose its shape.

Checkov emits a single object when one runner reports and a list of objects when more than
one does, depending on the frameworks it detects. A gate that assumes the object form
raises AttributeError on a list - a crash inside a security gate, which gives the operator
a stack trace instead of a verdict.
"""

from __future__ import annotations

from driftcode.detect.gate_a import evaluate
from driftcode.policy import evaluated_checks, failed_checks, failure_keys, sections

ONE = {"results": {"failed_checks": [{"check_id": "CKV_AWS_1", "resource": "a"}]}}
TWO = {"results": {"failed_checks": [{"check_id": "CKV_AWS_2", "resource": "b"}]}}


def test_object_form_is_read():
    assert failed_checks(ONE) == [{"check_id": "CKV_AWS_1", "resource": "a"}]


def test_list_form_is_read():
    assert len(failed_checks([ONE, TWO])) == 2


def test_absent_and_malformed_output_yield_nothing_rather_than_raising():
    for document in (None, {}, [], "unexpected", 3, {"results": None}, [None, "x"]):
        assert failed_checks(document) == []
        assert sections(document) in ([], [{}], [{"results": None}])


def test_failure_keys_are_comparable_across_shapes():
    assert failure_keys([ONE, TWO]) == {("CKV_AWS_1", "a"), ("CKV_AWS_2", "b")}


def test_gate_a_reports_a_verdict_on_list_shaped_output():
    """List-shaped output yields a verdict rather than an AttributeError inside the gate."""
    result = evaluate(
        refresh_only_plan={"resource_drift": []},
        provider_schema=None,
        reconciled={},
        log_text="",
        checkov_result=[ONE, TWO],
    )

    assert result["checkov_failed_checks"] == 2
    assert result["verdict"] == "FAIL"
    assert result["claim"] == "no claim: the observable surface could not be established"


def test_gate_a_passes_when_there_are_no_findings_in_either_shape():
    for document in ({"results": {"failed_checks": []}}, [{"results": {"failed_checks": []}}]):
        result = evaluate(
            refresh_only_plan={"resource_drift": []},
            provider_schema=None,
            reconciled={},
            log_text="",
            checkov_result=document,
        )
        assert result["checkov_failed_checks"] == 0



# --- an empty scan is not a clean scan ---------------------------------------------

EMPTY = {"results": {"passed_checks": [], "failed_checks": []}}
CLEAN = {"results": {"passed_checks": [{"check_id": "CKV_AWS_79"}], "failed_checks": []}}


def test_evaluated_checks_distinguishes_absent_from_clean():
    assert evaluated_checks(EMPTY) == 0
    assert evaluated_checks(CLEAN) == 1
    assert evaluated_checks([ONE, TWO]) == 2
    assert evaluated_checks(None) == 0


def test_checkov_evaluates_nothing_on_a_refresh_only_plan_shape():
    """Encodes Checkov's behaviour on this shape without needing Checkov installed.

    A refresh-only plan has no `resource_changes` and an empty `planned_values`; the
    refreshed live values are in `prior_state` and `resource_drift`. Checkov's
    terraform_plan framework builds from `planned_values`, so it evaluates zero resources
    and returns zero passed and zero failed - observed on a captured real plan.
    """
    observed = {"check_type": "terraform_plan", "results": {"passed_checks": [], "failed_checks": []}}

    assert failed_checks(observed) == []
    assert evaluated_checks(observed) == 0
