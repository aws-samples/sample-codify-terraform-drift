"""Gate A tests.

The theme: every check exists because a provider failure looks identical to
"no drift" unless something positively asserts otherwise.
"""

from __future__ import annotations

from driftcode.detect.gate_a import (
    classify_attribute,
    classify_candidates,
    evaluate,
    scan_log,
)

PLAN = {"format_version": "1.2", "resource_drift": []}

# Minimal aws_launch_template schema: instance_type is settable, latest_version is
# computed-only, master_password is write-only.
SCHEMA = {
    "provider_schemas": {
        "registry.terraform.io/hashicorp/aws": {
            "resource_schemas": {
                "aws_launch_template": {
                    "block": {
                        "attributes": {
                            "instance_type": {"type": "string", "optional": True},
                            "description": {"type": "string", "optional": True},
                            "latest_version": {"type": "number", "computed": True},
                            "default_version": {"type": "number", "optional": True, "computed": True},
                            "arn": {"type": "string", "computed": True},
                        },
                        "block_types": {
                            "tag_specifications": {
                                "block": {"attributes": {"resource_type": {"type": "string", "optional": True}}}
                            }
                        },
                    }
                },
                "aws_db_instance": {
                    "block": {
                        "attributes": {
                            "password": {"type": "string", "optional": True, "write_only": True},
                        }
                    }
                },
            }
        }
    }
}

RECONCILED = {
    "real_drift": [
        {
            "address": "module.compute.aws_launch_template.app",
            "type": "aws_launch_template",
            "changed_attributes": ["instance_type", "description", "latest_version", "nonexistent_attr"],
        }
    ]
}


# --- fail closed when the read is suspect ----------------------------------

def test_missing_plan_fails_closed():
    r = evaluate(refresh_only_plan=None)
    assert r["verdict"] == "FAIL"
    assert "missing or unparseable" in r["failures"][0]
    assert r["claim"] == "no claim: the observable surface could not be established"


def test_authorization_failure_fails_closed():
    log = "Error: reading EC2 Launch Template: AccessDenied: not authorized to perform ec2:DescribeLaunchTemplates"
    r = evaluate(PLAN, log_text=log)
    assert r["verdict"] == "FAIL"
    assert any("unreadable" in f for f in r["failures"])


def test_expired_credentials_fail_closed():
    r = evaluate(PLAN, log_text="ExpiredToken: The security token included in the request is expired")
    assert r["verdict"] == "FAIL"


def test_throttling_fails_closed():
    """A throttled read can return an incomplete object without erroring."""
    r = evaluate(PLAN, log_text="ThrottlingException: Rate exceeded")
    assert r["verdict"] == "FAIL"
    assert any("throttl" in f.lower() for f in r["failures"])


def test_provider_inconsistency_fails_closed():
    r = evaluate(PLAN, log_text="Warning: Provider produced inconsistent result after apply")
    assert r["verdict"] == "FAIL"


def test_clean_run_passes_with_bounded_claim():
    r = evaluate(PLAN, log_text="Acquiring state lock...\nReleasing state lock...", provider_schema=SCHEMA)
    assert r["verdict"] == "PASS"
    assert r["claim"] == "reconciled over the observable projection"
    assert "fully reconciled" not in r["claim"]


def test_dangerous_drift_fails_the_gate():
    """A finding on the drift projection that the configured intent does not have."""
    baseline = {"results": {"passed_checks": [{"check_id": "CKV_PASS"}], "failed_checks": []}}
    checkov = {
        "results": {
            "passed_checks": [{"check_id": "CKV_PASS"}],
            "failed_checks": [
                {"check_id": "CKV_AWS_260", "resource": "aws_lb.a"},
                {"check_id": "CKV_AWS_23", "resource": "aws_security_group.b"},
            ],
        }
    }
    r = evaluate(PLAN, provider_schema=SCHEMA, checkov_result=checkov, checkov_baseline=baseline)
    assert r["verdict"] == "FAIL"
    assert r["checkov_failed_checks"] == 2
    assert len(r["policy_findings_introduced_by_drift"]) == 2
    assert any("dangerous" in f for f in r["failures"])


def test_clean_checkov_does_not_fail_the_gate():
    """A scan that ran and found nothing. Note the passed checks: they are what make it
    a clean scan rather than an absent one."""
    checkov = {
        "results": {
            "passed_checks": [{"check_id": "CKV_AWS_79"}, {"check_id": "CKV_AWS_23"}],
            "failed_checks": [],
        }
    }
    r = evaluate(PLAN, provider_schema=SCHEMA, checkov_result=checkov)
    assert r["verdict"] == "PASS"
    assert r["checkov_evaluated_checks"] == 2


def test_a_scan_that_evaluated_nothing_fails_the_gate():
    """Zero findings and zero checks is an absent scan, not a clean one.

    This is the shape Checkov actually produces when pointed at a refresh-only plan: its
    terraform_plan framework builds from planned_values, which refresh-only leaves empty,
    so it evaluates no resources and reports 0 passed and 0 failed. Reading only the
    failure count turns that into a pass on a scan that never happened - the same mistake
    as inferring "no drift" from silence.
    """
    r = evaluate(PLAN, provider_schema=SCHEMA, checkov_result={"results": {"failed_checks": []}})

    assert r["verdict"] == "FAIL"
    assert r["checkov_evaluated_checks"] == 0
    assert any("evaluated 0 checks" in f for f in r["failures"])


def test_no_checkov_result_at_all_is_not_silently_a_pass_either():
    """Omitting the scan is reported by the absence of the claim, not by inventing one."""
    r = evaluate(PLAN, provider_schema=SCHEMA, checkov_result=None)

    assert r["checkov_evaluated_checks"] == 0
    assert r["checkov_failed_checks"] == 0


# --- log scanning ----------------------------------------------------------

def test_scan_log_groups_by_signal():
    signals = scan_log("AccessDenied on thing\nRate exceeded: Throttling\nall good here")
    assert set(signals) == {"authorization", "throttling"}


def test_ordinary_log_produces_no_signals():
    assert scan_log("Refreshing state...\nPlan: 0 to add, 1 to change, 0 to destroy.") == {}


# --- schema classification ------------------------------------------------

def test_settable_attribute_is_codifiable():
    assert classify_attribute(SCHEMA, "aws_launch_template", "instance_type") == "codifiable"


def test_computed_only_attribute_is_not_codifiable():
    """latest_version genuinely differs after an out-of-band change, but it cannot be
    written in configuration, so it must never reach the agent as a target."""
    assert classify_attribute(SCHEMA, "aws_launch_template", "latest_version") == "computed"


def test_optional_and_computed_is_still_codifiable():
    assert classify_attribute(SCHEMA, "aws_launch_template", "default_version") == "codifiable"


def test_write_only_attribute_is_flagged():
    assert classify_attribute(SCHEMA, "aws_db_instance", "password") == "write_only"


def test_unknown_attribute_is_not_silently_accepted():
    assert classify_attribute(SCHEMA, "aws_launch_template", "invented_attr") == "unknown"


def test_unknown_resource_type_is_unknown():
    assert classify_attribute(SCHEMA, "aws_not_a_real_type", "whatever") == "unknown"


def test_nested_block_attribute_resolves():
    assert classify_attribute(SCHEMA, "aws_launch_template", "tag_specifications.0.resource_type") == "codifiable"


# --- candidate splitting --------------------------------------------------

def test_candidates_are_split_by_codifiability():
    [c] = classify_candidates(RECONCILED, SCHEMA)
    assert set(c["codifiable"]) == {"instance_type", "description"}
    assert c["computed"] == ["latest_version"]
    assert c["unclassified"] == ["nonexistent_attr"]


def test_unclassifiable_attributes_surface_as_warnings():
    r = evaluate(PLAN, provider_schema=SCHEMA, reconciled=RECONCILED)
    joined = " ".join(r["warnings"])
    assert "latest_version" in joined and "computed" in joined
    assert "nonexistent_attr" in joined


def test_absent_schema_is_a_warning_not_a_silent_pass():
    r = evaluate(PLAN, reconciled=RECONCILED)
    assert r["verdict"] == "PASS"  # not fatal on its own
    assert any("no provider schema" in w for w in r["warnings"])
    # ...but nothing may be treated as codifiable without one
    assert classify_candidates(RECONCILED, None)[0]["codifiable"] == []



# --- the policy verdict is a delta, not a count ------------------------------------
#
# Numbers here match what Checkov 3.3.17 reported on the captured plans: 9 findings on
# the configured intent, the same 9 on the projection of a benign drift, and one extra
# (CKV_AWS_24 on the security group) once SSH is opened to the world.

SG = "module.networking.aws_security_group.web_prod"


def scan(*failures, passed=9):
    return {
        "results": {
            "passed_checks": [{"check_id": f"CKV_PASS_{i}"} for i in range(passed)],
            "failed_checks": [
                {"check_id": check_id, "resource": resource} for check_id, resource in failures
            ],
        }
    }


PRE_EXISTING = (
    ("CKV_AWS_79", "module.compute.aws_launch_template.app"),
    ("CKV_AWS_382", SG),
    ("CKV2_AWS_5", SG),
)


def test_benign_drift_passes_despite_pre_existing_findings():
    """The nine findings the sample estate already carries are not this drift's fault."""
    r = evaluate(
        PLAN,
        provider_schema=SCHEMA,
        checkov_result=scan(*PRE_EXISTING),
        checkov_baseline=scan(*PRE_EXISTING),
    )

    assert r["verdict"] == "PASS"
    assert r["policy_findings_introduced_by_drift"] == []
    assert any("pre-existing" in w for w in r["warnings"])


def test_drift_that_introduces_a_finding_fails():
    """Case B: an operator opens SSH to the world, so the drift must not be codified."""
    r = evaluate(
        PLAN,
        provider_schema=SCHEMA,
        checkov_result=scan(*PRE_EXISTING, ("CKV_AWS_24", SG)),
        checkov_baseline=scan(*PRE_EXISTING),
    )

    assert r["verdict"] == "FAIL"
    assert r["policy_findings_introduced_by_drift"] == [
        {"check_id": "CKV_AWS_24", "resource": SG}
    ]
    assert any("must not be codified" in f for f in r["failures"])


def test_a_finding_the_drift_resolves_does_not_fail_the_gate():
    """Fewer findings than the baseline is not a reason to refuse; the delta is one-way."""
    r = evaluate(
        PLAN,
        provider_schema=SCHEMA,
        checkov_result=scan(PRE_EXISTING[0]),
        checkov_baseline=scan(*PRE_EXISTING),
    )

    assert r["verdict"] == "PASS"


def test_swapping_one_finding_for_another_still_fails():
    """A set difference catches this; a count comparison would not."""
    r = evaluate(
        PLAN,
        provider_schema=SCHEMA,
        checkov_result=scan(("CKV_AWS_24", SG)),
        checkov_baseline=scan(("CKV_AWS_79", "module.compute.aws_launch_template.app")),
    )

    assert r["verdict"] == "FAIL"
    assert [f["check_id"] for f in r["policy_findings_introduced_by_drift"]] == ["CKV_AWS_24"]


def test_a_drift_scan_without_a_baseline_cannot_apportion_blame():
    r = evaluate(PLAN, provider_schema=SCHEMA, checkov_result=scan(*PRE_EXISTING))

    assert r["verdict"] == "FAIL"
    assert any("no baseline was supplied" in f for f in r["failures"])


def test_an_empty_baseline_fails_rather_than_blaming_the_drift_for_everything():
    r = evaluate(
        PLAN,
        provider_schema=SCHEMA,
        checkov_result=scan(*PRE_EXISTING),
        checkov_baseline={"results": {"passed_checks": [], "failed_checks": []}},
    )

    assert r["verdict"] == "FAIL"
    assert any("nothing to compare against" in f for f in r["failures"])
    assert r["policy_findings_introduced_by_drift"] == []


def test_the_scan_target_mistake_is_still_caught_with_a_baseline_present():
    """Scanning the refresh-only plan itself: 0 evaluated. A baseline does not rescue it."""
    r = evaluate(
        PLAN,
        provider_schema=SCHEMA,
        checkov_result={"results": {"passed_checks": [], "failed_checks": []}},
        checkov_baseline=scan(*PRE_EXISTING),
    )

    assert r["verdict"] == "FAIL"
    assert any("evaluated 0 checks" in f for f in r["failures"])
    assert any("drift-project" in f for f in r["failures"])



def test_a_clean_drift_scan_needs_no_baseline():
    """Zero findings cannot have introduced one, so no comparison is required."""
    checkov = {
        "results": {
            "passed_checks": [{"check_id": "CKV_AWS_79"}, {"check_id": "CKV_AWS_23"}],
            "failed_checks": [],
        }
    }
    r = evaluate(PLAN, provider_schema=SCHEMA, checkov_result=checkov)

    assert r["verdict"] == "PASS"
    assert r["policy_findings_introduced_by_drift"] == []
