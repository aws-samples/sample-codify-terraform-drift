"""Independently-sourced ground truth: real provider output, committed and always run.

Every other test in this suite runs against fixtures written by hand alongside the logic
they exercise. That checks internal consistency, which is the kind of confidence that
survives a wrong assumption about what Terraform actually emits — and two assumptions a
hand-written fixture invites are both false: a refresh-only plan reports provider
normalization as drift, and its ``planned_values`` is empty so a plan-based scanner
evaluates nothing.

So the captured plans are committed, reduced and redacted by ``tests/redact_plan.py``. They
are real ``terraform show -json`` output from an applied nine-resource stack with exactly
one induced drift. Structure, attribute names, actions, and the ``null`` versus ``[]``
distinctions are untouched, because those are the properties under test.

The first test below is the safety interlock: if the redactor ever regresses, these fixtures
fail the leak scan rather than quietly carrying an account identifier into a distributed
repository.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from driftcode.classify import CODIFIABLE, UNCONFIRMED_OBSERVATION, classify_all
from driftcode.detect.gate_a import evaluate
from driftcode.detect.reconcile import reconcile
from driftcode.policy import evaluated_checks
from driftcode.project import count_resources, drift_projection
from driftcode.sign import sign_all

FIXTURES = Path(__file__).parent / "fixtures"
REFRESH_ONLY = FIXTURES / "real-refresh-only.json"
FULL_PLAN = FIXTURES / "real-full-plan.json"

REAL_DRIFT = "module.compute.aws_launch_template.app"


@pytest.fixture(scope="module")
def refresh_only() -> dict:
    return json.loads(REFRESH_ONLY.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def full_plan() -> dict:
    return json.loads(FULL_PLAN.read_text(encoding="utf-8"))


# --- the interlock: these files must stay free of identifiers ------------------------
#
# Written as an ALLOWLIST over identifier shapes, not as a list of known-bad patterns. A scan
# built from the redactor's own pattern list can only catch classes the redactor already handles,
# which makes it a redactor checking its own homework: an identifier class nobody thought of
# passes both. Two identifier classes reached a committed fixture that way - route-table ids and
# S3 canonical user ids.
#
# So the question asked here is inverted. Anything *shaped* like an identifier must be a known
# placeholder, and anything else fails - whether or not the redactor knows how to handle it.

#: Any AWS resource identifier: lowercase prefix, hyphen, hex.
RESOURCE_ID = re.compile(r"\b([a-z][a-z0-9]{1,12})-([0-9a-f]{8,})\b")

#: Bare hex runs long enough to be an identifier rather than a coincidence. Covers S3 canonical
#: user ids, which map to an account as directly as an account number, plus ETags and digests.
BARE_HEX = re.compile(r"\b[0-9a-f]{32,}\b")

#: Long mixed-case runs: access key ids, session tokens, base64 material.
OPAQUE_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

#: Structured identifiers that are not hex-shaped.
NAMED_SHAPES = {
    "account id": re.compile(r"\b\d{12}\b"),
    # Excludes the backslash too: an ARN inside an embedded policy document is JSON-escaped, so
    # the redacted value is followed by the escape rather than by the quote.
    "arn": re.compile(r'arn:aws:[^"\s,\]}\\]+'),
    "iam unique id": re.compile(r"\b(?:AROA|AIDA|ASIA|AKIA)[A-Z0-9]{8,}\b"),
    "email address": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"),
}

#: The only values an identifier-shaped string is allowed to be. Everything here is something the
#: redactor produces deliberately.
def _is_placeholder(value: str) -> bool:
    hexpart = value.split("-")[-1] if "-" in value else value
    return (
        set(hexpart) <= {"0"}
        or value in ("000000000000", "arn:aws:REDACTED", "REDACTED")
        or value in ("AROAREDACTEDROLEID", "AIDAREDACTEDUSERID")
        or value.endswith("REDACTED")
    )


@pytest.mark.parametrize("path", [REFRESH_ONLY, FULL_PLAN], ids=lambda p: p.name)
def test_no_resource_identifier_survives(path: Path):
    """Any prefix-hex identifier must be zeroed, including prefixes the redactor never saw."""
    leaks = sorted(
        {m.group(0) for m in RESOURCE_ID.finditer(path.read_text(encoding="utf-8"))
         if not _is_placeholder(m.group(0))}
    )

    assert leaks == [], f"{path.name} leaks resource identifiers: {leaks[:6]}"


@pytest.mark.parametrize("path", [REFRESH_ONLY, FULL_PLAN], ids=lambda p: p.name)
def test_no_bare_hex_identifier_survives(path: Path):
    """Catches S3 canonical user ids, which identify an account as precisely as its number."""
    leaks = sorted(
        {m.group(0) for m in BARE_HEX.finditer(path.read_text(encoding="utf-8"))
         if not _is_placeholder(m.group(0))}
    )

    assert leaks == [], f"{path.name} leaks bare hex identifiers: {[l[:16] + '…' for l in leaks[:6]]}"


@pytest.mark.parametrize("path", [REFRESH_ONLY, FULL_PLAN], ids=lambda p: p.name)
def test_no_opaque_token_survives(path: Path):
    leaks = sorted(
        {m.group(0) for m in OPAQUE_TOKEN.finditer(path.read_text(encoding="utf-8"))
         if not _is_placeholder(m.group(0))}
    )

    assert leaks == [], f"{path.name} leaks opaque tokens: {[l[:16] + '…' for l in leaks[:6]]}"


@pytest.mark.parametrize("path", [REFRESH_ONLY, FULL_PLAN], ids=lambda p: p.name)
@pytest.mark.parametrize("label", sorted(NAMED_SHAPES))
def test_no_named_identifier_shape_survives(path: Path, label: str):
    leaks = sorted(
        {m.group(0) for m in NAMED_SHAPES[label].finditer(path.read_text(encoding="utf-8"))
         if not _is_placeholder(m.group(0))}
    )

    assert leaks == [], f"{path.name} leaks {label}: {leaks[:6]}"


def test_the_scan_would_catch_an_identifier_class_the_redactor_does_not_handle():
    """The property that makes this an interlock rather than a restatement.

    A prefix no redaction rule enumerates must still fail the scan, otherwise the scan is only as
    good as the redactor and adds nothing.
    """
    invented = "quicksightns-0a1b2c3d4e5f6789"

    assert RESOURCE_ID.search(invented)
    assert not _is_placeholder(invented)


def test_placeholders_are_recognised_so_the_scan_is_not_vacuous():
    """A scan that flagged its own placeholders would be turned off within a week."""
    for value in ("rtb-00000000000000000", "000000000000", "arn:aws:REDACTED", "0" * 64):
        assert _is_placeholder(value), value


# --- what a real refresh-only plan actually looks like ------------------------------


def test_a_real_refresh_only_plan_has_no_resource_changes(refresh_only):
    """There is no resource_changes key at all, so a gate keyed on it sees an empty estate."""
    assert "resource_changes" not in refresh_only or not refresh_only["resource_changes"]


def test_a_real_refresh_only_plan_has_empty_planned_values(refresh_only):
    """Which is why a plan-based policy scanner evaluates nothing on it."""
    assert count_resources(refresh_only, "planned_values") == 0


def test_the_live_values_are_in_prior_state(refresh_only):
    assert count_resources(refresh_only, "prior_state") > 0


# --- reconciliation against real provider output ------------------------------------


def test_refresh_only_over_reports_against_the_full_plan(refresh_only, full_plan):
    """Why two-plan reconciliation is required: 4 reported, 1 real."""
    result = reconcile(refresh_only, full_plan)

    assert result["counts"]["refresh_only_reported"] == 4
    assert result["counts"]["real_drift"] == 1
    assert result["counts"]["suppressed"] == 3


def test_the_one_real_drift_is_the_launch_template(refresh_only, full_plan):
    result = reconcile(refresh_only, full_plan)

    assert [e["address"] for e in result["real_drift"]] == [REAL_DRIFT]


def test_every_phantom_carried_the_same_action_as_the_real_drift(refresh_only):
    """An action filter cannot separate them, which is the whole reason for the intersection."""
    actions = {
        tuple(e["change"]["actions"]) for e in refresh_only["resource_drift"]
    }

    assert actions == {("update",)}


def test_the_suppressed_resources_are_the_known_normalization_sources(refresh_only, full_plan):
    result = reconcile(refresh_only, full_plan)

    assert {e["address"] for e in result["suppressed"]} == {
        "module.compute.aws_autoscaling_group.app",
        "module.iam.aws_iam_role.app_role",
        "module.storage.aws_s3_bucket.data_bucket",
    }


def test_reconciliation_narrows_attributes_not_only_resources(refresh_only, full_plan):
    """Real drift and normalization noise coexist on the same resource."""
    result = reconcile(refresh_only, full_plan)
    changed = result["real_drift"][0]["changed_attributes"]

    assert "instance_type" in changed
    assert len(changed) > 1, "the real resource also reported attributes that are not drift"


# --- the projection makes the drift scannable --------------------------------------


def test_the_projection_recovers_the_resources_the_scan_needs(refresh_only):
    projected = drift_projection(refresh_only)

    assert count_resources(refresh_only, "planned_values") == 0
    assert count_resources(projected, "planned_values") == 9


def test_the_projection_carries_the_drifted_value(refresh_only):
    projected = drift_projection(refresh_only)

    def walk(module):
        for r in module.get("resources") or []:
            yield r
        for c in module.get("child_modules") or []:
            yield from walk(c)

    templates = [
        r for r in walk(projected["planned_values"]["root_module"])
        if r["type"] == "aws_launch_template"
    ]

    assert len(templates) == 1
    assert templates[0]["values"]["instance_type"] == "t2.micro"


def test_the_projection_drops_data_sources(refresh_only):
    """Two of the eleven prior-state entries are data sources; they cannot drift."""
    projected = drift_projection(refresh_only)

    def walk(module):
        for r in module.get("resources") or []:
            yield r
        for c in module.get("child_modules") or []:
            yield from walk(c)

    assert all(r.get("mode") == "managed" for r in walk(projected["planned_values"]["root_module"]))
    assert count_resources(refresh_only, "prior_state") == 11


# --- Gate A against real output ----------------------------------------------------


def test_gate_a_refuses_a_scan_of_the_raw_refresh_only_plan(refresh_only, full_plan):
    """On the real document 0 checks are evaluated, which reads as clean to a count check."""
    empty = {"check_type": "terraform_plan", "results": {"passed_checks": [], "failed_checks": []}}

    result = evaluate(
        refresh_only,
        reconciled=reconcile(refresh_only, full_plan),
        checkov_result=empty,
    )

    assert evaluated_checks(empty) == 0
    assert result["verdict"] == "FAIL"
    assert any("evaluated 0 checks" in f for f in result["failures"])


def test_gate_a_classifies_the_real_computed_attribute(refresh_only, full_plan):
    """latest_version legitimately differs and cannot be set in configuration."""
    schema_free = evaluate(refresh_only, reconciled=reconcile(refresh_only, full_plan))

    assert any("no provider schema" in w for w in schema_free["warnings"])


# --- signing and classification against real output --------------------------------


def test_the_real_drift_signs_stably(refresh_only, full_plan):
    reconciled = reconcile(refresh_only, full_plan)

    first = sign_all(reconciled, refresh_only, "dev", "acme/infra")
    second = sign_all(reconciled, refresh_only, "dev", "acme/infra")

    assert list(first) == [REAL_DRIFT]
    assert first == second
    assert len(first[REAL_DRIFT]) == 64


def test_the_signature_survives_the_phantom_attributes(refresh_only, full_plan):
    """H is taken over reconciled paths, so noise that clears after an apply cannot move it."""
    reconciled = reconcile(refresh_only, full_plan)
    with_noise = sign_all(reconciled, refresh_only, "dev", "acme/infra")

    stripped = json.loads(json.dumps(refresh_only))
    for entry in stripped["resource_drift"]:
        if entry["address"] == REAL_DRIFT:
            continue
        entry["change"]["after"] = entry["change"]["before"]

    assert sign_all(reconciled, stripped, "dev", "acme/infra") == with_noise


def test_the_real_drift_is_unconfirmed_on_a_first_sighting(refresh_only, full_plan):
    result = classify_all(reconcile(refresh_only, full_plan), {})

    assert [d["code"] for d in result["suppress"]] == [UNCONFIRMED_OBSERVATION]
    assert result["has_work"] is False


def test_the_real_drift_is_codifiable_once_confirmed_and_traced(refresh_only, full_plan):
    result = classify_all(
        reconcile(refresh_only, full_plan),
        {"attribute_classification": [{"address": REAL_DRIFT, "codifiable": ["instance_type"]}]},
        confirmed_samples=2,
        source_layers={"instance_type": "workspace_tfvars"},
    )

    assert [d["code"] for d in result["codify"]] == [CODIFIABLE]
    assert result["codify"][0]["authorized_attributes"] == ["instance_type"]
