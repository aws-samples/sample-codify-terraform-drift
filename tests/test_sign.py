"""The drift signature H.

H decides which pull request a retry adopts and whether two consecutive runs are counted
as observations of the same drift. So the tests that matter are the stability ones - same
drift, same H - and the separation ones, where anything that should be a different drift
must not collide.
"""

from __future__ import annotations

import pytest

from driftcode.sign import (
    DEFAULT_VOLATILE_PATHS,
    attribute_at,
    branch_name,
    canonical_json,
    projection,
    sign_all,
    signature,
)

WORKSPACE = "dev"
REPO = "acme/infra"
ADDRESS = "module.compute.aws_launch_template.app"


def plan_entry(before=None, after=None, address=ADDRESS, actions=("update",)) -> dict:
    return {
        "address": address,
        "type": "aws_launch_template",
        "mode": "managed",
        "change": {
            "actions": list(actions),
            "before": before if before is not None else {"instance_type": "t3.micro"},
            "after": after if after is not None else {"instance_type": "t2.micro"},
        },
    }


def sign(entry=None, attributes=("instance_type",), **kwargs):
    kwargs.setdefault("workspace_id", WORKSPACE)
    kwargs.setdefault("repo", REPO)
    return signature(entry or plan_entry(), attributes, **kwargs)


# --- stability: the same drift must sign the same ------------------------------------


def test_the_signature_is_a_full_sha256():
    value = sign()

    assert len(value) == 64
    assert all(c in "0123456789abcdef" for c in value)


def test_the_same_drift_signs_identically():
    assert sign() == sign()


def test_key_order_in_the_plan_does_not_change_the_signature():
    a = plan_entry(before={"instance_type": "t3.micro", "image_id": "ami-1"})
    b = plan_entry(before={"image_id": "ami-1", "instance_type": "t3.micro"})

    assert sign(a) == sign(b)


def test_an_integral_float_and_an_int_sign_identically():
    """A provider upgrade emitting 1.0 where it emitted 1 must not fork the identity."""
    a = plan_entry(before={"desired_capacity": 1}, after={"desired_capacity": 2})
    b = plan_entry(before={"desired_capacity": 1.0}, after={"desired_capacity": 2.0})

    assert sign(a, ("desired_capacity",)) == sign(b, ("desired_capacity",))


def test_an_instance_index_is_stripped_so_it_matches_the_file_location_model():
    indexed = plan_entry(address=f'{ADDRESS}["prod"]')

    assert sign(indexed) == sign(plan_entry())


def test_unrelated_attributes_in_the_plan_do_not_affect_the_signature():
    """This is what keeps H stable while provider normalization noise comes and goes."""
    quiet = plan_entry(before={"instance_type": "t3.micro"}, after={"instance_type": "t2.micro"})
    noisy = plan_entry(
        before={"instance_type": "t3.micro", "enabled_metrics": None},
        after={"instance_type": "t2.micro", "enabled_metrics": []},
    )

    assert sign(quiet) == sign(noisy)


def test_volatile_attributes_are_excluded_even_when_reported_as_changed():
    with_volatile = sign(attributes=("instance_type", "latest_version"))

    assert with_volatile == sign(attributes=("instance_type",))
    assert "latest_version" in DEFAULT_VOLATILE_PATHS


# --- separation: different drift must not collide -----------------------------------


def test_a_different_value_signs_differently():
    assert sign() != sign(plan_entry(after={"instance_type": "m5.large"}))


def test_a_different_attribute_signs_differently():
    entry = plan_entry(
        before={"instance_type": "t3.micro", "image_id": "ami-1"},
        after={"instance_type": "t3.micro", "image_id": "ami-2"},
    )

    assert sign(entry, ("image_id",)) != sign(entry, ("instance_type",))


def test_a_different_resource_signs_differently():
    assert sign() != sign(plan_entry(address="module.compute.aws_launch_template.other"))


def test_a_different_action_signs_differently():
    assert sign() != sign(plan_entry(actions=("delete", "create")))


def test_the_same_drift_in_two_workspaces_signs_differently():
    """Two environments sharing a module must not share one pull request."""
    assert sign(workspace_id="dev") != sign(workspace_id="prod")


def test_the_same_drift_in_two_repositories_signs_differently():
    assert sign(repo="acme/infra") != sign(repo="acme/other-infra")


def test_a_tag_change_is_signed_because_it_can_be_a_privilege_change():
    entry = plan_entry(
        before={"tags": {"Team": "web"}},
        after={"tags": {"Team": "admin"}},
    )

    assert sign(entry, ("tags.Team",)) != sign(entry, ())


def test_unsalted_signing_is_refused():
    for workspace, repo in (("", REPO), (WORKSPACE, ""), ("", "")):
        with pytest.raises(ValueError, match="required as salt"):
            signature(plan_entry(), ["instance_type"], workspace, repo)


# --- ordering: only confirmed sets are sorted ---------------------------------------


def test_list_order_is_significant_by_default():
    """Blanket sorting would erase order-only drift on lists where order matters."""
    a = plan_entry(before={"p": ["a", "b"]}, after={"p": ["b", "a"]})

    assert sign(a, ("p",)) != sign(plan_entry(before={"p": ["a", "b"]}, after={"p": ["a", "b"]}), ("p",))


def test_a_schema_confirmed_set_is_order_insensitive():
    forward = plan_entry(before={"p": ["a", "b"]}, after={"p": ["x", "y"]})
    reversed_ = plan_entry(before={"p": ["b", "a"]}, after={"p": ["y", "x"]})

    assert sign(forward, ("p",), set_paths=["p"]) == sign(reversed_, ("p",), set_paths=["p"])


# --- the projection and its primitives ----------------------------------------------


def test_the_projection_carries_only_the_changed_paths():
    entry = plan_entry(
        before={"instance_type": "t3.micro", "image_id": "ami-1", "arn": "arn:aws:x"},
        after={"instance_type": "t2.micro", "image_id": "ami-1", "arn": "arn:aws:x"},
    )

    p = projection(entry, ["instance_type"])

    assert list(p["attributes"]) == ["instance_type"]
    assert p["attributes"]["instance_type"] == {"before": "t3.micro", "after": "t2.micro"}
    assert p["address"] == ADDRESS


def test_a_path_absent_from_before_projects_as_none():
    """An attribute the configuration never set has no prior value; that is not an error."""
    entry = plan_entry(before={}, after={"description": "hotfix"})

    p = projection(entry, ["description"])

    assert p["attributes"]["description"] == {"before": None, "after": "hotfix"}


@pytest.mark.parametrize(
    "path,expected",
    [
        ("a", 1),
        ("b.c", 2),
        ("d.0", "x"),
        ("d.1", "y"),
        ("d.5", None),
        ("missing", None),
        ("a.b", None),
    ],
)
def test_attribute_at_reads_dotted_paths(path, expected):
    values = {"a": 1, "b": {"c": 2}, "d": ["x", "y"]}

    assert attribute_at(values, path) == expected


def test_canonical_json_is_byte_stable():
    assert canonical_json({"b": 1, "a": [2, {"d": 4, "c": 3}]}) == '{"a":[2,{"c":3,"d":4}],"b":1}'


# --- branch names -------------------------------------------------------------------


def test_the_branch_name_is_deterministic_and_carries_the_full_hash():
    value = sign()

    assert branch_name(value, "dev") == f"drift/dev-{value}"
    assert branch_name(value, "dev") == branch_name(value, "dev")


def test_a_workspace_id_is_slugged_for_git():
    value = sign()

    assert branch_name(value, "team/dev env") == f"drift/team-dev-env-{value}"


def test_a_truncated_signature_is_refused_as_a_branch_key():
    with pytest.raises(ValueError, match="not a safe branch key"):
        branch_name(sign()[:12], "dev")


# --- signing a whole reconciliation -------------------------------------------------


def test_sign_all_joins_reconciled_paths_to_plan_values():
    reconciled = {
        "real_drift": [
            {"address": ADDRESS, "type": "aws_launch_template", "actions": ["update"],
             "changed_attributes": ["instance_type"]}
        ]
    }
    plan = {"resource_drift": [plan_entry()]}

    signatures = sign_all(reconciled, plan, WORKSPACE, REPO)

    assert list(signatures) == [ADDRESS]
    assert signatures[ADDRESS] == sign()


def test_sign_all_skips_an_address_with_no_values_rather_than_signing_nothing():
    """Signing an empty projection would give every such resource the same H."""
    reconciled = {"real_drift": [{"address": ADDRESS, "changed_attributes": ["instance_type"]}]}

    assert sign_all(reconciled, {"resource_drift": []}, WORKSPACE, REPO) == {}


def test_sign_all_on_a_quiet_estate_is_empty():
    assert sign_all({"real_drift": []}, {"resource_drift": []}, WORKSPACE, REPO) == {}
