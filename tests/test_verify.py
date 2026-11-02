"""The verifier: does the agent's diff match what the work order authorized?

The accepting cases are few and the rejecting cases are many, which is the intended shape.
Each rejection test corresponds to something an agent can plausibly do - edit the right
attribute in the wrong file, edit the right file at the wrong line, write a value nobody
observed, add a lifecycle block that makes the drift disappear - and each must fail.
"""

from __future__ import annotations

import json
import textwrap

import pytest

from driftcode.verify import (
    ACCEPT,
    REJECT,
    new_checkov_findings,
    parse_unified_diff,
    verify,
)

TFVARS = "environments/dev/terraform.tfvars"


def authorization(
    *,
    file: str = TFVARS,
    line: int = 7,
    attribute: str = "instance_type",
    assigned_name: str | None = None,
    observed: object = "t2.micro",
    layer: str = "workspace_tfvars",
) -> dict:
    return {
        "work_orders": [
            {
                "resource_address": "module.compute.aws_launch_template.app",
                "resource_type": "aws_launch_template",
                "edit_sites": [
                    {
                        "attribute": attribute,
                        "assigned_name": assigned_name or attribute,
                        "layer": layer,
                        "file": file,
                        "line": line,
                        "current_expression": '"t3.micro"',
                    }
                ],
                "drift": {
                    "attributes": [
                        {
                            "path": attribute,
                            "current_value_in_code": "t3.micro",
                            "observed_value_in_cloud": observed,
                        }
                    ]
                },
            }
        ]
    }


def diff(path: str = TFVARS, old_line: int = 7, removed: str = 'instance_type    = "t3.micro"', added: str = 'instance_type    = "t2.micro"') -> str:
    return textwrap.dedent(
        f"""\
        diff --git a/{path} b/{path}
        --- a/{path}
        +++ b/{path}
        @@ -{old_line},1 +{old_line},1 @@
        -{removed}
        +{added}
        """
    )


# --- accepting the one diff that is correct ----------------------------------------


def test_the_authorized_edit_is_accepted():
    result = verify(diff(), authorization())

    assert result["verdict"] == ACCEPT
    assert result["violations"] == []
    assert result["verified_edits"] == [
        {
            "file": TFVARS,
            "line": 7,
            "attribute": "instance_type",
            "resource_address": "module.compute.aws_launch_template.app",
            "value": "t2.micro",
        }
    ]


def test_realignment_and_requoting_do_not_matter():
    """Values are compared parsed, so formatting differences are not violations."""
    result = verify(
        diff(added='instance_type="t2.micro"   # hotfix codified'),
        authorization(),
    )

    assert result["verdict"] == ACCEPT


def test_a_numeric_value_is_compared_by_value():
    result = verify(
        diff(removed="desired_capacity = 1", added="desired_capacity = 2"),
        authorization(attribute="desired_capacity", observed=2),
    )

    assert result["verdict"] == ACCEPT


def test_a_boolean_value_is_not_satisfied_by_a_number():
    result = verify(
        diff(removed="enabled = false", added="enabled = 1"),
        authorization(attribute="enabled", observed=True),
    )

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "wrong_value"


def test_a_tfvars_site_is_checked_against_the_variable_name():
    """The identifier on a tfvars line is the variable's name, not the attribute's."""
    result = verify(
        diff(removed='app_size = "t3.micro"', added='app_size = "t2.micro"'),
        authorization(attribute="instance_type", assigned_name="app_size"),
    )

    assert result["verdict"] == ACCEPT


# --- rejecting everything else -----------------------------------------------------


def test_an_unauthorized_file_is_rejected():
    result = verify(diff(path="modules/compute/main.tf"), authorization())

    assert result["verdict"] == REJECT
    assert {v["kind"] for v in result["violations"]} >= {"unauthorized_file", "unmade_edit"}


def test_the_right_attribute_at_the_wrong_line_is_rejected():
    result = verify(diff(old_line=9), authorization(line=7))

    assert result["verdict"] == REJECT
    assert any(v["kind"] == "unauthorized_line" for v in result["violations"])


def test_a_value_nobody_observed_is_rejected():
    result = verify(diff(added='instance_type = "m5.24xlarge"'), authorization())

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "wrong_value"
    assert "m5.24xlarge" in result["violations"][0]["detail"]


def test_a_different_attribute_on_an_authorized_line_is_rejected():
    result = verify(
        diff(removed='instance_type = "t3.micro"', added='ami_id = "t2.micro"'),
        authorization(),
    )

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "renamed_assignment"


def test_editing_a_neighbouring_attribute_is_rejected():
    result = verify(
        diff(removed='ami_id = "ami-1"', added='ami_id = "ami-2"'),
        authorization(),
    )

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "wrong_attribute"


def test_an_expression_instead_of_the_observed_value_is_rejected():
    result = verify(diff(added="instance_type = var.override"), authorization())

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "non_literal_value"


@pytest.mark.parametrize("added", ["  lifecycle {", "    ignore_changes = [instance_type]"])
def test_introducing_drift_suppression_is_rejected(added: str):
    """A lifecycle block makes the drift vanish from every downstream signal."""
    body = textwrap.dedent(
        f"""\
        diff --git a/{TFVARS} b/{TFVARS}
        --- a/{TFVARS}
        +++ b/{TFVARS}
        @@ -7,1 +7,2 @@
        -instance_type = "t3.micro"
        +instance_type = "t2.micro"
        +{added}
        """
    )
    result = verify(body, authorization())

    assert result["verdict"] == REJECT
    assert any(v["kind"] == "drift_suppression" for v in result["violations"])


def test_an_extra_added_line_is_rejected_even_if_harmless():
    """A comment is not a codified value, and the authorization covers one line."""
    body = textwrap.dedent(
        f"""\
        diff --git a/{TFVARS} b/{TFVARS}
        --- a/{TFVARS}
        +++ b/{TFVARS}
        @@ -7,1 +7,2 @@
        -instance_type = "t3.micro"
        +instance_type = "t2.micro"
        +# codified from the 2am hotfix
        """
    )
    result = verify(body, authorization())

    assert result["verdict"] == REJECT
    assert any(v["kind"] == "not_a_replacement" for v in result["violations"])


def test_an_insertion_is_not_a_replacement():
    body = textwrap.dedent(
        f"""\
        diff --git a/{TFVARS} b/{TFVARS}
        --- a/{TFVARS}
        +++ b/{TFVARS}
        @@ -7,0 +7,1 @@
        +instance_type = "t2.micro"
        """
    )
    result = verify(body, authorization())

    assert result["verdict"] == REJECT
    assert any(v["kind"] == "not_a_replacement" for v in result["violations"])


def test_a_new_file_is_rejected():
    body = textwrap.dedent(
        """\
        diff --git a/environments/dev/override.tf b/environments/dev/override.tf
        new file mode 100644
        --- /dev/null
        +++ b/environments/dev/override.tf
        @@ -0,0 +1,1 @@
        +resource "aws_launch_template" "app" {}
        """
    )
    result = verify(body, authorization())

    assert result["verdict"] == REJECT
    assert any(v["kind"] == "structural_change" for v in result["violations"])


def test_a_deleted_file_is_rejected():
    body = textwrap.dedent(
        f"""\
        diff --git a/{TFVARS} b/{TFVARS}
        deleted file mode 100644
        --- a/{TFVARS}
        +++ /dev/null
        @@ -1,9 +0,0 @@
        -instance_type = "t3.micro"
        """
    )
    result = verify(body, authorization())

    assert result["verdict"] == REJECT
    assert any(v["kind"] == "structural_change" for v in result["violations"])


def test_a_rename_is_rejected():
    body = textwrap.dedent(
        f"""\
        diff --git a/{TFVARS} b/environments/dev/vars.tfvars
        rename from {TFVARS}
        rename to environments/dev/vars.tfvars
        """
    )
    result = verify(body, authorization())

    assert result["verdict"] == REJECT
    assert any(v["kind"] == "structural_change" for v in result["violations"])


def test_an_authorized_edit_that_was_not_made_is_rejected():
    """An unmade edit is a silent failure, so it is a violation rather than an accept."""
    result = verify("", authorization())

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "empty_diff"


def test_a_second_authorized_attribute_left_unedited_is_rejected():
    auth = authorization()
    auth["work_orders"][0]["edit_sites"].append(
        {
            "attribute": "ami_id",
            "assigned_name": "ami_id",
            "layer": "workspace_tfvars",
            "file": TFVARS,
            "line": 6,
            "current_expression": '"ami-1"',
        }
    )
    auth["work_orders"][0]["drift"]["attributes"].append(
        {"path": "ami_id", "current_value_in_code": "ami-1", "observed_value_in_cloud": "ami-2"}
    )

    result = verify(diff(), auth)

    assert result["verdict"] == REJECT
    assert [v["kind"] for v in result["violations"]] == ["unmade_edit"]


def test_a_diff_with_no_authorization_is_rejected():
    result = verify(diff(), {"work_orders": []})

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "unauthorized_change"


def test_no_authorization_and_no_diff_is_accepted():
    """A quiet estate: nothing authorized, nothing changed."""
    result = verify("", {"work_orders": []})

    assert result["verdict"] == ACCEPT


def test_a_non_assignment_line_is_rejected():
    result = verify(diff(removed="  }", added="  })"), authorization())

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "not_an_assignment"


# --- the policy delta --------------------------------------------------------------


def checkov(*failures: tuple[str, str]) -> dict:
    return {
        "results": {
            "failed_checks": [
                {"check_id": check_id, "resource": resource} for check_id, resource in failures
            ]
        }
    }


def test_a_new_policy_finding_rejects_the_diff():
    result = verify(
        diff(),
        authorization(),
        checkov_before=checkov(),
        checkov_after=checkov(("CKV_AWS_1", "aws_s3_bucket.data")),
    )

    assert result["verdict"] == REJECT
    assert result["violations"][0]["kind"] == "new_policy_finding"


def test_pre_existing_findings_do_not_reject_the_diff():
    existing = checkov(("CKV_AWS_1", "aws_s3_bucket.data"))

    result = verify(diff(), authorization(), checkov_before=existing, checkov_after=existing)

    assert result["verdict"] == ACCEPT


def test_findings_are_compared_as_a_set_not_a_count():
    """Fixing one finding while introducing another leaves the count unchanged."""
    findings = new_checkov_findings(
        checkov(("CKV_AWS_1", "a")), checkov(("CKV_AWS_2", "b"))
    )

    assert findings == [{"check_id": "CKV_AWS_2", "resource": "b"}]


# --- diff parsing primitives -------------------------------------------------------


def test_line_numbers_follow_context_lines():
    body = textwrap.dedent(
        f"""\
        diff --git a/{TFVARS} b/{TFVARS}
        --- a/{TFVARS}
        +++ b/{TFVARS}
        @@ -5,5 +5,5 @@
         ami_id           = "ami-1"
         internal_cidr    = "10.0.0.0/8"
        -instance_type    = "t3.micro"
        +instance_type    = "t2.micro"
         desired_capacity = 1
        """
    )
    files = parse_unified_diff(body)

    assert len(files) == 1
    assert files[0].removed == [(7, 'instance_type    = "t3.micro"')]
    assert files[0].added == [(7, 'instance_type    = "t2.micro"')]


def test_multiple_files_are_parsed_separately():
    body = diff() + diff(path="modules/compute/main.tf", old_line=13)
    files = parse_unified_diff(body)

    assert [f.path for f in files] == [TFVARS, "modules/compute/main.tf"]


def test_no_newline_marker_is_ignored():
    body = diff() + "\\ No newline at end of file\n"

    assert parse_unified_diff(body)[0].added == [(7, 'instance_type    = "t2.micro"')]


# --- the command-line surface ------------------------------------------------------


def test_cli_rejects_with_a_non_zero_exit(tmp_path):
    from driftcode.verify import main

    auth = tmp_path / "authorization.json"
    auth.write_text(json.dumps(authorization()), encoding="utf-8")
    patch = tmp_path / "change.diff"
    patch.write_text(diff(added='instance_type = "m5.large"'), encoding="utf-8")
    out = tmp_path / "verification.json"

    code = main(["--authorization", str(auth), "--diff", str(patch), "--out", str(out)])

    assert code == 1
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == REJECT


def test_cli_accepts_with_a_zero_exit(tmp_path):
    from driftcode.verify import main

    auth = tmp_path / "authorization.json"
    auth.write_text(json.dumps(authorization()), encoding="utf-8")
    patch = tmp_path / "change.diff"
    patch.write_text(diff(), encoding="utf-8")
    out = tmp_path / "verification.json"

    code = main(["--authorization", str(auth), "--diff", str(patch), "--out", str(out)])

    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == ACCEPT



# --- multiple simultaneous edits, on the ACCEPT path --------------------------------
#
# Every accept case above uses one work order with one site. The failure mode for multiple
# edits is covered ("second attribute left unedited"); these cover the success case, where a
# bug in pairing removals to additions across several sites, files or work orders would
# otherwise pass unnoticed.


def site(attribute, line, file=TFVARS, assigned=None, layer="workspace_tfvars", current='"old"'):
    return {
        "attribute": attribute,
        "assigned_name": assigned or attribute,
        "layer": layer,
        "file": file,
        "line": line,
        "current_expression": current,
    }


def attribute(path, before, after):
    return {
        "path": path,
        "current_value_in_code": before,
        "observed_value_in_cloud": after,
    }


def order(address, sites, attributes):
    return {
        "resource_address": address,
        "resource_type": "aws_launch_template",
        "edit_sites": sites,
        "drift": {"attributes": attributes},
    }


def hunk(file, pairs):
    """A single-file diff replacing each (line, old, new) in ascending line order."""
    body = [f"diff --git a/{file} b/{file}", f"--- a/{file}", f"+++ b/{file}"]
    for line, old, new in pairs:
        body += [f"@@ -{line},1 +{line},1 @@", f"-{old}", f"+{new}"]
    return "\n".join(body) + "\n"


def test_two_attributes_in_one_file_are_both_verified():
    auth = {
        "work_orders": [
            order(
                "module.compute.aws_launch_template.app",
                [site("instance_type", 7), site("ami_id", 6)],
                [
                    attribute("instance_type", "t3.micro", "t2.micro"),
                    attribute("ami_id", "ami-1", "ami-2"),
                ],
            )
        ]
    }
    body = hunk(
        TFVARS,
        [
            (6, 'ami_id           = "ami-1"', 'ami_id           = "ami-2"'),
            (7, 'instance_type    = "t3.micro"', 'instance_type    = "t2.micro"'),
        ],
    )

    result = verify(body, auth)

    assert result["verdict"] == ACCEPT
    assert result["counts"]["verified_edits"] == 2
    assert {e["attribute"] for e in result["verified_edits"]} == {"ami_id", "instance_type"}


def test_two_attributes_in_one_hunk_are_paired_by_position():
    """Adjacent lines land in one hunk, so removals and additions interleave differently."""
    auth = {
        "work_orders": [
            order(
                "module.compute.aws_launch_template.app",
                [site("ami_id", 6), site("instance_type", 7)],
                [
                    attribute("ami_id", "ami-1", "ami-2"),
                    attribute("instance_type", "t3.micro", "t2.micro"),
                ],
            )
        ]
    }
    body = textwrap.dedent(
        f"""\
        diff --git a/{TFVARS} b/{TFVARS}
        --- a/{TFVARS}
        +++ b/{TFVARS}
        @@ -5,4 +5,4 @@
         internal_cidr    = "10.0.0.0/8"
        -ami_id           = "ami-1"
        -instance_type    = "t3.micro"
        +ami_id           = "ami-2"
        +instance_type    = "t2.micro"
         desired_capacity = 1
        """
    )

    result = verify(body, auth)

    assert result["verdict"] == ACCEPT
    assert result["counts"]["verified_edits"] == 2


def test_edits_across_two_files_are_both_verified():
    """A resource-literal site and a tfvars site in the same work order."""
    module = "modules/compute/main.tf"
    auth = {
        "work_orders": [
            order(
                "module.compute.aws_launch_template.app",
                [
                    site("instance_type", 7),
                    site("description", 13, file=module, layer="resource_literal"),
                ],
                [
                    attribute("instance_type", "t3.micro", "t2.micro"),
                    attribute("description", "old", "new"),
                ],
            )
        ]
    }
    body = hunk(TFVARS, [(7, 'instance_type = "t3.micro"', 'instance_type = "t2.micro"')]) + hunk(
        module, [(13, '  description = "old"', '  description = "new"')]
    )

    result = verify(body, auth)

    assert result["verdict"] == ACCEPT
    assert result["counts"]["verified_edits"] == 2
    assert set(result["files_changed"]) == {TFVARS, module}


def test_two_work_orders_are_both_verified():
    """Two resources codified in one run, each with its own file."""
    storage = "environments/dev/storage.tfvars"
    auth = {
        "work_orders": [
            order(
                "module.compute.aws_launch_template.app",
                [site("instance_type", 7)],
                [attribute("instance_type", "t3.micro", "t2.micro")],
            ),
            order(
                "module.storage.aws_s3_bucket.data",
                [site("bucket_class", 3, file=storage)],
                [attribute("bucket_class", "standard", "ia")],
            ),
        ]
    }
    body = hunk(TFVARS, [(7, 'instance_type = "t3.micro"', 'instance_type = "t2.micro"')]) + hunk(
        storage, [(3, 'bucket_class = "standard"', 'bucket_class = "ia"')]
    )

    result = verify(body, auth)

    assert result["verdict"] == ACCEPT
    assert result["counts"]["verified_edits"] == 2
    assert {e["resource_address"] for e in result["verified_edits"]} == {
        "module.compute.aws_launch_template.app",
        "module.storage.aws_s3_bucket.data",
    }


def test_two_work_orders_sharing_one_file_are_both_verified():
    """Sites from different resources can legitimately land in the same tfvars file."""
    auth = {
        "work_orders": [
            order(
                "module.compute.aws_launch_template.app",
                [site("instance_type", 7)],
                [attribute("instance_type", "t3.micro", "t2.micro")],
            ),
            order(
                "module.compute.aws_autoscaling_group.app",
                [site("max_size", 9)],
                [attribute("max_size", 4, 6)],
            ),
        ]
    }
    body = hunk(
        TFVARS,
        [
            (7, 'instance_type = "t3.micro"', 'instance_type = "t2.micro"'),
            (9, "max_size      = 4", "max_size      = 6"),
        ],
    )

    result = verify(body, auth)

    assert result["verdict"] == ACCEPT
    assert result["counts"]["verified_edits"] == 2


def test_one_correct_edit_among_several_does_not_rescue_the_others():
    """Partial success is rejection: two authorized, one made, one wrong value."""
    auth = {
        "work_orders": [
            order(
                "module.compute.aws_launch_template.app",
                [site("instance_type", 7), site("ami_id", 6)],
                [
                    attribute("instance_type", "t3.micro", "t2.micro"),
                    attribute("ami_id", "ami-1", "ami-2"),
                ],
            )
        ]
    }
    body = hunk(
        TFVARS,
        [
            (6, 'ami_id        = "ami-1"', 'ami_id        = "ami-99"'),
            (7, 'instance_type = "t3.micro"', 'instance_type = "t2.micro"'),
        ],
    )

    result = verify(body, auth)

    assert result["verdict"] == REJECT
    assert [v["kind"] for v in result["violations"]] == ["wrong_value"]
    # The correct edit is still recorded, so a reviewer sees what was right as well.
    assert [e["attribute"] for e in result["verified_edits"]] == ["instance_type"]


def test_editing_one_of_two_work_orders_is_rejected():
    auth = {
        "work_orders": [
            order(
                "module.compute.aws_launch_template.app",
                [site("instance_type", 7)],
                [attribute("instance_type", "t3.micro", "t2.micro")],
            ),
            order(
                "module.storage.aws_s3_bucket.data",
                [site("bucket_class", 3, file="environments/dev/storage.tfvars")],
                [attribute("bucket_class", "standard", "ia")],
            ),
        ]
    }
    body = hunk(TFVARS, [(7, 'instance_type = "t3.micro"', 'instance_type = "t2.micro"')])

    result = verify(body, auth)

    assert result["verdict"] == REJECT
    assert [v["kind"] for v in result["violations"]] == ["unmade_edit"]
    assert result["violations"][0]["file"] == "environments/dev/storage.tfvars"
