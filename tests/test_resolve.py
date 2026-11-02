"""Source-layer tracing: does a value belong to this workspace or to its siblings?

The layer decides whether an attribute may be codified at all, so the cases that must
not be classified local are tested as carefully as the ones that must.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from driftcode.classify import CODIFY, ESCALATE, classify_resource
from driftcode.resolve import (
    EXPRESSION,
    EXTERNAL_VARIABLE,
    MODULE_INPUT,
    MODULE_RESOURCE_LITERAL,
    MODULE_VARIABLE_DEFAULT,
    NESTED_ATTRIBUTE,
    RESOURCE_LITERAL,
    SHARED_TFVARS,
    UNKNOWN,
    WORKSPACE_TFVARS,
    WORKSPACE_VARIABLE_DEFAULT,
    is_literal,
    resolve_attribute,
    source_layers,
    strip_comment,
    top_level_assignments,
)

ADDRESS = "module.compute.aws_launch_template.app"
ROOT_ADDRESS = "aws_launch_template.app"


def write(root: Path, relative: str, body: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


def repo(
    tmp_path: Path,
    *,
    module_body: str,
    module_variables: str = 'variable "instance_type" {\n  type = string\n}\n',
    root_body: str | None = None,
    root_variables: str | None = 'variable "instance_type" {\n  type = string\n}\n',
    tfvars: str | None = 'instance_type = "t3.micro"\n',
) -> tuple[Path, Path]:
    """Build a two-level workspace: environments/dev calling modules/compute."""
    write(tmp_path, "modules/compute/main.tf", module_body)
    write(tmp_path, "modules/compute/variables.tf", module_variables)

    if root_body is None:
        root_body = """
        module "compute" {
          source        = "../../modules/compute"
          instance_type = var.instance_type
        }
        """
    write(tmp_path, "environments/dev/main.tf", root_body)
    if root_variables is not None:
        write(tmp_path, "environments/dev/variables.tf", root_variables)
    if tfvars is not None:
        write(tmp_path, "environments/dev/terraform.tfvars", tfvars)

    return tmp_path, tmp_path / "environments" / "dev"


def root_repo(tmp_path: Path, *, body: str) -> tuple[Path, Path]:
    """A workspace declaring the resource in its own root module, with no module call.

    Used wherever a test needs an *editable* literal: a literal on a resource inside a
    reusable module is shared by every caller of that module and escalates instead.
    """
    write(tmp_path, "environments/dev/main.tf", body)
    return tmp_path, tmp_path / "environments" / "dev"


# --- the local layers, which are the only ones that may be codified ----------------


def test_literal_in_a_root_module_resource_block_is_workspace_local(tmp_path: Path):
    root, workspace = root_repo(
        tmp_path,
        body="""
        resource "aws_launch_template" "app" {
          instance_type = "t3.micro"
        }
        """,
    )
    r = resolve_attribute(ROOT_ADDRESS, "instance_type", root, workspace)

    assert r.layer == RESOURCE_LITERAL
    assert r.is_workspace_local
    assert r.edit_file == "environments/dev/main.tf"
    assert r.edit_line == 2
    assert r.expression == '"t3.micro"'


def test_literal_in_a_reusable_module_resource_block_escalates(tmp_path: Path):
    """The same literal, one directory over, is shared by every caller of that module.

    Editing it would write one environment's drift into every other environment that calls
    the module, so it escalates - exactly as a module variable's default does. The value is
    still reported; it just yields no edit site.
    """
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = "t3.micro"
        }
        """,
    )
    r = resolve_attribute(ADDRESS, "instance_type", root, workspace)

    assert r.layer == MODULE_RESOURCE_LITERAL
    assert not r.is_workspace_local
    assert r.edit_file is None
    assert r.edit_line is None
    assert r.expression == '"t3.micro"'
    assert "every workspace that calls that module" in r.reason


def test_literal_passed_in_the_module_block_is_a_module_input(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
        root_body="""
        module "compute" {
          source        = "../../modules/compute"
          instance_type = "t3.micro"
        }
        """,
    )
    r = resolve_attribute(ADDRESS, "instance_type", root, workspace)

    assert r.layer == MODULE_INPUT
    assert r.is_workspace_local
    assert r.edit_file == "environments/dev/main.tf"
    assert r.edit_line == 3


def test_value_forwarded_to_workspace_tfvars(tmp_path: Path):
    """The canonical chain: resource -> module input -> root variable -> tfvars."""
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
    )
    r = resolve_attribute(ADDRESS, "instance_type", root, workspace)

    assert r.layer == WORKSPACE_TFVARS
    assert r.is_workspace_local
    assert r.edit_file == "environments/dev/terraform.tfvars"
    assert r.expression == '"t3.micro"'
    assert [h.kind for h in r.chain] == [
        "resource_block",
        "attribute",
        "module_input",
        "workspace_tfvars",
    ]


def test_root_variable_default_applies_when_no_tfvars_overrides_it(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
        root_variables="""
        variable "instance_type" {
          type    = string
          default = "t3.micro"
        }
        """,
        tfvars=None,
    )
    r = resolve_attribute(ADDRESS, "instance_type", root, workspace)

    assert r.layer == WORKSPACE_VARIABLE_DEFAULT
    assert r.is_workspace_local
    assert r.edit_file == "environments/dev/variables.tf"


def test_tfvars_takes_precedence_over_a_root_default(tmp_path: Path):
    """Terraform's own precedence: editing the default would not change the plan."""
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
        root_variables="""
        variable "instance_type" {
          type    = string
          default = "t3.nano"
        }
        """,
        tfvars='instance_type = "t3.micro"\n',
    )
    r = resolve_attribute(ADDRESS, "instance_type", root, workspace)

    assert r.layer == WORKSPACE_TFVARS
    assert r.edit_file == "environments/dev/terraform.tfvars"


def test_resource_in_the_root_module_resolves_against_the_workspace(tmp_path: Path):
    root = tmp_path
    write(root, "environments/dev/main.tf", """
    resource "aws_s3_bucket" "data" {
      bucket = var.bucket_name
    }
    """)
    write(root, "environments/dev/terraform.tfvars", 'bucket_name = "demo"\n')
    workspace = root / "environments" / "dev"

    r = resolve_attribute("aws_s3_bucket.data", "bucket", root, workspace)

    assert r.layer == WORKSPACE_TFVARS
    assert r.edit_file == "environments/dev/terraform.tfvars"


# --- the non-local layers, which must escalate -------------------------------------


def test_module_default_is_shared_and_not_codifiable(tmp_path: Path):
    """No caller passes the value, so the default is shared with every other caller."""
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
        module_variables="""
        variable "instance_type" {
          type    = string
          default = "t3.micro"
        }
        """,
        root_body="""
        module "compute" {
          source = "../../modules/compute"
        }
        """,
    )
    r = resolve_attribute(ADDRESS, "instance_type", root, workspace)

    assert r.layer == MODULE_VARIABLE_DEFAULT
    assert not r.is_workspace_local
    assert "every workspace that calls it" in r.reason


def test_tfvars_outside_the_workspace_is_shared(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
        tfvars=None,
    )
    write(root, "global/common.tfvars", 'instance_type = "t3.micro"\n')

    r = resolve_attribute(ADDRESS, "instance_type", root, workspace)

    assert r.layer == SHARED_TFVARS
    assert not r.is_workspace_local
    assert r.edit_file == "global/common.tfvars"


def test_variable_with_no_value_in_the_repository_is_external(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
        tfvars=None,
    )
    r = resolve_attribute(ADDRESS, "instance_type", root, workspace)

    assert r.layer == EXTERNAL_VARIABLE
    assert not r.is_workspace_local
    assert r.edit_file is None


def test_interpolated_string_has_no_single_literal_to_replace(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          name_prefix = "${var.project_name}-app-"
        }
        """,
    )
    r = resolve_attribute(ADDRESS, "name_prefix", root, workspace)

    assert r.layer == EXPRESSION
    assert not r.is_workspace_local


@pytest.mark.parametrize(
    "expression",
    ['local.instance_type', 'data.aws_ssm_parameter.t.value', 'coalesce(var.a, "t3.micro")'],
)
def test_indirect_references_are_expressions(tmp_path: Path, expression: str):
    root, workspace = repo(
        tmp_path,
        module_body=f"""
        resource "aws_launch_template" "app" {{
          instance_type = {expression}
        }}
        """,
    )
    assert resolve_attribute(ADDRESS, "instance_type", root, workspace).layer == EXPRESSION


def test_module_input_expression_is_not_traced_through(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
        root_body="""
        module "compute" {
          source        = "../../modules/compute"
          instance_type = var.environment == "prod" ? "m5.large" : "t3.micro"
        }
        """,
    )
    assert resolve_attribute(ADDRESS, "instance_type", root, workspace).layer == EXPRESSION


def test_dotted_path_into_a_nested_block_is_out_of_scope(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          tag_specifications {
            resource_type = "instance"
          }
        }
        """,
    )
    r = resolve_attribute(ADDRESS, "tag_specifications.0.resource_type", root, workspace)

    assert r.layer == NESTED_ATTRIBUTE
    assert not r.is_workspace_local


def test_attribute_absent_from_the_block_is_unknown(tmp_path: Path):
    """Drift on an attribute the code never sets is an insertion, not a replacement."""
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = "t3.micro"
        }
        """,
    )
    r = resolve_attribute(ADDRESS, "description", root, workspace)

    assert r.layer == UNKNOWN
    assert "provider default" in r.reason


def test_unlocatable_resource_is_unknown_not_an_exception(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = "t3.micro"
        }
        """,
    )
    r = resolve_attribute("module.compute.aws_launch_template.absent", "instance_type", root, workspace)

    assert r.layer == UNKNOWN


def test_assignment_inside_a_nested_block_is_not_mistaken_for_the_attribute(tmp_path: Path):
    """`resource_type` inside tag_specifications must not answer for a top-level lookup."""
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type

          tag_specifications {
            resource_type = "instance"
          }
        }
        """,
    )
    assert resolve_attribute(ADDRESS, "resource_type", root, workspace).layer == UNKNOWN


def test_heredoc_body_does_not_desynchronise_the_scan(tmp_path: Path):
    """Policy JSON in a heredoc contains braces that would unbalance a naive counter."""
    root, workspace = root_repo(
        tmp_path,
        body="""
        resource "aws_launch_template" "app" {
          user_data = <<-EOT
            { "nested": { "braces": true } }
          EOT

          instance_type = "t3.micro"
        }
        """,
    )
    r = resolve_attribute(ROOT_ADDRESS, "instance_type", root, workspace)

    assert r.layer == RESOURCE_LITERAL
    assert r.expression == '"t3.micro"'


def test_hash_inside_a_string_is_not_a_comment(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = "t3.micro" # keep small in dev
          description   = "colour #1"
        }
        """,
    )
    assert resolve_attribute(ADDRESS, "instance_type", root, workspace).expression == '"t3.micro"'
    assert resolve_attribute(ADDRESS, "description", root, workspace).expression == '"colour #1"'


def test_commented_out_assignment_is_ignored(tmp_path: Path):
    root, workspace = root_repo(
        tmp_path,
        body="""
        resource "aws_launch_template" "app" {
          # instance_type = "m5.large"
          instance_type = "t3.micro"
        }
        """,
    )
    r = resolve_attribute(ROOT_ADDRESS, "instance_type", root, workspace)

    assert r.expression == '"t3.micro"'
    assert r.edit_line == 3


# --- expression and comment primitives ---------------------------------------------


@pytest.mark.parametrize(
    "expression",
    ['"t3.micro"', "1", "-2", "1.5", "true", "false", '["a", "b"]', "[1, 2]", '"with \\" escape"'],
)
def test_literals_are_recognised(expression: str):
    assert is_literal(expression)


@pytest.mark.parametrize(
    "expression",
    [
        "var.instance_type",
        "local.x",
        '"${var.x}-app"',
        '"a" == "b"',
        '"a" + "b"',
        "[",
        "[]",
        "{",
        "",
        "[var.a]",
    ],
)
def test_non_literals_are_rejected(expression: str):
    assert not is_literal(expression)


@pytest.mark.parametrize(
    "line,expected",
    [
        ('a = "b" # c', 'a = "b" '),
        ('a = "b" // c', 'a = "b" '),
        ('a = "has # inside"', 'a = "has # inside"'),
        ('a = "has // inside"', 'a = "has // inside"'),
        ("# whole line", ""),
    ],
)
def test_strip_comment(line: str, expected: str):
    assert strip_comment(line) == expected


def test_top_level_assignments_reports_only_the_block_body():
    lines = textwrap.dedent(
        """
        resource "aws_launch_template" "app" {
          instance_type = "t3.micro"
          tag_specifications {
            resource_type = "instance"
          }
          image_id = var.ami_id
        }
        """
    ).strip().splitlines()

    found = list(top_level_assignments(lines, 0, len(lines)))

    assert [(name, expression) for _, name, expression in found] == [
        ("instance_type", '"t3.micro"'),
        ("image_id", "var.ami_id"),
    ]


# --- the reason this module exists: it unblocks the scope guard ---------------------


def entry(**overrides):
    base = {
        "address": ADDRESS,
        "type": "aws_launch_template",
        "actions": ["update"],
        "changed_attributes": ["instance_type"],
    }
    base.update(overrides)
    return base


def test_resolved_layers_let_the_scope_guard_codify(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
    )
    layers = source_layers(ADDRESS, ["instance_type"], root, workspace)

    decision = classify_resource(
        entry(), codifiable_attributes=["instance_type"], source_layers=layers, confirmed_samples=2
    )

    assert decision["verdict"] == CODIFY
    assert decision["authorized_attributes"] == ["instance_type"]


def test_a_shared_value_escalates_even_when_the_schema_allows_it(tmp_path: Path):
    root, workspace = repo(
        tmp_path,
        module_body="""
        resource "aws_launch_template" "app" {
          instance_type = var.instance_type
        }
        """,
        tfvars=None,
    )
    write(root, "global/common.tfvars", 'instance_type = "t3.micro"\n')

    layers = source_layers(ADDRESS, ["instance_type"], root, workspace)
    decision = classify_resource(
        entry(), codifiable_attributes=["instance_type"], source_layers=layers, confirmed_samples=2
    )

    assert decision["verdict"] == ESCALATE
    assert decision["rejected_attributes"][0]["source_layer"] == "shared_tfvars"


def test_absent_resolution_escalates_rather_than_editing_blindly(tmp_path: Path):
    """With no source-layer evidence there is no known location, so nothing is codified."""
    decision = classify_resource(
        entry(), codifiable_attributes=["instance_type"], source_layers={}, confirmed_samples=2
    )

    assert decision["verdict"] == ESCALATE
