"""Edit-target resolution tests.

Ambiguity and absence must both fail loudly. A wrong file is worse than no edit, so
guessing is never acceptable — that is the property these tests defend.
"""

from __future__ import annotations

import pytest

from driftcode.locate import LocateError, locate, parse_address

LAUNCH_TEMPLATE = '''
# Compute module
resource "aws_launch_template" "app" {
  name_prefix   = "${var.project_name}-app-"
  instance_type = var.instance_type

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "app"
    }
  }
}

resource "aws_autoscaling_group" "app" {
  desired_capacity = var.desired_capacity
}
'''

WITH_HEREDOC = '''
resource "aws_iam_role_policy" "app" {
  policy = <<-EOT
    {
      "Statement": [{ "Effect": "Allow" }]
    }
  EOT
}

resource "aws_s3_bucket" "data" {
  bucket = "x"
}
'''


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "modules" / "compute").mkdir(parents=True)
    (tmp_path / "modules" / "compute" / "main.tf").write_text(LAUNCH_TEMPLATE)
    (tmp_path / "modules" / "iam").mkdir(parents=True)
    (tmp_path / "modules" / "iam" / "main.tf").write_text(WITH_HEREDOC)
    (tmp_path / "environments" / "dev").mkdir(parents=True)
    (tmp_path / "environments" / "dev" / "main.tf").write_text('module "compute" {\n  source = "../../modules/compute"\n}\n')
    return tmp_path


# --- address parsing -------------------------------------------------------

def test_parses_module_type_and_name():
    assert parse_address("module.compute.aws_launch_template.app") == (
        ["compute"], "aws_launch_template", "app")


def test_strips_instance_index():
    """An indexed address appears nowhere in source; the block must still be found."""
    modules, rtype, name = parse_address('module.compute.aws_launch_template.app["us-west-2"]')
    assert (modules, rtype, name) == (["compute"], "aws_launch_template", "app")


def test_parses_nested_modules():
    assert parse_address("module.a.module.b.aws_s3_bucket.x") == (["a", "b"], "aws_s3_bucket", "x")


def test_parses_root_module_resource():
    assert parse_address("aws_s3_bucket.x") == ([], "aws_s3_bucket", "x")


def test_rejects_unparseable_address():
    with pytest.raises(LocateError, match="unparseable"):
        parse_address("not an address at all!")


# --- locating --------------------------------------------------------------

def test_locates_block_and_its_extent(repo):
    t = locate("module.compute.aws_launch_template.app", repo)
    assert t.file == "modules/compute/main.tf"
    assert t.resource_type == "aws_launch_template" and t.resource_name == "app"
    # Block spans from its header to the closing brace, past the nested block.
    assert t.block_start_line == 3
    assert t.block_end_line == 13


def test_indexed_address_locates_the_shared_block(repo):
    t = locate('module.compute.aws_launch_template.app[0]', repo)
    assert t.file == "modules/compute/main.tf"


def test_second_resource_in_same_file_is_distinguished(repo):
    t = locate("module.compute.aws_autoscaling_group.app", repo)
    assert t.block_start_line == 15


def test_heredoc_braces_do_not_break_extent(repo):
    """Policy JSON inside a heredoc would otherwise unbalance brace counting."""
    t = locate("module.iam.aws_iam_role_policy.app", repo)
    assert t.file == "modules/iam/main.tf"
    following = locate("module.iam.aws_s3_bucket.data", repo)
    assert following.block_start_line > t.block_end_line


def test_missing_resource_fails_rather_than_guessing(repo):
    with pytest.raises(LocateError, match="rather than guessing"):
        locate("module.compute.aws_instance.absent", repo)


def test_ambiguous_resource_fails_with_both_locations(repo):
    (repo / "modules" / "compute" / "duplicate.tf").write_text(
        'resource "aws_launch_template" "app" {\n  instance_type = "t3.micro"\n}\n'
    )
    with pytest.raises(LocateError) as exc:
        locate("module.compute.aws_launch_template.app", repo)
    assert "ambiguous" in str(exc.value)
    assert "main.tf" in str(exc.value) and "duplicate.tf" in str(exc.value)


def test_bad_repo_root_is_reported(tmp_path):
    with pytest.raises(LocateError, match="not a directory"):
        locate("aws_s3_bucket.x", tmp_path / "nope")


def test_unterminated_block_is_reported(tmp_path):
    (tmp_path / "broken.tf").write_text('resource "aws_s3_bucket" "x" {\n  bucket = "y"\n')
    with pytest.raises(LocateError, match="unterminated"):
        locate("aws_s3_bucket.x", tmp_path)


def test_terraform_cache_is_skipped(tmp_path):
    """Vendored modules under .terraform/ must not shadow real source."""
    (tmp_path / ".terraform" / "modules" / "x").mkdir(parents=True)
    (tmp_path / ".terraform" / "modules" / "x" / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n  bucket = "vendored"\n}\n'
    )
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "data" {\n  bucket = "real"\n}\n')
    assert locate("aws_s3_bucket.data", tmp_path).file == "main.tf"
