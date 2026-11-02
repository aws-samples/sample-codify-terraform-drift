"""The whole deterministic chain, on more than one resource at a time.

Every other integration-shaped test drives one resource with one attribute through the
chain. That leaves the interesting case untested: two resources drifting in the same run,
whose edits land in different source layers and different files, verified together against
one authorization. Aggregation is exercised at unit level in ``classify_all`` and
``sign_all``; this file drives it end to end.

The diffs here are generated with :mod:`difflib` from files that are actually edited, not
written out by hand, so the unified-diff text the verifier parses is produced the same way
a real tool produces it - including hunk headers and context lines this suite would
otherwise never see.
"""

from __future__ import annotations

import difflib
import json
import textwrap
from pathlib import Path

from driftcode.authorize import authorize
from driftcode.ledger import Ledger, MemoryStore
from driftcode.prompt import render_task
from driftcode.sign import sign_all
from driftcode.verify import ACCEPT, REJECT, verify

LAUNCH_TEMPLATE = "module.compute.aws_launch_template.app"
BUCKET = "aws_s3_bucket.data"

WORKSPACE_ID = "dev"
REPO = "acme/infra"


def write(root: Path, relative: str, body: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


def two_resource_repo(tmp_path: Path) -> tuple[Path, Path]:
    """Two drifting resources whose values come from different source layers.

    ``instance_type`` is declared inside a reusable module and traces through a module input
    to the workspace's tfvars; ``versioning_status`` is a literal in a resource declared in
    the workspace's own root module. So the two work orders exercise different layers,
    different files, and different edit shapes in one run.

    The bucket is deliberately in the root module rather than a reusable one: a literal
    inside a reusable module is shared by every caller of that module, so it escalates
    rather than being edited, and would not produce a work order at all.
    """
    write(tmp_path, "modules/compute/main.tf", """
    resource "aws_launch_template" "app" {
      instance_type = var.instance_type
    }
    """)
    write(tmp_path, "modules/compute/variables.tf", 'variable "instance_type" {\n  type = string\n}\n')

    write(tmp_path, "environments/dev/main.tf", """
    module "compute" {
      source        = "../../modules/compute"
      instance_type = var.instance_type
    }

    resource "aws_s3_bucket" "data" {
      bucket            = var.bucket_name
      versioning_status = "Suspended"
    }
    """)
    write(tmp_path, "environments/dev/variables.tf", """
    variable "instance_type" {
      type = string
    }

    variable "bucket_name" {
      type = string
    }
    """)
    write(tmp_path, "environments/dev/terraform.tfvars", """
    instance_type = "t3.micro"
    bucket_name   = "demo-data"
    """)

    return tmp_path, tmp_path / "environments" / "dev"


def reconciled() -> dict:
    return {
        "real_drift": [
            {
                "address": LAUNCH_TEMPLATE,
                "type": "aws_launch_template",
                "actions": ["update"],
                "changed_attributes": ["instance_type"],
            },
            {
                "address": BUCKET,
                "type": "aws_s3_bucket",
                "actions": ["update"],
                "changed_attributes": ["versioning_status"],
            },
        ]
    }


def gate_a() -> dict:
    return {
        "attribute_classification": [
            {"address": LAUNCH_TEMPLATE, "codifiable": ["instance_type"]},
            {"address": BUCKET, "codifiable": ["versioning_status"]},
        ]
    }


def refresh_only_plan() -> dict:
    return {
        "resource_drift": [
            {
                "address": LAUNCH_TEMPLATE,
                "type": "aws_launch_template",
                "mode": "managed",
                "change": {
                    "actions": ["update"],
                    # Sibling attributes and an account identifier, so the allowlist
                    # property is exercised on a realistic payload rather than a clean one.
                    "before": {"instance_type": "t3.micro", "arn": "arn:aws:ec2:us-east-1:123456789012:lt/lt-1"},
                    "after": {
                        "instance_type": "t2.micro",
                        "arn": "arn:aws:ec2:us-east-1:123456789012:lt/lt-1",
                        "tags": {"Owner": "sre@example.com"},
                    },
                },
            },
            {
                "address": BUCKET,
                "type": "aws_s3_bucket",
                "mode": "managed",
                "change": {
                    "actions": ["update"],
                    "before": {"versioning_status": "Suspended"},
                    "after": {"versioning_status": "Enabled"},
                },
            },
        ]
    }


def apply_edits(root: Path, orders: list[dict]) -> str:
    """Make each authorized edit for real, and return the unified diff of the result."""
    patches: list[str] = []

    for order in orders:
        targets = {
            a["path"]: a["observed_value_in_cloud"] for a in order["drift"]["attributes"]
        }
        for edit in order["edit_sites"]:
            path = root / edit["file"]
            before = path.read_text(encoding="utf-8").splitlines(keepends=True)
            after = list(before)

            index = edit["line"] - 1
            name = edit["assigned_name"]
            value = targets[edit["attribute"]]
            rendered = json.dumps(value) if isinstance(value, str) else str(value)

            original = after[index]
            indent = original[: len(original) - len(original.lstrip())]
            after[index] = f"{indent}{name} = {rendered}\n"
            path.write_text("".join(after), encoding="utf-8")

            patches.append(
                "".join(
                    difflib.unified_diff(
                        before,
                        after,
                        fromfile=f"a/{edit['file']}",
                        tofile=f"b/{edit['file']}",
                    )
                )
            )

    # difflib emits no `diff --git` line; the verifier reads the +++ header, so prepend one
    # per file the way git does.
    out = []
    for patch in patches:
        first = patch.splitlines()[1]
        relative = first.removeprefix("+++ b/")
        out.append(f"diff --git a/{relative} b/{relative}\n{patch}")
    return "".join(out)


def run_chain(tmp_path: Path, build_number: int, book: Ledger) -> tuple[dict, dict]:
    root, workspace = two_resource_repo(tmp_path)
    plan = refresh_only_plan()
    signatures = sign_all(reconciled(), plan, WORKSPACE_ID, REPO)
    observations = book.observe(signatures, build_number=build_number)

    result = authorize(
        reconciled(),
        gate_a(),
        plan,
        root,
        workspace,
        sample_counts=book.counts(observations),
        observations=observations,
        signatures=signatures,
    )
    return result, observations


# --- the chain, on two resources ----------------------------------------------------


def test_two_resources_produce_two_bounded_work_orders(tmp_path: Path):
    book = Ledger(MemoryStore())
    run_chain(tmp_path, 1, book)  # first sighting: suppressed
    result, _ = run_chain(tmp_path, 2, book)

    assert result["counts"] == {"work_orders": 2, "escalate": 0, "suppress": 0}

    by_address = {o["resource_address"]: o for o in result["work_orders"]}
    assert set(by_address) == {LAUNCH_TEMPLATE, BUCKET}

    # Different source layers, resolved independently, landing in different files.
    compute = by_address[LAUNCH_TEMPLATE]["edit_sites"][0]
    storage = by_address[BUCKET]["edit_sites"][0]

    assert (compute["layer"], compute["file"]) == (
        "workspace_tfvars",
        "environments/dev/terraform.tfvars",
    )
    assert (storage["layer"], storage["file"]) == ("resource_literal", "environments/dev/main.tf")


def test_each_work_order_gets_its_own_signature_and_branch(tmp_path: Path):
    book = Ledger(MemoryStore())
    run_chain(tmp_path, 1, book)
    result, _ = run_chain(tmp_path, 2, book)

    signatures = {o["signature"] for o in result["work_orders"]}
    branches = {o["branch"] for o in result["work_orders"]}

    assert len(signatures) == 2, "one resource's resolution must not close another's PR"
    assert len(branches) == 2
    assert all(len(s) == 64 for s in signatures)


def test_both_resources_are_debounced_independently_but_together(tmp_path: Path):
    book = Ledger(MemoryStore())
    first, observations = run_chain(tmp_path, 1, book)

    assert first["counts"]["suppress"] == 2
    assert all(o["confirmed"] is False for o in observations.values())

    second, observations = run_chain(tmp_path, 2, book)

    assert second["counts"]["work_orders"] == 2
    assert all(o["confirmed"] is True for o in observations.values())


def test_each_work_order_renders_its_own_bounded_prompt(tmp_path: Path):
    book = Ledger(MemoryStore())
    run_chain(tmp_path, 1, book)
    result, _ = run_chain(tmp_path, 2, book)

    prompts = {o["resource_address"]: render_task(o) for o in result["work_orders"]}

    # One work order per prompt: neither task mentions the other resource.
    assert BUCKET not in prompts[LAUNCH_TEMPLATE]
    assert LAUNCH_TEMPLATE not in prompts[BUCKET]

    # And the allowlist holds on a payload that carried an ARN and a tag.
    for prompt in prompts.values():
        assert "123456789012" not in prompt
        assert "sre@example.com" not in prompt


def test_both_edits_applied_together_verify_as_accepted(tmp_path: Path):
    """The success case for simultaneous edits: two files, two layers, one verdict."""
    book = Ledger(MemoryStore())
    run_chain(tmp_path, 1, book)
    result, _ = run_chain(tmp_path, 2, book)
    root = tmp_path

    diff = apply_edits(root, result["work_orders"])
    verification = verify(diff, result)

    assert verification["verdict"] == ACCEPT, verification["violations"]
    assert verification["counts"]["verified_edits"] == 2
    assert set(verification["files_changed"]) == {
        "environments/dev/terraform.tfvars",
        "environments/dev/main.tf",
    }
    assert {e["resource_address"] for e in verification["verified_edits"]} == {
        LAUNCH_TEMPLATE,
        BUCKET,
    }


def test_the_edits_actually_land_in_the_files(tmp_path: Path):
    """Not just a verdict: the files on disk say what the cloud says."""
    book = Ledger(MemoryStore())
    run_chain(tmp_path, 1, book)
    result, _ = run_chain(tmp_path, 2, book)

    apply_edits(tmp_path, result["work_orders"])

    tfvars = (tmp_path / "environments/dev/terraform.tfvars").read_text(encoding="utf-8")
    storage = (tmp_path / "environments/dev/main.tf").read_text(encoding="utf-8")

    assert 't2.micro' in tfvars and 't3.micro' not in tfvars
    assert '"Enabled"' in storage and '"Suspended"' not in storage
    # The sibling variable was not touched.
    assert 'bucket_name   = "demo-data"' in tfvars


def test_doing_only_one_of_the_two_edits_is_rejected(tmp_path: Path):
    book = Ledger(MemoryStore())
    run_chain(tmp_path, 1, book)
    result, _ = run_chain(tmp_path, 2, book)

    partial = [o for o in result["work_orders"] if o["resource_address"] == LAUNCH_TEMPLATE]
    diff = apply_edits(tmp_path, partial)

    verification = verify(diff, result)

    assert verification["verdict"] == REJECT
    assert [v["kind"] for v in verification["violations"]] == ["unmade_edit"]
    assert verification["violations"][0]["file"] == "environments/dev/main.tf"


def test_a_third_file_touched_alongside_correct_edits_is_rejected(tmp_path: Path):
    book = Ledger(MemoryStore())
    run_chain(tmp_path, 1, book)
    result, _ = run_chain(tmp_path, 2, book)

    diff = apply_edits(tmp_path, result["work_orders"])
    diff += textwrap.dedent(
        """\
        diff --git a/modules/compute/main.tf b/modules/compute/main.tf
        --- a/modules/compute/main.tf
        +++ b/modules/compute/main.tf
        @@ -2,1 +2,1 @@
        -  instance_type = var.instance_type
        +  instance_type = "m5.24xlarge"
        """
    )

    verification = verify(diff, result)

    assert verification["verdict"] == REJECT
    assert any(v["kind"] == "unauthorized_file" for v in verification["violations"])


def test_every_decision_in_the_run_carries_a_code(tmp_path: Path):
    """So a caller can route on the outcome without parsing prose."""
    book = Ledger(MemoryStore())
    first, _ = run_chain(tmp_path, 1, book)

    assert [d["code"] for d in first["suppress"]] == ["unconfirmed_observation"] * 2

    result, _ = run_chain(tmp_path, 2, book)
    assert all(o["verdict"] == "codify" for o in result["work_orders"])
