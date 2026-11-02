"""Minimal plan fixtures reproducing the drift-shapes observed on a real stack.

These are hand-written rather than captured. Real ``terraform show -json`` output is
large and carries account identifiers (account ID, IAM role unique IDs, caller
session alias), so it is not committed here — see ``test/fixtures/README.md`` for how
to capture it locally.

What matters for the reconciliation logic is not the volume of a real plan but the
*shapes*, and these reproduce them exactly as observed:

  - one genuinely drifted resource whose attribute set ALSO contains normalization
    noise (``null -> []``, ``null -> {}``) alongside the real changes
  - three resources that appear in the refresh-only plan only, reported purely
    because of provider representation normalization:
      * ``null -> []`` on unset collection attributes
      * a deprecated in-line attribute populated from its standalone resource
  - every entry carrying ``actions: ["update"]``, which is why an action gate cannot
    separate them

On the demo stack refresh-only reports 4 changed resources; the full plan reports 1.
"""

from __future__ import annotations

from typing import Any

REAL = "module.compute.aws_launch_template.app"
PHANTOM_ASG = "module.compute.aws_autoscaling_group.app"
PHANTOM_ROLE = "module.iam.aws_iam_role.app_role"
PHANTOM_BUCKET = "module.storage.aws_s3_bucket.data_bucket"

PHANTOMS = {PHANTOM_ASG, PHANTOM_ROLE, PHANTOM_BUCKET}


def _entry(address: str, type_: str, name: str, module: str, before: dict, after: dict) -> dict[str, Any]:
    return {
        "address": address,
        "module_address": module,
        "mode": "managed",
        "type": type_,
        "name": name,
        "change": {"actions": ["update"], "before": before, "after": after},
    }


def refresh_only_plan() -> dict[str, Any]:
    """A locked ``plan -refresh-only``: state -> live."""
    return {
        "format_version": "1.2",
        "resource_drift": [
            # Real drift. Note instance_type and description genuinely changed, while
            # tags and security_group_names are null -> empty normalization.
            _entry(
                REAL, "aws_launch_template", "app", "module.compute",
                before={
                    "instance_type": "t3.micro",
                    "description": "",
                    "latest_version": 1,
                    "default_version": 1,
                    "tags": None,
                    "security_group_names": None,
                },
                after={
                    "instance_type": "t2.micro",
                    "description": "SRE incident hotfix simulation",
                    "latest_version": 2,
                    "default_version": 2,
                    "tags": {},
                    "security_group_names": [],
                },
            ),
            # Phantom: unset collections normalize from null to empty list.
            _entry(
                PHANTOM_ASG, "aws_autoscaling_group", "app", "module.compute",
                before={"enabled_metrics": None, "suspended_processes": None, "termination_policies": None},
                after={"enabled_metrics": [], "suspended_processes": [], "termination_policies": []},
            ),
            # Phantom: deprecated in-line attribute populated from the standalone
            # aws_iam_role_policy resource that Terraform itself created.
            _entry(
                PHANTOM_ROLE, "aws_iam_role", "app_role", "module.iam",
                before={"inline_policy": []},
                after={"inline_policy": [{"name": "app-logging-policy", "policy": "{...}"}]},
            ),
            # Phantom: deprecated in-line attribute fed by aws_s3_bucket_versioning.
            _entry(
                PHANTOM_BUCKET, "aws_s3_bucket", "data_bucket", "module.storage",
                before={"versioning": [{"enabled": False, "mfa_delete": False}]},
                after={"versioning": [{"enabled": True, "mfa_delete": False}]},
            ),
        ],
    }


def full_plan() -> dict[str, Any]:
    """A full ``terraform plan``: live -> config (the proposed revert).

    Only the genuinely drifted resource appears. Directions are the inverse of the
    refresh-only plan, which is why attribute reconciliation must intersect on
    *path* and not on value.
    """
    return {
        "format_version": "1.2",
        "resource_changes": [
            _entry(
                REAL, "aws_launch_template", "app", "module.compute",
                before={
                    "instance_type": "t2.micro",
                    "description": "SRE incident hotfix simulation",
                    "latest_version": 2,
                },
                after={
                    "instance_type": "t3.micro",
                    "description": None,
                    "latest_version": None,
                },
            ),
        ],
    }
