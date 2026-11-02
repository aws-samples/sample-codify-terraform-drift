# Detection role.
#
# Read over the managed surface, read on the state object, read and write on the lock table,
# and an explicit Deny on writing state. The model holds no AWS credentials at all: it
# receives a sanitized drift record and the contents of the files its work order names, so a
# compromised or prompt-injected model cannot describe infrastructure, read state, or call
# any AWS API. The codify and gates roles are defined in codify.tf and gates.tf.
#
# Read-only means one specific thing here: the role may read the target estate's state
# object but may never write it. That is enforced by an explicit Deny, which cannot be
# overridden by any Allow. A command allowlist in the buildspec is defence in depth, but
# a build script cannot bind a principal - IAM can.

data "aws_caller_identity" "current" {}

# --- trust policy -----------------------------------------------------------

data "aws_iam_policy_document" "codebuild_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    # Confused-deputy guards: this role is assumable only on behalf of this account,
    # and only by this project.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:codebuild:${var.aws_region}:${data.aws_caller_identity.current.account_id}:project/${var.name_prefix}-detect"]
    }
  }
}

resource "aws_iam_role" "detection" {
  name        = "${var.name_prefix}-detection"
  description = "Read-only drift detection. Reads the managed surface and state; cannot write state."

  assume_role_policy = data.aws_iam_policy_document.codebuild_assume.json
}

# --- read over the managed surface ------------------------------------------

resource "aws_iam_role_policy_attachment" "managed_surface_read" {
  for_each = toset(var.managed_surface_read_policy_arns)

  role       = aws_iam_role.detection.name
  policy_arn = each.value
}

# --- state access: read the object, never write it --------------------------

data "aws_iam_policy_document" "state_access" {
  # Terraform reads the state object itself.
  statement {
    sid       = "ReadStateObject"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}"]
  }

  # Terraform lists the prefix to resolve the object and any workspace variants.
  statement {
    sid       = "ListStatePrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.target_state_bucket}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = [dirname(var.target_state_key) == "." ? "*" : "${dirname(var.target_state_key)}/*"]
    }
  }

  # THE read-only guarantee. An explicit Deny cannot be overridden by any Allow,
  # including a broad managed policy attached above. If a mutating terraform
  # subcommand were ever invoked, it would fail here rather than persist state.
  #
  # The resource list is enumerated rather than wildcarded, and that is load-bearing.
  # A blanket "${key}.*" also matches "${key}.tflock", which is the object Terraform
  # conditionally PUTs when the backend uses S3 native locking (`use_lockfile`, the
  # replacement for the deprecated `dynamodb_table`). Denying it would make the LOCK
  # unacquirable, so every locked detection run would fail - the same mistake as denying
  # the lock table's PutItem, one storage layer over. State objects are denied; the lock
  # object is not a state object.
  statement {
    sid    = "DenyStateMutation"
    effect = "Deny"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:AbortMultipartUpload",
    ]

    resources = [
      "arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}",
      "arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}.backup",
      "arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}.tfstate",
      # Workspace-suffixed state objects for the same key prefix.
      "arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}.d/*",
    ]
  }

  # Acquiring a lock is a WRITE, whichever backend holds it. With `use_lockfile` the lock
  # is a conditional PUT of "${key}.tflock" in the state bucket; with `dynamodb_table` it
  # is a PutItem. Both are granted, and neither weakens the guarantee above: a lock object
  # is not a state object, and the state objects themselves stay explicitly denied.
  statement {
    sid    = "AcquireAndReleaseStateLockObject"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
    ]

    resources = ["arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}.tflock"]
  }

  # Locking requires WRITES to the lock table: acquiring a lock puts an item and
  # releasing it deletes one. Denying these would break the locked read that
  # detection depends on. Scoped to the lock table only.
  statement {
    sid    = "AcquireAndReleaseStateLock"
    effect = "Allow"

    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
      "dynamodb:DescribeTable",
    ]

    resources = ["arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.target_lock_table}"]
  }
}

resource "aws_iam_role_policy" "state_access" {
  name   = "${var.name_prefix}-state-access"
  role   = aws_iam_role.detection.id
  policy = data.aws_iam_policy_document.state_access.json
}

# --- guardrails that hold regardless of how broad the read grant is ---------

data "aws_iam_policy_document" "read_guardrails" {
  # A refresh needs resource metadata, not secret material. Broad managed read-only
  # policies grant more than that, so the excess is denied - except the pipeline's own
  # credential, which CodeBuild must read.
  #
  # Deliberately scoped to secret *values*. kms:Decrypt is NOT denied here: CodeBuild
  # needs it to decrypt this secret and to write SSE-KMS artifacts, and a Deny with a
  # NotResource covering every key would be dead policy - denying nothing while looking
  # like a control.
  statement {
    sid    = "DenyForeignSecretReads"
    effect = "Deny"

    actions = [
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]

    not_resources = [aws_secretsmanager_secret.git_credential.arn]
  }

  # Detection must never mutate the estate it inspects, whatever else it is granted.
  #
  # Only mutating actions appear here. Denying `iam:*` instead would block iam:GetRole and
  # iam:ListRolePolicies - the reads the provider needs to refresh a managed IAM role. That
  # surfaces as an authorization failure, Gate A fails the run closed, and detection never
  # completes. Denying reads to prevent writes breaks the thing being protected.
  statement {
    sid    = "DenyEstateMutation"
    effect = "Deny"

    actions = [
      "ec2:RunInstances",
      "ec2:TerminateInstances",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:CreateLaunchTemplate",
      "ec2:CreateLaunchTemplateVersion",
      "ec2:ModifyLaunchTemplate",
      "ec2:DeleteLaunchTemplate",
      "autoscaling:UpdateAutoScalingGroup",
      "autoscaling:SetDesiredCapacity",
      "autoscaling:CreateAutoScalingGroup",
      "autoscaling:DeleteAutoScalingGroup",
      "iam:Create*",
      "iam:Delete*",
      "iam:Update*",
      "iam:Put*",
      "iam:Attach*",
      "iam:Detach*",
      "iam:Tag*",
      "iam:Untag*",
      "s3:PutBucketPolicy",
      "s3:PutBucketAcl",
      "s3:PutBucketVersioning",
      "s3:DeleteBucket",
      "dynamodb:UpdateTable",
      "dynamodb:DeleteTable",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "read_guardrails" {
  name   = "${var.name_prefix}-read-guardrails"
  role   = aws_iam_role.detection.id
  policy = data.aws_iam_policy_document.read_guardrails.json
}

# --- cross-account read -----------------------------------------------------

data "aws_iam_policy_document" "cross_account_read" {
  count = length(var.cross_account_read_role_arns) > 0 ? 1 : 0

  statement {
    sid       = "AssumeCrossAccountReadRoles"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = var.cross_account_read_role_arns
  }
}

resource "aws_iam_role_policy" "cross_account_read" {
  count = length(var.cross_account_read_role_arns) > 0 ? 1 : 0

  name   = "${var.name_prefix}-cross-account-read"
  role   = aws_iam_role.detection.id
  policy = data.aws_iam_policy_document.cross_account_read[0].json
}

# --- what CodeBuild itself needs -------------------------------------------

data "aws_iam_policy_document" "codebuild_runtime" {
  statement {
    sid    = "Logs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.detect.arn}:*"]
  }

  statement {
    sid       = "ReadGitCredential"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.git_credential.arn]
  }

  statement {
    sid    = "PublishArtifacts"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:GetBucketLocation",
    ]

    # Scoped to the artifact bucket. Note this does not weaken the state Deny above,
    # which is a different bucket and an explicit Deny regardless.
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  # The observation ledger. Read and write on its own table only: this is the pipeline's
  # own bookkeeping, unrelated to the target's Terraform state lock table, which is
  # granted separately and scoped to that table.
  statement {
    sid    = "RecordObservations"
    effect = "Allow"

    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
    ]

    resources = [aws_dynamodb_table.ledger.arn]
  }

  # CodeBuild downloads an S3 source using this role, so without this the project cannot
  # fetch its own code. Scoped to the one payload object rather than the bucket: the same
  # bucket will hold the agent runtime's payload, and the detection worker has no business
  # reading that.
  dynamic "statement" {
    for_each = var.package_source ? [1] : []

    content {
      sid    = "FetchOwnSource"
      effect = "Allow"

      actions = [
        "s3:GetObject",
        "s3:GetObjectVersion",
      ]

      resources = [module.detection_source[0].object_arn]
    }
  }

  # Listing the bucket is required for CodeBuild to resolve the object, and is harmless:
  # it reveals key names, not contents, and the read grant above is per-object.
  dynamic "statement" {
    for_each = var.package_source ? [1] : []

    content {
      sid       = "ResolveOwnSource"
      effect    = "Allow"
      actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
      resources = [aws_s3_bucket.source[0].arn]
    }
  }
}

resource "aws_iam_role_policy" "codebuild_runtime" {
  name   = "${var.name_prefix}-codebuild-runtime"
  role   = aws_iam_role.detection.id
  policy = data.aws_iam_policy_document.codebuild_runtime.json
}
