# Gate stage: scans the codified branch, holding no write credential.
#
# This is the third of three differently-privileged workers, and the split is the whole point:
#
#   detection  state read + estate read, no write credential
#   codify     model + write credential, NO state access
#   gates      state read + estate read, NO write credential   <- this
#   finalize   write credential, no state (a second codify invocation)
#
# Gate B is a `terraform plan` against the branch, so it needs state and a provider read. Codify
# holds a repository write credential and is therefore denied both. Rather than widen codify -
# which would produce one principal that can read every resource in the estate AND write to the
# repository - the scan runs here and its verdict is applied by a separate step.
#
# The role is modelled on detection's, including the explicit Deny on state writes: this stage
# reads state to plan, and must no more be able to persist it than detection can.

resource "aws_cloudwatch_log_group" "gates" {
  count             = var.enable_codify ? 1 : 0
  name              = "/aws/codebuild/${var.name_prefix}-gates"
  retention_in_days = var.log_retention_days
}

module "gates_source" {
  count  = var.enable_codify && var.package_source ? 1 : 0
  source = "./modules/source-package"

  name       = "gates"
  bucket     = aws_s3_bucket.source[0].id
  source_dir = local.implementation_root
  commit     = var.source_commit
  key_prefix = "payloads"
  excludes   = local.payload_excludes

  tags = { Payload = "gates" }
}

data "aws_iam_policy_document" "gates_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    # Pinned to this project, like every other role here. A trust document shared with another
    # project refuses this project's assume-role, because its aws:SourceArn guard names a
    # different project - and the answer is a document scoped to this project, not a wildcard
    # that would let any CodeBuild project in the account assume it.
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:codebuild:${var.aws_region}:${data.aws_caller_identity.current.account_id}:project/${var.name_prefix}-gates"]
    }
  }
}

resource "aws_iam_role" "gates" {
  count              = var.enable_codify ? 1 : 0
  name               = "${var.name_prefix}-gates"
  assume_role_policy = data.aws_iam_policy_document.gates_assume.json

  description = "Gate stage: plans and scans the codified branch. Reads Terraform state and the estate; holds no repository write credential."
}

# The estate read this stage needs to run a plan. Same grant detection gets, and for the same
# reason: a plan refreshes against the provider.
resource "aws_iam_role_policy_attachment" "gates_managed_surface_read" {
  for_each = var.enable_codify ? toset(var.managed_surface_read_policy_arns) : toset([])

  role       = aws_iam_role.gates[0].name
  policy_arn = each.value
}

data "aws_iam_policy_document" "gates_runtime" {
  statement {
    sid     = "Logs"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]

    resources = [for arn in aws_cloudwatch_log_group.gates[*].arn : "${arn}:*"]
  }

  # Read the state object to plan, and the lock table to plan safely.
  statement {
    sid       = "ReadStateObject"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}"]
  }

  statement {
    sid       = "ListStatePrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.target_state_bucket}"]
  }

  # Acquiring a lock is a write, whichever backend holds it. Granted for both, and neither
  # weakens the Deny below: a lock object is not a state object.
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

  statement {
    sid       = "AcquireAndReleaseStateLockObject"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}.tflock"]
  }

  # The clone credential. Read-only use here: this stage never pushes. That is not enforceable
  # through IAM - the token itself carries whatever scope it was issued with - which is why the
  # credential should be a read-only one and the write path should hold a separate token.
  statement {
    sid       = "ReadGitCredential"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.git_credential.arn]
  }

  statement {
    sid       = "DecryptTheCredential"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "PublishArtifacts"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetBucketLocation"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*", aws_s3_bucket.artifacts.arn]
  }

  dynamic "statement" {
    for_each = var.package_source && var.enable_codify ? [1] : []

    content {
      sid       = "FetchOwnSource"
      effect    = "Allow"
      actions   = ["s3:GetObject", "s3:GetObjectVersion"]
      resources = [module.gates_source[0].object_arn]
    }
  }

  dynamic "statement" {
    for_each = var.package_source && var.enable_codify ? [1] : []

    content {
      sid       = "ResolveOwnSource"
      effect    = "Allow"
      actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
      resources = [aws_s3_bucket.source[0].arn]
    }
  }
}

# The same read-only guarantee detection carries. This stage plans, and a plan must never
# persist state - so the deny is explicit rather than implied by the absence of a grant.
data "aws_iam_policy_document" "gates_guardrails" {
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

    # Enumerated, not wildcarded: a blanket "${key}.*" would also match "${key}.tflock" and make
    # the lock unacquirable, which is the same mistake one storage layer over.
    resources = [
      "arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}",
      "arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}.backup",
      "arn:aws:s3:::${var.target_state_bucket}/${var.target_state_key}.d/*",
    ]
  }

  # No model invocation. This stage scans; it has no reason to reach Bedrock, and denying it
  # explicitly means a future copy-paste of the codify policy cannot quietly grant it.
  statement {
    sid       = "DenyModelInvocation"
    effect    = "Deny"
    actions   = ["bedrock:*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "gates_runtime" {
  count  = var.enable_codify ? 1 : 0
  name   = "${var.name_prefix}-gates-runtime"
  role   = aws_iam_role.gates[0].id
  policy = data.aws_iam_policy_document.gates_runtime.json
}

resource "aws_iam_role_policy" "gates_guardrails" {
  count  = var.enable_codify ? 1 : 0
  name   = "${var.name_prefix}-gates-guardrails"
  role   = aws_iam_role.gates[0].id
  policy = data.aws_iam_policy_document.gates_guardrails.json
}

resource "aws_codebuild_project" "gates" {
  count = var.enable_codify ? 1 : 0

  name          = "${var.name_prefix}-gates"
  description   = "Scans the codified branch against its parent. Holds state and estate read, and no repository write credential."
  service_role  = aws_iam_role.gates[0].arn
  build_timeout = var.build_timeout_minutes

  artifacts {
    type      = "S3"
    location  = aws_s3_bucket.artifacts.bucket
    packaging = "ZIP"
  }

  environment {
    type         = "LINUX_CONTAINER"
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"

    environment_variable {
      name  = "TARGET_REPO_URL"
      value = var.target_repo_url
    }

    environment_variable {
      name  = "TF_WORKING_DIR"
      value = var.target_working_dir
    }

    environment_variable {
      name  = "GIT_CREDENTIAL_SECRET_ID"
      value = aws_secretsmanager_secret.git_credential.name
    }

    # Set per invocation by whatever starts this build. Not defaulted: scanning an unspecified
    # branch would mean reporting a verdict about something nobody asked about.
    environment_variable {
      name  = "DRIFT_BRANCH"
      value = "SET_PER_BUILD"
    }
  }

  source {
    type      = local.effective_gates_source_type
    location  = local.effective_gates_source_location
    buildspec = "buildspec-gates.yml"

    git_clone_depth = local.effective_gates_source_type == "S3" ? null : 1
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.gates[0].name
    }
  }
}

locals {
  effective_gates_source_type = var.package_source ? "S3" : var.source_type
  gates_packaged_location     = one(module.gates_source[*].s3_location)

  effective_gates_source_location = (
    local.gates_packaged_location != null
    ? local.gates_packaged_location
    : var.source_location
  )
}
