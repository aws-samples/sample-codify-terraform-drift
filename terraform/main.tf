# Detection stage infrastructure: the CodeBuild worker that produces both plans and
# reconciles them, its log group, its artifact store, the credential container, and the
# schedule that triggers it.
#
# The stage is gated by enable_codify and enable_orchestration so detection can be deployed
# and verified on its own before anything sequences it. The codify and gates stages are in
# codify.tf and gates.tf; the state machine and alert topic are in stepfunctions.tf.

# --- source packaging ------------------------------------------------------
#
# CodeBuild needs this repository on disk: the build installs the driftcode package and runs
# its entry points. Rather than require the implementation to be pushed to a git remote
# before the pattern can be deployed at all, Terraform packages what it has and uploads it,
# and CodeBuild takes an S3 source.
#
# The bucket is shared and owned here, not by the packaging module, so that a second payload
# is a second object in the same bucket. Two modules each creating their own bucket would
# mean a lifecycle policy set for one silently applying to neither.
#
# There is no lifecycle rule expiring objects here, unlike the artifacts bucket. Source
# archives are not disposable output - expiring one would break a project that had not been
# redeployed recently.

resource "aws_s3_bucket" "source" {
  count         = var.package_source ? 1 : 0
  bucket_prefix = "${var.name_prefix}-source-"
}

resource "aws_s3_bucket_public_access_block" "source" {
  count                   = var.package_source ? 1 : 0
  bucket                  = aws_s3_bucket.source[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source" {
  count  = var.package_source ? 1 : 0
  bucket = aws_s3_bucket.source[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioned so a payload's history survives, which is what makes the hash and version_id
# outputs a usable audit trail in place of a commit.
resource "aws_s3_bucket_versioning" "source" {
  count  = var.package_source ? 1 : 0
  bucket = aws_s3_bucket.source[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# The detection payload: the buildspec, the package, and its metadata. Tests, docs, this
# Terraform, and the local tooling are excluded - the worker neither needs nor should carry
# them, and everything shipped is code it could execute.
module "detection_source" {
  count  = var.package_source ? 1 : 0
  source = "./modules/source-package"

  name       = "detection"
  bucket     = aws_s3_bucket.source[0].id
  source_dir = local.implementation_root
  commit     = var.source_commit
  key_prefix = "payloads"

  excludes = local.payload_excludes

  tags = { Payload = "detection" }
}

locals {
  implementation_root = coalesce(var.implementation_root, "${path.module}/..")

  # Shared by both payloads: one definition, so a file excluded from the worker's view cannot
  # be excluded from one stage and shipped to the other.
  payload_excludes = [
    "terraform",
    "tests",
    "docs",
    ".git",
    ".kiro",
    ".claude",
    ".source-packages",
    ".pytest_cache",
    ".venv",
    "build",
    "dist",
    "src/driftcode.egg-info",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.DS_Store",
  ]

  # Where CodeBuild fetches this repository from: the packaged archive when Terraform owns
  # packaging, otherwise whatever the operator pointed at.
  #
  # one() over a splat rather than [0] behind a conditional: Terraform evaluates both branches
  # of a ternary, so indexing a count-0 module errors even when the condition is false. An
  # indexed form breaks setting package_source = false - the documented way to point at a real
  # repository - with a plan-time index error. And an explicit null check rather than
  # coalesce(), because coalesce treats "" as absent too and would raise when neither a package
  # nor a source_location is present.
  effective_source_type = var.package_source ? "S3" : var.source_type

  detection_packaged_location = one(module.detection_source[*].s3_location)

  effective_source_location = (
    local.detection_packaged_location != null
    ? local.detection_packaged_location
    : var.source_location
  )
}

# --- credential container ---------------------------------------------------

# The container is defined in code; the value is injected out-of-band with
#   aws secretsmanager put-secret-value --secret-id <id> --secret-string '{"token":"..."}'
# so the credential never appears in code, state, or a plan file.
resource "aws_secretsmanager_secret" "git_credential" {
  name        = "${var.name_prefix}/git-credential"
  description = "Read credential for cloning the target Terraform repository. Value injected out-of-band; never committed."

  recovery_window_in_days = 7
}

# --- observation ledger -----------------------------------------------------

# Consecutive-observation counts per drift signature. The scope guard refuses to codify
# drift seen only once, and "consecutive" is a claim about history that no single run can
# make, so the history lives here.
#
# Keyed on the signature rather than the resource address: if the drifted value changes,
# the signature changes with it, and the new value starts at one observation instead of
# inheriting confirmation earned by a different value.
resource "aws_dynamodb_table" "ledger" {
  name         = "${var.name_prefix}-observations"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "signature"

  attribute {
    name = "signature"
    type = "S"
  }

  # Resolved drift should disappear rather than accumulate. A signature not seen for the
  # retention window is either resolved or so intermittent that its count should restart.
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  # The count is the input to a decision about writing to a repository, and a lost write
  # under-counts silently - which looks exactly like the debounce working correctly.
  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}

# --- artifact store ---------------------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "${var.name_prefix}-detect-artifacts-"
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Plan JSON carries account identifiers and, depending on resource types, sensitive
# values. Artifacts are retained briefly rather than indefinitely.
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-plan-artifacts"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

# --- logs -------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "detect" {
  name              = "/aws/codebuild/${var.name_prefix}-detect"
  retention_in_days = var.log_retention_days
}

# --- the worker -------------------------------------------------------------

resource "aws_codebuild_project" "detect" {
  name          = "${var.name_prefix}-detect"
  description   = "Two-plan drift detection: locked refresh-only + full plan, reconciled, then Gate A."
  service_role  = aws_iam_role.detection.arn
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

    # The signature salt. It must be the stable owner/name slug rather than the clone URL:
    # the signature decides the branch name, so if the salt changed shape - a scheme added,
    # a .git suffix dropped - every branch name would change and the next run would open new
    # pull requests instead of adopting the open ones.
    environment_variable {
      name  = "TARGET_REPO_SLUG"
      value = var.target_repo_slug
    }

    environment_variable {
      name  = "TARGET_REPO_REF"
      value = var.target_repo_ref
    }

    environment_variable {
      name  = "TF_WORKING_DIR"
      value = var.target_working_dir
    }

    # Referenced by the buildspec's secrets-manager block, which resolves the
    # `token` key within the secret.
    environment_variable {
      name  = "GIT_CREDENTIAL_SECRET_ID"
      value = aws_secretsmanager_secret.git_credential.name
    }

    # The observation ledger, the workspace half of the drift signature's salt, and the
    # debounce threshold. Without the ledger and the salt the debounce cannot establish
    # consecutiveness, and every drift suppresses. The other half of the salt is
    # TARGET_REPO_SLUG, set above.
    environment_variable {
      name  = "DRIFT_LEDGER_TABLE"
      value = aws_dynamodb_table.ledger.name
    }

    environment_variable {
      name  = "DRIFT_WORKSPACE_ID"
      value = var.workspace_id
    }

    environment_variable {
      name  = "DRIFT_REQUIRED_SAMPLES"
      value = tostring(var.required_samples)
    }
  }

  # THIS repository, fetched by CodeBuild before the build starts. It supplies the
  # buildspec and the driftcode package the build installs. The estate under inspection is
  # a different repository entirely, cloned inside the build from TARGET_REPO_URL.
  source {
    type      = local.effective_source_type
    location  = local.effective_source_location
    buildspec = "buildspec.yml"

    # Only meaningful for git sources; CodeBuild rejects it on an S3 source, so it is
    # omitted rather than defaulted.
    git_clone_depth = local.effective_source_type == "S3" ? null : 1
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.detect.name
    }
  }
}

# --- schedule ---------------------------------------------------------------

# Detection is a scheduled poll, so it samples rather than streams: drift that appears
# and reverts entirely between runs is never observed. That is an accepted limitation of
# the approach, not an oversight.

resource "aws_iam_role" "scheduler" {
  count = var.schedule_expression == "" ? 0 : 1

  name = "${var.name_prefix}-detect-scheduler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "events.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

data "aws_iam_policy_document" "scheduler_states" {
  statement {
    effect    = "Allow"
    actions   = ["states:StartExecution"]
    resources = compact([one(aws_sfn_state_machine.pipeline[*].arn)])
  }
}

resource "aws_iam_role_policy" "scheduler_states" {
  count  = var.schedule_expression == "" || !var.enable_orchestration ? 0 : 1
  name   = "${var.name_prefix}-scheduler-states"
  role   = aws_iam_role.scheduler[0].id
  policy = data.aws_iam_policy_document.scheduler_states.json
}

resource "aws_iam_role_policy" "scheduler" {
  count = var.schedule_expression == "" ? 0 : 1

  name = "${var.name_prefix}-detect-scheduler"
  role = aws_iam_role.scheduler[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "codebuild:StartBuild"
      Resource = aws_codebuild_project.detect.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "detect" {
  count = var.schedule_expression == "" ? 0 : 1

  name                = "${var.name_prefix}-detect"
  description         = "Scheduled drift detection run."
  schedule_expression = var.schedule_expression
}

# When orchestration is enabled the schedule starts the state machine instead of the detection
# build directly. Pointing it at the build would run detection unattended with nothing to carry
# the result forward - the drift would be found and then dropped.
resource "aws_cloudwatch_event_target" "pipeline" {
  count = var.schedule_expression == "" || !var.enable_orchestration ? 0 : 1

  rule     = aws_cloudwatch_event_rule.detect[0].name
  arn      = aws_sfn_state_machine.pipeline[0].arn
  role_arn = aws_iam_role.scheduler[0].arn

  # No input transformer. The state machine needs nothing from the event: the lease decides
  # staleness by asking whether the previous holder is still running, so there is no timestamp to
  # pass and no epoch conversion to get wrong.
  input = "{}"
}

resource "aws_cloudwatch_event_target" "detect" {
  count = var.schedule_expression == "" || var.enable_orchestration ? 0 : 1

  rule     = aws_cloudwatch_event_rule.detect[0].name
  arn      = aws_codebuild_project.detect.arn
  role_arn = aws_iam_role.scheduler[0].arn
}
