# Orchestration: one run at a time, four stages, and a lease that outlives a crash.
#
# Starting the four builds by hand is fine for a demonstration and unusable as a control. Two
# properties are the reason this is a state machine rather than a fifth buildspec that shells
# out:
#
#   Mutual exclusion. Two concurrent runs against one workspace would race on the Terraform
#   state lock, and worse, could open two pull requests for the same drift before either had
#   recorded an observation. Step Functions' own execution-name idempotency does not give this -
#   it only blocks executions that are concurrently ACTIVE with the same name, which is not the
#   same claim. The lease below is a conditional DynamoDB write, guarded by a liveness check
#   on whichever execution currently holds it.
#
#   Release on failure. A lease held by a crashed run is worse than no lease: it blocks every
#   subsequent run indefinitely. Every terminal path here passes through Release, including the
#   catch-all, so a failure does not leave the workspace wedged - and if a run dies without
#   reaching Release at all, the next run finds its execution no longer RUNNING and takes over.
#
# What this deliberately does NOT yet do: verify the fencing token at the point of write. The
# token is minted and passed to the workers, so it is available - but a worker does not check it
# before acting. That means the lease is mutual exclusion, not fenced mutual exclusion: a holder
# whose lease has been taken over, because its execution stopped reporting as RUNNING, could still
# act if it resumed. Closing that requires the workers to compare the token at every
# state-affecting write, which is a change to them and not to this file.

resource "aws_dynamodb_table" "lease" {
  count        = var.enable_orchestration ? 1 : 0
  name         = "${var.name_prefix}-run-lease"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "workspace_id"

  attribute {
    name = "workspace_id"
    type = "S"
  }

  # No TTL. Staleness is decided by asking whether the holder's execution is still RUNNING, so
  # there is no clock to expire and nothing to guess. A TTL here would only ever be wrong in one
  # of two directions: expiring under a live holder, or holding a workspace after a crash.

  server_side_encryption {
    enabled = true
  }
}

# --- role -------------------------------------------------------------------

data "aws_iam_policy_document" "states_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "orchestrator" {
  count              = var.enable_orchestration ? 1 : 0
  name               = "${var.name_prefix}-orchestrator"
  assume_role_policy = data.aws_iam_policy_document.states_assume.json

  description = "Sequences the drift pipeline. Starts builds and manages the run lease; touches nothing else."
}

data "aws_iam_policy_document" "orchestrator" {
  # Starting and watching builds. .sync integrations need the events permissions too, which is
  # how Step Functions learns a build finished rather than polling it.
  statement {
    sid    = "RunTheStages"
    effect = "Allow"

    actions = [
      "codebuild:StartBuild",
      "codebuild:StopBuild",
      "codebuild:BatchGetBuilds",
    ]

    resources = compact([
      aws_codebuild_project.detect.arn,
      one(aws_codebuild_project.codify[*].arn),
      one(aws_codebuild_project.gates[*].arn),
    ])
  }

  # A `.sync` integration does not poll the build. Step Functions creates an EventBridge managed
  # rule so CodeBuild notifies it on completion, which is why an orchestrator that can only
  # StartBuild fails at CreateStateMachine with "not authorized to create managed-rule".
  #
  # Scoped by the StepFunctions* name prefix rather than granted on all rules: these are rules
  # the service creates and owns, and the exact name varies by integration, so pinning one name
  # breaks the moment another .sync target is added.
  statement {
    sid    = "WatchBuildsForSyncIntegration"
    effect = "Allow"

    actions = [
      "events:PutTargets",
      "events:PutRule",
      "events:DescribeRule",
    ]

    resources = ["arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/StepFunctions*"]
  }

  # The lease. UpdateItem is what mints the fencing token: an ADD on a counter is atomic, so two
  # racing runs cannot receive the same value.
  statement {
    sid       = "ManageTheRunLease"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:GetItem"]
    resources = compact([one(aws_dynamodb_table.lease[*].arn)])
  }

  # Asking whether the lease holder is still running. Scoped to this state machine's own
  # executions: it needs to know about its predecessors, nothing else.
  statement {
    sid       = "CheckLeaseHolderLiveness"
    effect    = "Allow"
    actions   = ["states:DescribeExecution"]
    resources = ["arn:aws:states:${var.aws_region}:${data.aws_caller_identity.current.account_id}:execution:${var.name_prefix}-pipeline:*"]
  }

  statement {
    sid       = "Notify"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = compact([one(aws_sns_topic.alerts[*].arn)])
  }

  # Publishing to an encrypted topic needs the data key as well as the publish action. The
  # AWS-managed SNS key delegates authorization to IAM rather than granting it in its own key
  # policy, so without this the publish fails with AccessDenied and the escalation is lost -
  # a failure mode that only shows up on the path that reports failures. Scoped by ViaService
  # so it cannot be used to encrypt or decrypt through any other service, and left at "*" so
  # it keeps working if alerts_kms_key_id is repointed at a customer-managed key.
  statement {
    sid    = "EncryptAlerts"
    effect = "Allow"

    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sns.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "orchestrator" {
  count  = var.enable_orchestration ? 1 : 0
  name   = "${var.name_prefix}-orchestrator"
  role   = aws_iam_role.orchestrator[0].id
  policy = data.aws_iam_policy_document.orchestrator.json
}

# --- alerting ---------------------------------------------------------------

# The design's containment path starts here: an escalation nobody sees is an escalation that did
# not happen. Subscriptions are left to the operator - an email address in Terraform state is
# both a leak and a support burden.
#
# Encrypted at rest. The default is the AWS-managed SNS key, which costs nothing and needs no
# key policy; point alerts_kms_key_id at a customer-managed key where you need control over the
# key policy, rotation, or cross-account subscribers. Either way the publisher needs KMS
# permissions in its own identity policy - see the EncryptAlerts statement above, and note that
# an encrypted topic with no such grant fails at publish time, which would silence exactly the
# alerts this topic exists to carry.
resource "aws_sns_topic" "alerts" {
  count             = var.enable_orchestration ? 1 : 0
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = var.alerts_kms_key_id
}

# --- the state machine ------------------------------------------------------

resource "aws_cloudwatch_log_group" "orchestrator" {
  count             = var.enable_orchestration ? 1 : 0
  name              = "/aws/vendedlogs/states/${var.name_prefix}-pipeline"
  retention_in_days = var.log_retention_days
}

locals {
  detect_project   = aws_codebuild_project.detect.name
  codify_project   = one(aws_codebuild_project.codify[*].name)
  gates_project    = one(aws_codebuild_project.gates[*].name)
  artifacts_bucket = aws_s3_bucket.artifacts.bucket

  # The lease row itself, shared by both takeover states so the two cannot drift apart in what
  # they record. Only the guard differs between them.
  lease_item = {
    workspace_id  = { S = var.workspace_id }
    execution_arn = { "S.$" = "$$.Execution.Id" }
    execution     = { "S.$" = "$$.Execution.Name" }
    fence         = { "N.$" = "States.Format('{}', $.fence.Attributes.fence.N)" }
    acquired_at   = { "S.$" = "$$.State.EnteredTime" }
  }

  pipeline = {
    Comment = "Detect valid Terraform drift, codify it, scan the result, and label the pull request."
    StartAt = "MintFencingToken"
    States = {
      # A monotonic counter, incremented atomically. Two runs racing here cannot receive the
      # same token, which is what makes it usable as a fence even though nothing verifies it yet.
      MintFencingToken = {
        Type     = "Task"
        Resource = "arn:aws:states:::aws-sdk:dynamodb:updateItem"
        Parameters = {
          TableName                 = one(aws_dynamodb_table.lease[*].name)
          Key                       = { workspace_id = { S = "${var.workspace_id}#fence" } }
          UpdateExpression          = "ADD fence :one"
          ExpressionAttributeValues = { ":one" = { N = "1" } }
          ReturnValues              = "UPDATED_NEW"
        }
        ResultPath = "$.fence"
        Next       = "ReadLease"
      }

      # Staleness is judged by asking whether the recorded holder is still RUNNING, not by
      # comparing a clock.
      #
      # A TTL lease has to guess how long a run takes, and both errors hurt: too short and it
      # expires under a working holder, too long and a crashed run wedges the workspace. It also
      # needs epoch arithmetic, which Step Functions cannot do on the ISO8601 timestamp
      # EventBridge supplies - so a TTL lease works when started by hand with an epoch and fails
      # on the first scheduled run. DescribeExecution answers the question the lease actually
      # cares about, and needs no clock at all.
      ReadLease = {
        Type     = "Task"
        Resource = "arn:aws:states:::aws-sdk:dynamodb:getItem"
        Parameters = {
          TableName      = one(aws_dynamodb_table.lease[*].name)
          Key            = { workspace_id = { S = var.workspace_id } }
          ConsistentRead = true
        }
        ResultPath = "$.lease"
        Next       = "IsWorkspaceHeld"
      }

      IsWorkspaceHeld = {
        Type = "Choice"
        Choices = [{
          Variable  = "$.lease.Item"
          IsPresent = true
          Next      = "IsHolderStillRunning"
        }]
        Default = "TakeLease"
      }

      IsHolderStillRunning = {
        Type     = "Task"
        Resource = "arn:aws:states:::aws-sdk:sfn:describeExecution"
        Parameters = {
          "ExecutionArn.$" = "$.lease.Item.execution_arn.S"
        }
        ResultSelector = { "status.$" = "$.Status" }
        ResultPath     = "$.holder"
        Next           = "HolderVerdict"
        # A holder whose execution has aged out of history cannot be running, so the lease is
        # stale and takeable.
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.holderError"
          Next        = "TakeLeaseFromDeadHolder"
        }]
      }

      HolderVerdict = {
        Type = "Choice"
        Choices = [{
          Variable     = "$.holder.status"
          StringEquals = "RUNNING"
          Next         = "AnotherRunHoldsTheWorkspace"
        }]
        Default = "TakeLeaseFromDeadHolder"
      }

      # Two takeover states rather than one, because each asserts a different thing and the
      # assertion has to name what was actually observed. A single state cannot: on the
      # no-holder path $.lease.Item does not exist, and a Parameters JSONPath that does not
      # resolve is a States.Runtime error, not an empty string.

      # No holder was recorded. The only safe assertion is that there is still none.
      TakeLease = {
        Type     = "Task"
        Resource = "arn:aws:states:::aws-sdk:dynamodb:putItem"
        Parameters = {
          TableName           = one(aws_dynamodb_table.lease[*].name)
          Item                = local.lease_item
          ConditionExpression = "attribute_not_exists(workspace_id)"
        }
        ResultPath = null
        Next       = "Detect"
        Catch = [{
          ErrorEquals = ["DynamoDb.ConditionalCheckFailedException"]
          Next        = "AnotherRunHoldsTheWorkspace"
        }]
      }

      # A holder was recorded and found not to be running. The assertion is that the row is
      # still that same dead holder's - so two runs reaching this instant together cannot both
      # win, since the first replaces the ARN the second is testing for.
      #
      # attribute_not_exists is also accepted: the dead holder's row may have been cleaned up
      # between the read and this write, which leaves the workspace free rather than contended.
      # A live holder that took over in the meantime has neither an absent row nor the dead
      # ARN, so it still turns this run away.
      TakeLeaseFromDeadHolder = {
        Type     = "Task"
        Resource = "arn:aws:states:::aws-sdk:dynamodb:putItem"
        Parameters = {
          TableName           = one(aws_dynamodb_table.lease[*].name)
          Item                = local.lease_item
          ConditionExpression = "attribute_not_exists(workspace_id) OR execution_arn = :dead"
          ExpressionAttributeValues = {
            ":dead" = { "S.$" = "$.lease.Item.execution_arn.S" }
          }
        }
        ResultPath = null
        Next       = "Detect"
        Catch = [{
          ErrorEquals = ["DynamoDb.ConditionalCheckFailedException"]
          Next        = "AnotherRunHoldsTheWorkspace"
        }]
      }

      AnotherRunHoldsTheWorkspace = {
        Type    = "Succeed"
        Comment = "Not a failure. Serialization is the point, and a skipped cycle is visible in the missed-cadence alert rather than here."
      }

      Detect = {
        Type     = "Task"
        Resource = "arn:aws:states:::codebuild:startBuild.sync"
        Parameters = {
          ProjectName = local.detect_project
        }
        ResultSelector = {
          "status.$"   = "$.Build.BuildStatus"
          "has_work.$" = "$.Build.ExportedEnvironmentVariables[?(@.Name=='DRIFT_HAS_WORK')].Value"
          "artifact.$" = "States.Format('{}', '${local.detect_project}')"
        }
        ResultPath = "$.detect"
        Next       = "AnythingToCodify"
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "Alert" }]
      }

      AnythingToCodify = {
        Type = "Choice"
        Choices = [{
          Variable     = "$.detect.has_work[0]"
          StringEquals = "true"
          Next         = "Codify"
        }]
        Default = "NoDriftToCodify"
      }

      NoDriftToCodify = {
        Type    = "Pass"
        Comment = "Detection ran and found nothing codifiable - a quiet estate, or drift awaiting a second observation."
        Next    = "Release"
      }

      Codify = {
        Type     = "Task"
        Resource = "arn:aws:states:::codebuild:startBuild.sync"
        Parameters = {
          ProjectName = local.codify_project
          EnvironmentVariablesOverride = [
            { Name = "DETECTION_ARTIFACT_KEY", Value = local.detect_project, Type = "PLAINTEXT" },
            { Name = "DRIFT_FENCE", "Value.$" = "States.Format('{}', $.fence.Attributes.fence.N)", Type = "PLAINTEXT" },
          ]
        }
        ResultSelector = {
          "status.$"    = "$.Build.BuildStatus"
          "published.$" = "$.Build.ExportedEnvironmentVariables[?(@.Name=='DRIFT_PUBLISHED')].Value"
          "branch.$"    = "$.Build.ExportedEnvironmentVariables[?(@.Name=='DRIFT_BRANCH')].Value"
        }
        ResultPath = "$.codify"
        Next       = "AnythingPublished"
        # A rejected diff fails this build deliberately. It is an escalation, not a pipeline
        # fault, so it alerts rather than retrying: retrying a diff that did not match the work
        # order would produce the same diff.
        Catch = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "Alert" }]
      }

      AnythingPublished = {
        Type = "Choice"
        Choices = [{
          Variable     = "$.codify.published[0]"
          StringEquals = "true"
          Next         = "Gates"
        }]
        Default = "NothingPublished"
      }

      NothingPublished = {
        Type    = "Pass"
        Comment = "The agent declined or the change did not verify. Nothing was written and there is no pull request to scan."
        Next    = "Alert"
      }

      # The privilege split made visible: a different project, a different role, no write
      # credential. This is the state that cannot be merged into Codify without giving the
      # worker that holds a write credential access to Terraform state.
      Gates = {
        Type     = "Task"
        Resource = "arn:aws:states:::codebuild:startBuild.sync"
        Parameters = {
          ProjectName = local.gates_project
          EnvironmentVariablesOverride = [
            { Name = "DRIFT_BRANCH", "Value.$" = "$.codify.branch[0]", Type = "PLAINTEXT" },
          ]
        }
        ResultSelector = { "status.$" = "$.Build.BuildStatus" }
        ResultPath     = "$.gates"
        Next           = "Finalize"
        # A failing gate still produces a verdict artifact, so this catch is for the stage
        # breaking, not for the gate refusing.
        Catch = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "Alert" }]
      }

      # The codify project again, with a buildspec override: the credential that opened the pull
      # request is the one that labels it, and no fourth role exists.
      Finalize = {
        Type     = "Task"
        Resource = "arn:aws:states:::codebuild:startBuild.sync"
        Parameters = {
          ProjectName       = local.codify_project
          BuildspecOverride = "buildspec-finalize.yml"
          EnvironmentVariablesOverride = [
            { Name = "DRIFT_GATES_ARTIFACT_KEY", Value = local.gates_project, Type = "PLAINTEXT" },
            { Name = "DRIFT_CODIFY_ARTIFACT_KEY", Value = local.codify_project, Type = "PLAINTEXT" },
          ]
        }
        ResultSelector = { "status.$" = "$.Build.BuildStatus" }
        ResultPath     = "$.finalize"
        Next           = "Release"
        Catch          = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "Alert" }]
      }

      # Every failure path reaches here, and it releases the lease before reporting. A lease held
      # by a failed run blocks every subsequent run until something takes it over, which turns
      # one failure into an outage.
      Alert = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn    = one(aws_sns_topic.alerts[*].arn)
          Subject     = "Drift pipeline: attention required"
          "Message.$" = "States.Format('Workspace {} run {} needs attention. The drift may still be live and unaddressed. Detail: {}', '${var.workspace_id}', $$.Execution.Name, States.JsonToString($))"
        }
        ResultPath = null
        Next       = "ReleaseAfterFailure"
      }

      ReleaseAfterFailure = {
        Type     = "Task"
        Resource = "arn:aws:states:::aws-sdk:dynamodb:deleteItem"
        Parameters = {
          TableName = one(aws_dynamodb_table.lease[*].name)
          Key       = { workspace_id = { S = var.workspace_id } }
        }
        ResultPath = null
        Next       = "Escalated"
      }

      Escalated = {
        Type  = "Fail"
        Error = "DriftUnaddressed"
        Cause = "A stage failed or the change was refused. The drift may still be live with nothing in front of a human."
      }

      Release = {
        Type     = "Task"
        Resource = "arn:aws:states:::aws-sdk:dynamodb:deleteItem"
        Parameters = {
          TableName = one(aws_dynamodb_table.lease[*].name)
          Key       = { workspace_id = { S = var.workspace_id } }
        }
        ResultPath = null
        End        = true
      }
    }
  }
}

resource "aws_sfn_state_machine" "pipeline" {
  count = var.enable_orchestration ? 1 : 0

  name     = "${var.name_prefix}-pipeline"
  role_arn = aws_iam_role.orchestrator[0].arn

  # STANDARD, not EXPRESS: the run takes minutes, needs .sync integrations, and its history is
  # the audit trail for a change that reached a repository.
  type       = "STANDARD"
  definition = jsonencode(local.pipeline)

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.orchestrator[0].arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }
}
