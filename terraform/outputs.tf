output "detect_project_name" {
  description = "CodeBuild project running detection. Start a run with: aws codebuild start-build --project-name <this>"
  value       = aws_codebuild_project.detect.name
}

output "detection_role_arn" {
  description = "Role the detection worker assumes. Reads the managed surface and state; denied writing state. The model holds no AWS credentials."
  value       = aws_iam_role.detection.arn
}

output "git_credential_secret_id" {
  description = <<-EOT
    Secret holding the credential for cloning the target repository. Created empty on
    purpose - inject the value out-of-band so it never enters code, state, or a plan:

      aws secretsmanager put-secret-value \
        --secret-id <this> --secret-string '{"token":"<credential>"}'
  EOT
  value       = aws_secretsmanager_secret.git_credential.name
}

output "artifacts_bucket" {
  description = "Artifact store for plan JSON and gate results. Treat as sensitive: plan output carries account identifiers."
  value       = aws_s3_bucket.artifacts.bucket
}

output "log_group_name" {
  description = "Build logs. These echo plan content, so retention is deliberately short."
  value       = aws_cloudwatch_log_group.detect.name
}

output "observation_ledger_table" {
  description = "DynamoDB table holding consecutive-observation counts per drift signature. Without it the debounce cannot establish consecutiveness and every drift suppresses."
  value       = aws_dynamodb_table.ledger.name
}


# --- source packaging -------------------------------------------------------
#
# Exposed so the agent runtime's stack can package into the same bucket rather than standing
# up a second one, and so a run can be traced to the payload it executed.

output "source_bucket" {
  description = "Shared bucket holding packaged payloads. Pass this to the source-package module for the agent runtime rather than creating another bucket."
  value       = one(aws_s3_bucket.source[*].id)
}

output "detection_source_location" {
  description = "What CodeBuild is actually fetching, in whichever form applies."
  value       = local.effective_source_location
}

output "detection_source_sha256" {
  description = "Base64 SHA-256 of the packaged detection payload. Changes only when the packaged files change, so it identifies what a build ran."
  value       = one(module.detection_source[*].sha256)
}

output "detection_source_version_id" {
  description = "S3 version of the uploaded detection payload, for pinning a reproducible run."
  value       = one(module.detection_source[*].version_id)
}

output "codify_project_name" {
  description = "CodeBuild project running the agent, the verifier and the pull-request path. Null when enable_codify is false."
  value       = one(aws_codebuild_project.codify[*].name)
}

output "codify_role_arn" {
  description = "Role the codify stage assumes. Separate from detection: it invokes a model and holds a repository write credential, and has no AWS estate write access or Terraform state access."
  value       = one(aws_iam_role.codify[*].arn)
}

output "gates_project_name" {
  description = "CodeBuild project that scans the codified branch. Holds state and estate read, and no repository write credential."
  value       = one(aws_codebuild_project.gates[*].name)
}

output "gates_role_arn" {
  description = "Role the gate stage assumes. Deliberately cannot invoke a model and cannot write Terraform state."
  value       = one(aws_iam_role.gates[*].arn)
}

output "pipeline_state_machine_arn" {
  description = "Step Functions state machine sequencing detect -> codify -> gates -> finalize, serialized per workspace by a DynamoDB lease."
  value       = one(aws_sfn_state_machine.pipeline[*].arn)
}

output "alerts_topic_arn" {
  description = "SNS topic for escalations. Subscribe an address to it: an escalation nobody sees is an escalation that did not happen."
  value       = one(aws_sns_topic.alerts[*].arn)
}

output "run_lease_table" {
  description = "DynamoDB table holding the per-workspace run lease. Distinct from the observation ledger."
  value       = one(aws_dynamodb_table.lease[*].name)
}
