output "bucket" {
  description = "Bucket holding the payload."
  value       = var.bucket
}

output "key" {
  description = "Object key of the payload."
  value       = aws_s3_object.payload.key
}

output "s3_location" {
  description = "\"bucket/key\", the form a CodeBuild S3 source expects."
  value       = "${var.bucket}/${aws_s3_object.payload.key}"
}

output "s3_uri" {
  description = "\"s3://bucket/key\", the form most other consumers expect."
  value       = "s3://${var.bucket}/${aws_s3_object.payload.key}"
}

output "object_arn" {
  description = "ARN of the uploaded object, for granting read access to exactly this payload rather than the whole bucket."
  value       = "arn:aws:s3:::${var.bucket}/${aws_s3_object.payload.key}"
}

output "version_id" {
  description = "S3 version of this upload. Pin a consumer to it when a run must be reproducible against a specific payload rather than the latest one."
  value       = aws_s3_object.payload.version_id
}

output "sha256" {
  description = "Base64 SHA-256 of the archive contents. Changes if and only if the packaged files change, so it identifies what a run actually executed."
  value       = data.archive_file.payload.output_base64sha256
}

output "commit" {
  description = "Commit recorded with the payload, empty when none was supplied."
  value       = var.commit
}
