# Package a directory of this repository into a versioned S3 object.
#
# Deploying the pattern should not require pushing it to a git remote first. Terraform
# already has the code on disk when it runs, so it packages what it needs and uploads it,
# and the consumer references an S3 object instead of a repository.
#
# This is a module because there is more than one consumer. The detection CodeBuild project
# takes the detection payload; the agent runtime takes the agent payload. Each call produces
# its own independently versioned object under a shared bucket, so one payload changing does
# not redeploy the other.
#
# The bucket is NOT created here, deliberately. Two callers would create two buckets, and a
# lifecycle policy set for one would eventually surprise the other. The root module owns the
# bucket and passes it in.
#
# The tradeoff against a git source is provenance: an S3 zip has no commit behind it. That
# is mitigated rather than ignored - the object is content-addressed by hash, the bucket is
# versioned, the hash and any known commit are recorded as object metadata, and both are
# exposed as outputs so a run can be traced back to exactly what it executed.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

locals {
  # Written beside the root module and gitignored. Unique per package name so two calls
  # cannot race on one temporary file.
  archive_path = coalesce(
    var.archive_path,
    "${path.root}/.source-packages/${var.name}.zip"
  )

  key = coalesce(var.key, "${var.key_prefix}/${var.name}.zip")
}

data "archive_file" "payload" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = local.archive_path
  excludes    = var.excludes
}

# A stable key, not a hash-suffixed one. A changing key would leave every previous archive
# behind with no safe way to expire them: any age-based rule would eventually delete the
# object a long-idle project still depends on. Instead the key is fixed, the bucket is
# versioned, and `source_hash` re-uploads when the content changes.
resource "aws_s3_object" "payload" {
  bucket = var.bucket
  key    = local.key
  source = data.archive_file.payload.output_path

  # etag drives replacement on content change; source_hash makes the diff legible.
  etag        = data.archive_file.payload.output_md5
  source_hash = data.archive_file.payload.output_md5

  content_type = "application/zip"

  metadata = merge(
    {
      "payload-sha256" = data.archive_file.payload.output_base64sha256
      "packaged-by"    = "terraform"
    },
    var.commit == "" ? {} : { "source-commit" = var.commit }
  )

  tags = var.tags
}
