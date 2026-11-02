variable "name" {
  description = "Short identifier for this payload, e.g. \"detection\" or \"agent\". Used for the object key and the temporary archive filename, so it must be unique per call."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*$", var.name))
    error_message = "name must be lowercase alphanumeric with hyphens; it becomes part of an S3 key."
  }
}

variable "bucket" {
  description = "S3 bucket to upload into. Owned by the root module and shared across payloads, so that a lifecycle policy set for one consumer cannot expire another's source."
  type        = string
}

variable "source_dir" {
  description = "Directory to package, normally the repository root. Everything under it is included except the excludes below."
  type        = string
}

variable "excludes" {
  description = <<-EOT
    Paths under source_dir to leave out, relative to it. Keep this tight rather than
    generous: anything included is code the worker could execute, and anything excluded that
    the payload actually imports fails at runtime rather than at apply time.
  EOT
  type        = list(string)
  default     = []
}

variable "key_prefix" {
  description = "Key prefix within the bucket. Ignored when key is set explicitly."
  type        = string
  default     = "source"
}

variable "key" {
  description = "Full object key, overriding key_prefix/name.zip. Leave null unless a consumer requires a specific path."
  type        = string
  default     = null
}

variable "archive_path" {
  description = "Where to write the zip locally before upload. Defaults to a gitignored directory beside the root module."
  type        = string
  default     = null
}

variable "commit" {
  description = <<-EOT
    Commit the payload was packaged from, recorded as object metadata. An S3 archive has no
    commit behind it the way a git source does; supplying this restores the audit trail. Pass
    the output of `git rev-parse HEAD`, or leave empty when packaging a dirty tree - an absent
    value is more honest than a commit that does not describe what was uploaded.
  EOT
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags for the uploaded object."
  type        = map(string)
  default     = {}
}
