variable "aws_region" {
  description = "Region hosting the detection pipeline."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for all resource names, so the pipeline is filterable in a shared account."
  type        = string
  default     = "drift-demo"
}

# --- the repository holding this implementation (CodeBuild's source) ---------

variable "package_source" {
  description = <<-EOT
    Let Terraform package this repository and upload it, instead of requiring a git remote.
    Terraform already has the code on disk when it runs, so the default is to zip the
    detection payload, put it in a bucket it owns, and give CodeBuild an S3 source. Nothing
    has to be pushed anywhere for the pattern to be deployable.

    Set false to point CodeBuild at a real repository instead, via source_type and
    source_location — appropriate once the implementation lives somewhere with review and
    history, since an S3 archive carries no commit of its own (the module records the hash,
    the version and an optional commit in its place).

    The same packaging module serves the agent runtime's payload, so this switch governs the
    approach for both rather than for CodeBuild alone.
  EOT
  type        = bool
  default     = true
}

variable "implementation_root" {
  description = "Directory to package when package_source is true. Defaults to the repository root, one level above this Terraform."
  type        = string
  default     = null
}

variable "source_commit" {
  description = <<-EOT
    Commit the payload is packaged from, recorded as object metadata so a run can be traced
    to the code it executed. Pass `git rev-parse HEAD`; leave empty when the tree is dirty,
    because an absent value is more honest than a commit that does not describe the upload.
  EOT
  type        = string
  default     = ""
}

variable "source_location" {
  description = <<-EOT
    Where CodeBuild fetches THIS repository from — the implementation, not the
    infrastructure being inspected. Only used when package_source is false; otherwise
    Terraform packages the repository and this is computed.

    Do not confuse this with target_repo_url. Two repositories are involved at runtime and
    they are fetched by different mechanisms:

      source_location  -> this repo. Fetched by CodeBuild itself, before the build starts.
                          Contains the buildspec and the detection code.
      target_repo_url  -> the Terraform estate under inspection. Cloned INSIDE the build by
                          `git clone` with the read-only credential from Secrets Manager,
                          into /tmp/target. Never written to by detection.

    For GITHUB/GITLAB/GITHUB_ENTERPRISE/BITBUCKET this is the clone URL; for CODECOMMIT the
    repository URL; for S3 it is "bucket/key.zip".
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.source_location != "" || var.package_source
    error_message = "source_location is required when package_source is false; otherwise Terraform has nothing to point CodeBuild at."
  }
}

variable "source_type" {
  description = <<-EOT
    CodeBuild source type for THIS repository. S3 is included deliberately: it needs no git
    remote and no credential, so the pattern can be deployed and exercised before the
    implementation has anywhere to be pushed to. NO_SOURCE is not offered — the build
    installs the package from disk, so it cannot run without a source.
  EOT
  type        = string
  default     = "GITHUB"

  validation {
    condition     = contains(["GITHUB", "GITLAB", "GITHUB_ENTERPRISE", "CODECOMMIT", "BITBUCKET", "S3"], var.source_type)
    error_message = "source_type must be one of GITHUB, GITLAB, GITHUB_ENTERPRISE, CODECOMMIT, BITBUCKET, S3."
  }
}

# --- the estate being inspected ---------------------------------------------

variable "target_repo_url" {
  description = <<-EOT
    Host and path of the Terraform repository to inspect, without scheme or
    credentials (for example "github.com/org/infra"). The buildspec prefixes the
    scheme and injects the credential at clone time.
  EOT
  type        = string
}

variable "target_repo_ref" {
  description = "Branch of the target repository to reconcile against."
  type        = string
  default     = "main"
}

variable "target_working_dir" {
  description = "Path within the target repository to the root module to inspect."
  type        = string
  default     = "environments/dev"
}

# --- state backend of the TARGET estate (what detection reads) --------------

variable "target_state_bucket" {
  description = "S3 bucket holding the target estate's Terraform state."
  type        = string
}

variable "target_state_key" {
  description = <<-EOT
    Exact S3 key of the target estate's state object. Scoped deliberately: the
    detection role is granted GetObject on this key only, and explicitly denied
    PutObject and DeleteObject on it.
  EOT
  type        = string
  default     = "environments/dev/terraform.tfstate"
}

variable "target_lock_table" {
  description = <<-EOT
    DynamoDB table used for Terraform state locking on the target estate. The
    detection role needs read AND WRITE here: acquiring a lock writes an item.
    Denying writes to this table would break locking, which detection requires.
  EOT
  type        = string
}

# --- read scope over the managed surface ------------------------------------

variable "managed_surface_read_policy_arns" {
  description = <<-EOT
    Policies granting read over the estate under management. Terraform's provider
    must be able to Describe/Get every managed resource: a missing permission does
    not error, it leaves the prior state in place so the resource looks unchanged.
    That is silently masked drift.

    Prefer a policy derived from the state inventory over a broad managed one - state
    already enumerates every managed resource type, so the required action set is
    computable. Least privilege is only safe here because Gate A fails closed on read
    failures; narrow permissions without that gate under-report drift silently, which
    is worse than granting broadly.

    Defaults to the AWS managed ReadOnlyAccess for a first deployment. Replace it for
    anything beyond a sandbox: it permits reading object and item *data*, which a
    refresh never needs.
  EOT
  type        = list(string)
  default     = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
}

variable "cross_account_read_role_arns" {
  description = <<-EOT
    Read roles to assume in other accounts holding managed resources. Without these,
    a provider alias for an unconfigured account can present managed objects as
    deleted rather than raising an authorization error.
  EOT
  type        = list(string)
  default     = []
}

# --- scheduling and retention ----------------------------------------------

variable "schedule_expression" {
  description = <<-EOT
    EventBridge schedule for the detection run. Empty disables the schedule, which is the
    default: a fresh clone should not start running unattended against an estate before the
    target repository, the credential and the alert subscription have been configured. Set
    this (for example "rate(1 day)") once a first run has been driven by hand.
  EOT
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch retention for build logs. Logs echo plan content, so keep this short."
  type        = number
  default     = 14
}

variable "build_timeout_minutes" {
  description = "Build timeout. Two plans over a large estate can be slow."
  type        = number
  default     = 30
}


variable "workspace_id" {
  description = <<-DESC
    Identifies this workspace in the drift signature's salt. Two environments that call the
    same module can drift identically; without distinct salts they would share one
    signature, one observation count and one pull request. Defaults to the working
    directory's leaf name, which is distinct per environment in the conventional layout.
  DESC
  type        = string
  default     = "dev"
}

variable "required_samples" {
  description = <<-DESC
    Consecutive observations required before drift may be codified. Below 2 the debounce is
    inert and a transient flap can be written into the repository permanently; the cost of
    raising it is one detection cadence of delay per increment.
  DESC
  type        = number
  default     = 2

  validation {
    condition     = var.required_samples >= 2
    error_message = "required_samples must be at least 2; a single observation may be a transient flap."
  }
}


# --- codify stage -----------------------------------------------------------

variable "enable_codify" {
  description = <<-EOT
    Provision the codify stage: the agent, the verifier and the pull-request path. Separate
    from detection so the read-only half can be deployed and trusted on its own before
    anything is granted a write credential or a model invocation.
  EOT
  type        = bool
  default     = false
}

variable "target_repo_slug" {
  description = <<-EOT
    "owner/name" of the target repository, as the GitHub API addresses it. Distinct from
    target_repo_url, which is the clone URL - the API needs the slug and git needs the URL, and
    deriving one from the other guesses at host and suffix conventions.

    Required, because it is also the signature salt. The signature decides the branch name, so
    a salt that can change shape - a scheme added, a .git suffix dropped - would change every
    branch name and make the next run open new pull requests instead of adopting the open ones.
    The slug is the one form of the identifier with a single spelling.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[^/]+/[^/]+$", var.target_repo_slug))
    error_message = "target_repo_slug must be \"owner/name\" with no scheme, host or .git suffix."
  }
}

variable "model_id" {
  description = <<-EOT
    Bedrock model the agent runs on. The task is small and heavily constrained - matching a
    file's conventions, not reasoning about infrastructure - so a mid-tier model is the right
    default and a larger one buys little.
  EOT
  type        = string
  default     = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
}

variable "model_invoke_arns" {
  description = <<-EOT
    ARNs the codify role may invoke. Named rather than wildcarded: `bedrock:InvokeModel` on
    `*` would let a compromised worker call anything in the account's catalogue, including
    models with different data-handling terms than the one that was reviewed.

    Cross-region inference profiles need both the profile ARN and the underlying foundation
    model ARNs in each region the profile can route to, which is why this is a list.
  EOT
  type        = list(string)
  default     = []
}

variable "github_app_id" {
  description = <<-EOT
    GitHub App ID for the write path. When set, the codify and finalize steps mint installation
    tokens instead of using the personal access token: scoped to one repository, limited to
    Contents and Pull requests, and valid for an hour.

    A personal access token authenticates as a person and carries that person's reach across
    every repository they can see, with no expiry. In a pipeline where one worker holds both a
    model and a write credential, that is the difference between a bounded compromise and an
    unbounded one. Leave empty to fall back to the token.
  EOT
  type        = string
  default     = ""
}

variable "github_app_key_secret_id" {
  description = <<-EOT
    Secrets Manager secret holding the App's PEM private key. Created out of band, like the
    clone credential: the key never appears in code, state, or a plan file.

      aws secretsmanager create-secret --name drift-demo/github-app-key \
        --secret-string file://drift-bot.private-key.pem
  EOT
  type        = string
  default     = ""
}

# --- orchestration ----------------------------------------------------------

variable "enable_orchestration" {
  description = <<-EOT
    Provision the Step Functions state machine, the run lease and the alert topic. Separate from
    the stages themselves so each can be deployed and trusted before anything sequences them
    unattended.
  EOT
  type        = bool
  default     = false
}

variable "alerts_kms_key_id" {
  description = <<-EOT
    KMS key for the alert topic's server-side encryption. Defaults to the AWS-managed SNS key,
    which costs nothing and needs no key policy. Use a customer-managed key where you need
    control over the key policy, rotation, or cross-account subscribers; the publisher's grant
    is scoped by kms:ViaService rather than by key ARN, so repointing this needs no IAM change.
  EOT
  type        = string
  default     = "alias/aws/sns"

  validation {
    condition     = var.alerts_kms_key_id != ""
    error_message = "alerts_kms_key_id must name a key; an unencrypted alert topic is not offered as an option."
  }
}

