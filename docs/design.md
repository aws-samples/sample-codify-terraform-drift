# Design notes

Why the implementation is shaped the way it is. Each of these records a decision that looks
like an unnecessary complication until you hit the failure it prevents, so changing any of
them should be deliberate.

## The deterministic boundary
Everything the agent is not allowed to decide is decided before it runs. The output of
`drift-authorize` is a **work order**: one resource, and for each authorized attribute
exactly one file, one line, the identifier expected on that line, and the value
observed in the cloud. `drift-verify` then reads the agent's diff and refuses anything
the work order did not name — another file, another line, another attribute, another
value, a new or deleted file, or an added `lifecycle`/`ignore_changes` block.

That is what lets the agent be treated as untrusted rather than merely constrained: a
prompt injection that changed the model's behaviour still has to produce a diff that
passes the verifier.

The task is handed to the agent as **JSON, not prose**. Any prose template needs a
delimiter between instruction and data, and every delimiter a template picks is one an
attacker-supplied value can contain — a fenced block falls to a fence, a tag marker falls
to the closing tag. A JSON string cannot escape itself, so a value is confined to its own
field whatever it contains. The task is also built by copying named fields, so plan
content that was never authorized is absent by construction rather than by filtering.

## Why the edit site is not the resource block

Knowing which resource drifted does not tell you what to edit. The same attribute can
be a literal in the resource block, a value passed in the caller's `module` block, an
entry in the workspace's own `tfvars`, or a `default` on a reusable module's variable —
different files with different blast radii. `resolve.py` traces the value and reports
which of those it is; only four layers are editable, and all of them are consumed by
this workspace alone:

| Source layer | Consumers | Verdict |
| --- | --- | --- |
| literal in a resource block in the workspace's own root module | this resource | editable |
| literal in the caller's `module` block | this workspace | editable |
| entry in the workspace's own `tfvars` | this workspace | editable |
| unoverridden `default` on a root-module variable | this workspace | editable |
| literal in a resource block inside a reusable module | every caller | escalate |
| `default` inside a reusable module | every caller | escalate |
| `tfvars` outside the workspace directory | every workspace reading it | escalate |
| `-var`, `TF_VAR_`, or CI-supplied | not in the repository | escalate |
| interpolation, function call, `local.`/`data.`/module output | no single literal | escalate |

A literal is workspace-local only when the block holding it belongs to the workspace's own
root module. A literal in a reusable module is shared by every caller, so the test is which
module the block is in, not whether the value is a literal.

In the sample workspace the drifted resource is declared in `modules/compute/main.tf`, but
the line that must change is in `environments/dev/terraform.tfvars`. Editing the block
instead would hardcode a shared module's value on the strength of one environment's drift,
and the next plan would contradict it.

Tracing is textual and deterministic — no model, no provider, no network — and
ambiguity resolves to escalation, so the failure mode is a human ticket rather than an
edit in the wrong file.

## Why there are two plans

A locked `terraform plan -refresh-only` is **not** a usable drift trigger on its own.
It reports provider *representation* normalization as drift — unset collections
flipping `null → []`, and deprecated in-line attributes populated from the standalone
resources that own them. On a freshly applied 9-resource stack with exactly one
induced drift, refresh-only reported **four** changed resources. Every one carried
`actions: ["update"]`, so an action filter admits all of them, and the pipeline would
open pull requests codifying changes nobody made.

Reconciling against a full `terraform plan` resolves it, with three *asymmetric*
outcomes:

| In refresh-only | In full plan | Verdict |
| --- | --- | --- |
| yes | yes | real drift — proceed |
| yes | no | normalization noise — suppress |
| no | yes | **not drift by itself** — a full plan also shows merged-but-never-applied code, so this needs a HEAD-vs-deployed check first |

The same intersection applies one level down: inside a genuinely drifted resource, the
changed-attribute list still mixes real changes with normalization noise. And an
attribute can survive intersection yet still be uncodifiable — provider-computed
values like `latest_version` legitimately differ but cannot be set in configuration.
Gate A classifies those against the provider schema so they never reach the agent as
an edit target.

## Why the policy scan needs a projection

Checkov **cannot** scan a `terraform plan -refresh-only` document. Its `terraform_plan`
framework builds a resource graph from `planned_values`, and a refresh-only plan leaves
that empty — the refreshed live values are in `prior_state`, and the captured plan has no
`resource_changes` key at all. Measured with Checkov 3.3.17:

| Scan target | Evaluated | Findings |
| --- | --- | --- |
| refresh-only plan | 0 | 0 |
| drift projection (`drift-project`) | 9 | 9 |
| full plan (baseline) | 9 | 9 |
| drift projection, SSH opened to `0.0.0.0/0` | 10 | 10 |

Zero findings out of zero checks reads as a clean estate to anything that looks at the
failure count, so the "is the drift dangerous" check could never fire.
`drift-project` transplants `prior_state` into `planned_values` and drops data sources,
producing a document that holds the live drifted values in the shape the scanner reads.
Nothing is synthesized.

The verdict is then a **set difference** against the full plan, which represents configured
intent — never a failure count. The sample estate carries nine pre-existing findings, so an
absolute threshold fails every run forever. The benign `instance_type` drift introduces
none of them and passes; opening SSH to the world introduces `CKV_AWS_24` on
`aws_security_group.web_prod` and fails, while that resource's two *pre-existing* findings
correctly do not count against it.

## Why drift must be seen twice

`classify` refuses to codify drift observed once: a value that appears and reverts is a
flap, and codifying a flap writes it into the repository permanently. "Consecutive" is a
claim about history that no single run can make, so `sign.py` gives each drift a stable
identity and `ledger.py` keeps the count.

The signature is keyed on the **attribute paths reconciliation confirmed**, not the whole
resource projection. A resource can carry real drift and provider normalization noise at
once, and the noise disappears after the next apply — so a whole-resource signature would
change between cycles for that reason alone, resetting the count every time and
guaranteeing the debounce never confirms.

Contiguity is decided by **build number, not elapsed time**. A time window has to guess
the cadence and silently accepts a gap when a run fails, which is exactly when the drift
could have reverted and returned unseen.

| Event | Count | Outcome |
| --- | --- | --- |
| build 1, first sighting | 1 | suppressed |
| build 2, consecutive | 2 | codified |
| build 3 retried | 3 (held) | a retry does not advance the count |
| build 7, after a gap | 1 | suppressed; the count restarts |
| drifted value changes | 1 | new signature, no inherited confirmation |

With no ledger table configured the store is in-memory and lasts one process, so every
sighting reads as a first observation and nothing is confirmed. That is deliberate: an
unconfigured ledger suppresses rather than inventing confirmation.

