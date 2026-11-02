# Development

Running the stages by hand, the repository layout, and how the test fixtures work.

## Layout

```
src/driftcode/
  detect/         runs INSIDE the pipeline (CodeBuild executes it)
    reconcile.py    two-plan reconciliation - what actually drifted
    gate_a.py       fail-closed completeness assertions + schema classification
    tf_guard.py     positive allowlist for terraform invocations
  classify.py     scope guard - may this drift be codified at all
  resolve.py      source-layer tracing - which file actually holds the value
  locate.py       resource address -> exact file and block, no model involved
  sanitize.py     the allowlisted record the agent is permitted to see
  project.py      live values, made scannable by a plan-based policy engine
  sign.py         the drift signature: one stable identity per drifted resource
  ledger.py       consecutive-observation counts, so the debounce means something
  authorize.py    the whole deterministic chain -> a bounded work order
  prompt.py       the agent's standing instruction and per-task rendering
  verify.py       checks the agent's diff against that work order
  mcp/            the write path: GitHub client, publisher, MCP tool surface
    github.py       the only component that holds a write credential
    github_app.py   mints hour-long tokens scoped to one repository
    publish.py      opens or converges on exactly one pull request per drift
    server.py       the agent's tools - none of which writes to a repository
  agent.py        drives a model through one codification over those tools
  codify.py       the codify stage: agent -> verify -> publish
  gates.py        Gates B and C, as a delta against a baseline
  finalize.py     applies the gate verdict to an open pull request
terraform/        provisions the pipeline; packages src/ so no git remote is needed
  modules/source-package/   zip -> versioned S3 object, reused per payload
tests/            offline tests; no AWS calls
docs/             pipeline.drawio - the deployed pipeline, credential boundaries included
                  pipeline.png    - rendered from the drawio, embedded in the README
                  design.md       - why the implementation is shaped the way it is
                  development.md  - this file
```

`src/` is the payload, `terraform/` is the launcher: the Terraform provisions a
CodeBuild project whose source is this repository and whose buildspec invokes
`driftcode.detect` and `drift-authorize`.


## Develop

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Tests are offline and make no AWS calls.

## Run the stages directly

```bash
# what actually drifted
drift-reconcile --refresh-only refresh-only.plan.json --full-plan full.plan.json --out reconciled.json

# did we see everything, and is any of it codifiable
terraform providers schema -json > schema.json

# the policy scan needs a document that holds the live values
drift-project --refresh-only-plan refresh-only.plan.json --out drift-projection.plan.json
checkov -f drift-projection.plan.json --output json --quiet --soft-fail > checkov-drift.json
checkov -f full.plan.json           --output json --quiet --soft-fail > checkov-baseline.json

drift-gate-a --refresh-only-plan refresh-only.plan.json \
             --provider-schema schema.json \
             --reconciled reconciled.json \
             --checkov-result checkov-drift.json \
             --checkov-baseline checkov-baseline.json \
             --log terraform.log

# every terraform invocation runs THROUGH the guard, which execs the argv it checked
drift-tf-guard -chdir=/tmp/target plan -refresh-only   # checked, then executed
drift-tf-guard apply -refresh-only                     # rejected, never executed
drift-tf-guard --check-only plan                       # validate without running

# reduce it to a bounded work order, or escalate
drift-authorize --reconciled reconciled.json \
                --gate-a gate-a.json \
                --refresh-only-plan refresh-only.plan.json \
                --repo-root /tmp/target \
                --workspace-dir environments/dev \
                --workspace-id dev --repo acme/infra \
                --ledger-table drift-demo-observations \
                --build-number "$CODEBUILD_BUILD_NUMBER" \
                --out authorization.json

# check the agent's diff against that work order
git -C /tmp/target diff | drift-verify --authorization authorization.json \
                                       --diff - --out verification.json

# the agent's standing instruction, and the per-task prompt
drift-prompt --instruction                          # the model's standing system prompt
drift-prompt --authorization authorization.json     # one task per work order
```

`drift-authorize` exits 0 whether or not there is anything to codify — a quiet estate
is not a broken pipeline, and the caller reads `has_work`. `drift-verify` exits
non-zero on any violation, so a rejected diff never reaches a pull request.

Gate A exits non-zero when it cannot assert completeness, and it never claims
"fully reconciled" — only *reconciled over the observable projection*, with the
unobservable part enumerated.

## Fixtures

Two kinds, for two jobs.

`tests/plan_fixtures.py` is compact and hand-written, reproducing the shapes a real stack
produces. It is convenient to work with, and it is not independent evidence: it asserts the
same understanding of plan output that the code under test encodes.

`tests/fixtures/real-*.json` **is committed** — real `terraform show -json` output from an
applied stack, reduced and redacted by `tests/redact_plan.py`, and exercised on every run by
`test_real_fixtures.py`. Raw captures are gitignored; only redacted output is tracked.

Redaction is checked by an **allowlist over identifier shapes**, not by a list of known-bad
patterns. A scan built from the redactor's own pattern list can only catch the classes the
redactor already handles, which makes it a redactor marking its own homework. So anything
shaped like an AWS identifier must be a recognised placeholder, and anything else fails
whether or not the redactor knows about it.

See `tests/fixtures/README.md` to capture and redact your own.



## Packaging a second payload

`terraform/modules/source-package` turns a directory into a versioned S3 object. Call it
again against the shared bucket rather than standing up another one — a lifecycle rule set
for one consumer would otherwise apply to a payload it knows nothing about:

```hcl
module "agent_source" {
  source = "./modules/source-package"

  name       = "agent"
  bucket     = aws_s3_bucket.source[0].id # or var.source_bucket from another stack
  source_dir = local.implementation_root
  commit     = var.source_commit
  key_prefix = "payloads"

  excludes = ["terraform", "tests", "src/driftcode/detect"]
}
```

Each call versions independently, so changing the detection payload does not redeploy the
other. Grant read on `module.agent_source.object_arn` — per object, not per bucket, so one
consumer cannot read another's payload.
