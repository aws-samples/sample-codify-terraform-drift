# Plan fixtures

Two kinds, for two different jobs.

## `real-refresh-only.json`, `real-full-plan.json` — committed, always run

Real `terraform show -json` output from an applied nine-resource stack with exactly one
induced drift, reduced and redacted by `../redact_plan.py`. `test_real_fixtures.py` runs
against these on every invocation of the suite.

They exist because the rest of the suite runs on fixtures written alongside the logic they
exercise, which checks internal consistency — and the assumptions here were wrong twice in
ways only real output revealed:

- a `plan -refresh-only` reports provider *representation normalization* as drift, with the
  same `actions: ["update"]` as a real change (four reported, one real)
- its `planned_values` is **empty**, and it has no `resource_changes` key at all, so a
  plan-based policy scanner evaluates zero resources and reports a clean result

**What redaction changes:** account IDs, IAM role and user unique IDs, ARNs, AMI and other
resource IDs, and the caller's session alias — each replaced with a stable placeholder. The
`configuration` and `relevant_attributes` sections are dropped; no test reads them and they
dominate the file size.

**What it does not change:** structure, attribute names, actions, the `null` versus `[]`
distinctions, and which resources appear in `resource_drift` versus `resource_changes`.
Those are the properties under test, so normalizing them would recreate the problem these
files exist to solve.

`test_real_fixtures.py` re-scans both files for every identifier pattern on every run. A
regression in the redactor fails the build rather than shipping.

## `plan_fixtures.py` — synthetic, hand-written

Compact documents in `../plan_fixtures.py`, used by the unit tests. They reproduce the
shapes observed above without the bulk, so a test can state its case in a few lines. They
are not independent evidence, and are not treated as such.

## Capturing your own

Anything else you drop in this directory is gitignored.

```bash
cd <your-terraform-workspace>

# A) locked refresh-only plan  (state -> live)
terraform plan -refresh-only -out=refresh.tfplan
terraform show -json refresh.tfplan > refresh-only.plan.json

# B) full plan                 (live -> config)
terraform plan -out=full.tfplan
terraform show -json full.tfplan > full.plan.json
```

To turn a capture into a committable fixture:

```bash
python tests/redact_plan.py refresh-only.plan.json tests/fixtures/real-refresh-only.json
python tests/redact_plan.py full.plan.json         tests/fixtures/real-full-plan.json
pytest tests/test_real_fixtures.py     # includes the leak scan
```

Read the leak-scan results before committing. The redactor covers the identifier shapes this
estate produced; another estate may embed something it does not yet know about — a hostname,
an owner email in a tag, an account alias in a bucket name.
