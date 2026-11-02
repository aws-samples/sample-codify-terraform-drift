"""Detection stage: establish what actually drifted, and whether we saw everything.

``reconcile``  two-plan reconciliation - refresh-only alone over-reports drift
``gate_a``     fail-closed completeness assertions and schema classification
``tf_guard``   positive allowlist for Terraform invocations
"""
