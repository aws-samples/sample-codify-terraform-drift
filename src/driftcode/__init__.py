"""Drift-to-code reconciliation: detect valid Terraform drift and codify it as a PR.

The package is deliberately dependency-free at runtime. Everything under
``driftcode.detect`` runs inside a CodeBuild worker that may be a bare image, and the
reconciliation and gate logic are pure functions over plan JSON so they can be tested
offline against captured provider output.
"""

__version__ = "0.1.0"
