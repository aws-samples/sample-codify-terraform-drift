"""Read Checkov output without assuming its shape.

Checkov's JSON is a single object when one runner reports and a **list of objects** when
more than one does, which depends on the frameworks it detects rather than on anything the
caller controls. Code that assumes the object form raises ``AttributeError`` on a list, and
a crash inside a security gate is a bad failure even when it happens to fail the build: the
operator gets a stack trace instead of a verdict.

Both readers go through here so the two cannot disagree about the shape.
"""

from __future__ import annotations

from typing import Any


def sections(document: Any) -> list[dict[str, Any]]:
    """Normalize Checkov output to a list of result sections."""
    if document is None:
        return []
    if isinstance(document, list):
        return [s for s in document if isinstance(s, dict)]
    if isinstance(document, dict):
        return [document]
    return []


def failed_checks(document: Any) -> list[dict[str, Any]]:
    """Every failed check across all sections."""
    out: list[dict[str, Any]] = []
    for section in sections(document):
        checks = ((section.get("results") or {}).get("failed_checks")) or []
        out += [c for c in checks if isinstance(c, dict)]
    return out


def failure_keys(document: Any) -> set[tuple[str, str]]:
    """Failed checks as ``(check_id, resource)`` pairs, for before/after comparison."""
    return {
        (c.get("check_id", ""), c.get("resource", "")) for c in failed_checks(document)
    }


def evaluated_checks(document: Any) -> int:
    """How many checks Checkov actually ran, passed and failed together.

    Zero is not the same as clean. Checkov's ``terraform_plan`` framework builds its
    resource graph from ``planned_values``, and a ``plan -refresh-only`` document has an
    empty ``planned_values`` - the refreshed live values live in ``prior_state`` and
    ``resource_drift`` instead. Pointed at one, Checkov reports 0 passed and 0 failed:
    it evaluated nothing. A gate that reads only the failure count cannot tell that apart
    from a clean estate, and reports a pass on a scan that never happened.
    """
    total = 0
    for section in sections(document):
        results = section.get("results") or {}
        for bucket in ("passed_checks", "failed_checks"):
            total += len(results.get(bucket) or [])
    return total
