"""Check the agent's diff against the work order that authorized it.

An agent that writes code needs a reviewer that is not an agent. This is it. The work
order named one file and one line per attribute and the value expected there; this module
reads the actual diff and refuses anything else. It is the reason the agent's output can
be trusted without trusting the agent: a prompt injection that succeeded in changing the
model's behaviour still has to produce a diff that passes here, and a diff that touches
another file, another line, another attribute or another value does not.

Every check is a containment check, and all of them fail closed:

  * only files named in the work orders may appear in the diff
  * every removed line must be an authorized line, and every change must be a replacement
    of one line by one line - an insertion or a deletion is not a codified value
  * the identifier assigned on the line must be unchanged, and must be the one the work
    order named. That is not always the attribute's name: a value traced to ``tfvars`` is
    assigned there under the variable's name
  * the new value must equal the value observed in the cloud. Comparison is on parsed
    values, not text, so re-quoting or realignment is fine and a different value is not
  * no ``lifecycle`` or ``ignore_changes`` may be introduced. That would silence the drift
    rather than codify it, which is the one outcome that looks like success in every
    downstream signal while leaving the estate unreconciled
  * new files, deletions, renames and mode changes are refused outright

A rejection carries the reason, so the failure is reviewable rather than a bare refusal.
Diff parsing is stdlib only, on the same reasoning as the rest of the detection package.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any

from .policy import failure_keys
from .resolve import literal_value, strip_comment

ACCEPT = "accept"
REJECT = "reject"

_DIFF_GIT = re.compile(r"^diff --git a/(?P<old>.+?) b/(?P<new>.+)$")
_OLD_FILE = re.compile(r"^--- (?:a/)?(?P<path>.+?)(?:\t.*)?$")
_NEW_FILE = re.compile(r"^\+\+\+ (?:b/)?(?P<path>.+?)(?:\t.*)?$")
_HUNK = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)
_ASSIGNMENT = re.compile(r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(?P<rhs>\S.*?)\s*$")

#: Anything that suppresses drift instead of codifying it. Rejected wherever it is added.
_SUPPRESSION = re.compile(r"\bignore_changes\b|\blifecycle\b")

#: Git metadata lines that mean the change is not an in-place edit of a tracked file.
_STRUCTURAL = re.compile(
    r"^(new file mode|deleted file mode|rename from|rename to|copy from|copy to|old mode|new mode)\b"
)


@dataclass
class FileDiff:
    """One file's changes: which lines were removed, and which were added."""

    path: str
    removed: list[tuple[int, str]] = field(default_factory=list)
    added: list[tuple[int, str]] = field(default_factory=list)
    structural: list[str] = field(default_factory=list)


def parse_unified_diff(text: str) -> list[FileDiff]:
    """Parse a unified diff into per-file line changes with their line numbers.

    Line numbers matter: containment is checked against the line the work order named, so
    a change to the right attribute on the wrong line is still a rejection.
    """
    files: list[FileDiff] = []
    current: FileDiff | None = None
    old_line = new_line = 0

    for raw in text.splitlines():
        header = _DIFF_GIT.match(raw)
        if header:
            current = FileDiff(path=header.group("new"))
            files.append(current)
            old_line = new_line = 0
            continue

        if current is not None and _STRUCTURAL.match(raw):
            current.structural.append(raw.strip())
            continue

        if raw.startswith("--- "):
            match = _OLD_FILE.match(raw)
            if match and current is not None and match.group("path") == "/dev/null":
                current.structural.append("added file")
            continue

        if raw.startswith("+++ "):
            match = _NEW_FILE.match(raw)
            if match is None:
                continue
            path = match.group("path")
            if current is None:
                current = FileDiff(path=path)
                files.append(current)
            if path == "/dev/null":
                current.structural.append("deleted file")
            elif current.path in ("", "/dev/null"):
                current.path = path
            continue

        hunk = _HUNK.match(raw)
        if hunk:
            old_line = int(hunk.group("old_start"))
            new_line = int(hunk.group("new_start"))
            continue

        if current is None or not raw:
            continue

        marker, body = raw[0], raw[1:]
        if marker == "-":
            current.removed.append((old_line, body))
            old_line += 1
        elif marker == "+":
            current.added.append((new_line, body))
            new_line += 1
        elif marker in (" ", "\\"):
            if marker == " ":
                old_line += 1
                new_line += 1

    return files


def _assignment(line: str) -> tuple[str, str] | None:
    match = _ASSIGNMENT.match(strip_comment(line))
    if not match:
        return None
    return match.group("name"), match.group("rhs").strip()


def _expected_values(order: dict[str, Any]) -> dict[str, Any]:
    """Attribute path to the value observed in the cloud, as carried in the work order."""
    return {
        a.get("path"): a.get("observed_value_in_cloud")
        for a in ((order.get("drift") or {}).get("attributes") or [])
    }


def _sites_by_file(work_orders: list[dict[str, Any]]) -> dict[str, dict[int, dict[str, Any]]]:
    """Index every authorized site by file and line, carrying its expected value."""
    index: dict[str, dict[int, dict[str, Any]]] = {}
    for order in work_orders:
        expected = _expected_values(order)
        for site in order.get("edit_sites") or []:
            path, line = site.get("file"), site.get("line")
            if not path or not line:
                continue
            index.setdefault(path, {})[line] = {
                **site,
                "resource_address": order.get("resource_address"),
                "expected_value": expected.get(site.get("attribute")),
            }
    return index


def verify(
    diff_text: str,
    authorization: dict[str, Any],
    checkov_before: dict[str, Any] | None = None,
    checkov_after: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Accept or reject a diff against the authorization that produced it."""
    work_orders = list(authorization.get("work_orders") or [])
    index = _sites_by_file(work_orders)
    violations: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    #: Sites the diff tried to change. A site that failed a check is already reported, so
    #: it is not also reported as unmade - one cause, one violation.
    attempted: set[tuple[str, int]] = set()

    files = parse_unified_diff(diff_text)

    if not work_orders:
        if files:
            violations.append(
                {
                    "kind": "unauthorized_change",
                    "detail": "the diff changes files but no work order authorized any edit",
                    "files": [f.path for f in files],
                }
            )
        return _result(violations, verified, files)

    if not files:
        violations.append(
            {
                "kind": "empty_diff",
                "detail": f"{len(work_orders)} work order(s) were authorized but the diff is "
                "empty; an unmade edit is a failure, not a safe outcome",
            }
        )
        return _result(violations, verified, files)

    for file_diff in files:
        sites = index.get(file_diff.path)

        if file_diff.structural:
            violations.append(
                {
                    "kind": "structural_change",
                    "file": file_diff.path,
                    "detail": "a work order authorizes editing lines, not "
                    + ", ".join(sorted(set(file_diff.structural))),
                }
            )
            continue

        if sites is None:
            violations.append(
                {
                    "kind": "unauthorized_file",
                    "file": file_diff.path,
                    "detail": "no work order authorizes any edit in this file",
                }
            )
            continue

        for line_number, body in file_diff.added:
            if _SUPPRESSION.search(strip_comment(body)):
                violations.append(
                    {
                        "kind": "drift_suppression",
                        "file": file_diff.path,
                        "line": line_number,
                        "detail": "introduces lifecycle/ignore_changes, which hides the drift "
                        "instead of codifying it",
                    }
                )

        if len(file_diff.removed) != len(file_diff.added):
            violations.append(
                {
                    "kind": "not_a_replacement",
                    "file": file_diff.path,
                    "detail": f"{len(file_diff.removed)} line(s) removed and "
                    f"{len(file_diff.added)} added; codifying a value replaces one line "
                    "with one line",
                }
            )
            continue

        for (old_line, old_body), (new_line, new_body) in zip(file_diff.removed, file_diff.added):
            attempted.add((file_diff.path, old_line))
            violations += _check_replacement(file_diff.path, sites, old_line, old_body, new_body, verified)

    seen = {(v["file"], v["line"]) for v in verified} | attempted
    for path, sites in index.items():
        for line, site in sites.items():
            if (path, line) not in seen:
                violations.append(
                    {
                        "kind": "unmade_edit",
                        "file": path,
                        "line": line,
                        "detail": f"{site['attribute']} was authorized but the diff does not "
                        "change it",
                    }
                )

    if checkov_before is not None and checkov_after is not None:
        for finding in new_checkov_findings(checkov_before, checkov_after):
            violations.append(
                {
                    "kind": "new_policy_finding",
                    "detail": f"{finding['check_id']} on {finding['resource']} is not present "
                    "before the change; codifying drift must not introduce a policy failure",
                    **finding,
                }
            )

    return _result(violations, verified, files)


def _check_replacement(
    path: str,
    sites: dict[int, dict[str, Any]],
    old_line: int,
    old_body: str,
    new_body: str,
    verified: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate one removed/added line pair against the site authorized at that line."""
    site = sites.get(old_line)
    if site is None:
        return [
            {
                "kind": "unauthorized_line",
                "file": path,
                "line": old_line,
                "detail": "changed a line no work order authorized; authorized lines here are "
                + ", ".join(str(n) for n in sorted(sites)),
            }
        ]

    old = _assignment(old_body)
    new = _assignment(new_body)
    if old is None or new is None:
        return [
            {
                "kind": "not_an_assignment",
                "file": path,
                "line": old_line,
                "detail": "the replaced line is not an attribute assignment, so this is not a "
                "value change",
            }
        ]

    old_name, _ = old
    new_name, new_expression = new
    expected_name = site.get("assigned_name") or site.get("attribute")

    if old_name != new_name:
        return [
            {
                "kind": "renamed_assignment",
                "file": path,
                "line": old_line,
                "detail": f"the assignment changed from {old_name} to {new_name}; only the "
                "value may change",
            }
        ]

    if new_name != expected_name:
        return [
            {
                "kind": "wrong_attribute",
                "file": path,
                "line": old_line,
                "detail": f"changed {new_name}, but the work order authorizes {expected_name}",
            }
        ]

    parsed, value = literal_value(new_expression)
    if not parsed:
        return [
            {
                "kind": "non_literal_value",
                "file": path,
                "line": old_line,
                "detail": f"the new value {new_expression!r} is not a literal; codifying drift "
                "writes the observed value, not an expression",
            }
        ]

    expected = site.get("expected_value")
    if not _values_match(value, expected):
        return [
            {
                "kind": "wrong_value",
                "file": path,
                "line": old_line,
                "detail": f"wrote {value!r} but the observed cloud value is {expected!r}",
            }
        ]

    verified.append(
        {
            "file": path,
            "line": old_line,
            "attribute": site.get("attribute"),
            "resource_address": site.get("resource_address"),
            "value": value,
        }
    )
    return []


def _values_match(written: Any, expected: Any) -> bool:
    """Compare a written literal against a plan value.

    Numeric types are compared by value, since a plan can carry ``1`` where the
    configuration carries ``1.0`` and neither is a different instruction. Booleans are
    kept distinct from integers so ``true`` cannot satisfy ``1``.
    """
    if isinstance(written, bool) or isinstance(expected, bool):
        return written is expected
    if isinstance(written, (int, float)) and isinstance(expected, (int, float)):
        return float(written) == float(expected)
    if isinstance(written, list) and isinstance(expected, list):
        return len(written) == len(expected) and all(
            _values_match(w, e) for w, e in zip(written, expected)
        )
    return written == expected


def new_checkov_findings(
    before: dict[str, Any], after: dict[str, Any]
) -> list[dict[str, str]]:
    """Findings present after the change and absent before it.

    Compared as a set difference rather than by count: a change that fixes one finding and
    introduces another leaves the count unchanged while making the estate worse.
    """
    return [
        {"check_id": check_id, "resource": resource}
        for check_id, resource in sorted(failure_keys(after) - failure_keys(before))
    ]


def _result(
    violations: list[dict[str, Any]],
    verified: list[dict[str, Any]],
    files: list[FileDiff],
) -> dict[str, Any]:
    return {
        "verdict": REJECT if violations else ACCEPT,
        "violations": violations,
        "verified_edits": verified,
        "files_changed": [f.path for f in files],
        "counts": {
            "violations": len(violations),
            "verified_edits": len(verified),
            "files_changed": len(files),
        },
    }


def _load(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an agent's diff against the work order that authorized it"
    )
    parser.add_argument("--authorization", required=True, help="output of drift-authorize")
    parser.add_argument(
        "--diff", required=True, help="unified diff of the agent's branch, or - for stdin"
    )
    parser.add_argument("--checkov-before", help="checkov JSON for the unmodified checkout")
    parser.add_argument("--checkov-after", help="checkov JSON for the modified checkout")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    diff_text = sys.stdin.read() if args.diff == "-" else open(args.diff, encoding="utf-8").read()

    result = verify(
        diff_text,
        _load(args.authorization),
        _load(args.checkov_before) if args.checkov_before else None,
        _load(args.checkov_after) if args.checkov_after else None,
    )

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)

    if result["verdict"] == ACCEPT:
        print(
            f"Verification: ACCEPT — {result['counts']['verified_edits']} authorized edit(s), "
            "nothing else changed",
            file=sys.stderr,
        )
        for edit in result["verified_edits"]:
            print(f"  {edit['file']}:{edit['line']} {edit['attribute']} = {edit['value']!r}", file=sys.stderr)
        return 0

    print(f"Verification: REJECT — {result['counts']['violations']} violation(s)", file=sys.stderr)
    for violation in result["violations"]:
        location = violation.get("file", "")
        if violation.get("line"):
            location = f"{location}:{violation['line']}"
        print(f"  [{violation['kind']}] {location} {violation['detail']}", file=sys.stderr)

    # Non-zero fails the build. A rejected diff must never reach a pull request.
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
