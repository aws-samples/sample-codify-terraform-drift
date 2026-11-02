"""Resolve a resource address to an exact file and block, deterministically.

This is the counterpart to sanitization, and the reason it works. The agent is told which
file, which block, and which attribute it may touch; it does not decide. That decision is
made here, by matching block headers in the checked-out source - no model involved, so
attacker-controlled values in the drift record cannot influence where an edit lands.

The matching rule is the resource *block header*, ``resource "<type>" "<name>"``, and an
instance index is stripped before searching. An instance address such as
``aws_instance.web["prod"]`` appears nowhere in source: the configuration declares one
block with a ``for_each``, so searching for the indexed string finds nothing while
searching for the block finds one that governs every key.

Ambiguity is a failure, not a guess. If a type/name pair appears in more than one file
within scope, this reports the conflict rather than picking one - a wrong file is worse
than no edit.

Only the standard library is used: an HCL parser would be a runtime dependency in a
worker that may be a bare image, and header matching is sufficient to find a block whose
address is already known.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: `module.compute.module.inner.aws_launch_template.app` ->
#: module path ['compute', 'inner'], type 'aws_launch_template', name 'app'
_ADDRESS = re.compile(
    r"^(?P<modules>(?:module\.[A-Za-z0-9_-]+\.)*)"
    r"(?P<type>[A-Za-z0-9_]+)\."
    r"(?P<name>[A-Za-z0-9_-]+)"
    r"(?P<index>\[[^\]]+\])?$"
)


@dataclass
class Target:
    """An authorized edit target. Anything outside this is rejected by the verifier."""

    file: str
    resource_type: str
    resource_name: str
    block_start_line: int
    block_end_line: int
    module_path: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "block_start_line": self.block_start_line,
            "block_end_line": self.block_end_line,
            "module_path": self.module_path,
        }


class LocateError(Exception):
    """Raised when a target cannot be established unambiguously."""


def parse_address(address: str) -> tuple[list[str], str, str]:
    """Split a resource address into module path, type and name, discarding any index."""
    match = _ADDRESS.match(address.strip())
    if not match:
        raise LocateError(f"unparseable resource address: {address!r}")
    modules = [m for m in match.group("modules").split(".") if m and m != "module"]
    return modules, match.group("type"), match.group("name")


def block_header(kind: str, *labels: str) -> re.Pattern[str]:
    """Match an HCL block header such as ``resource "type" "name" {`` or ``module "x" {``.

    Whitespace is flexible and either quote style is accepted, matching what HCL permits
    and what formatters produce.
    """
    parts = [r"^\s*", re.escape(kind)]
    for label in labels:
        parts.append(r"""\s+["']""" + re.escape(label) + r"""["']""")
    parts.append(r"\s*\{")
    return re.compile("".join(parts), re.M)


def block_extent(lines: list[str], start_index: int) -> int:
    """Return the 1-based line number closing the block that opens at ``start_index``.

    Brace counting that ignores braces inside strings and comments. Heredocs are handled
    by skipping to their terminator, since HCL bodies commonly contain policy JSON whose
    braces would otherwise unbalance the count.
    """
    depth = 0
    heredoc_terminator: str | None = None

    for offset, raw in enumerate(lines[start_index:], start=start_index):
        line = raw

        if heredoc_terminator is not None:
            if line.strip() == heredoc_terminator:
                heredoc_terminator = None
            continue

        heredoc = re.search(r"<<[-~]?\s*([A-Za-z_][A-Za-z0-9_]*)", line)
        if heredoc:
            heredoc_terminator = heredoc.group(1)
            # A heredoc opener can still close braces before the marker.
            line = line[: heredoc.start()]

        in_string = False
        escaped = False
        for char in line:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == "#":
                break
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return offset + 1

    raise LocateError("unterminated resource block; braces never balanced")


def _candidate_files(repo_root: Path, module_path: list[str]) -> list[Path]:
    """Terraform files to search, narrowed to a module directory when one is inferable.

    A module *call* name is not guaranteed to match its directory name, so a matching
    directory narrows the search and its absence widens it rather than failing.
    """
    if module_path:
        leaf = module_path[-1]
        for candidate in (repo_root / "modules" / leaf, repo_root / leaf):
            if candidate.is_dir():
                return sorted(candidate.rglob("*.tf"))
    return sorted(p for p in repo_root.rglob("*.tf") if ".terraform" not in p.parts)


def locate(address: str, repo_root: str | Path) -> Target:
    """Resolve a resource address to exactly one block in the checked-out source."""
    root = Path(repo_root)
    if not root.is_dir():
        raise LocateError(f"repository root is not a directory: {root}")

    module_path, resource_type, resource_name = parse_address(address)
    header = block_header("resource", resource_type, resource_name)

    matches: list[Target] = []
    for path in _candidate_files(root, module_path):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        lines = text.splitlines()
        for index, line in enumerate(lines):
            if not header.match(line):
                continue
            matches.append(
                Target(
                    file=str(path.relative_to(root)),
                    resource_type=resource_type,
                    resource_name=resource_name,
                    block_start_line=index + 1,
                    block_end_line=block_extent(lines, index),
                    module_path=module_path,
                )
            )

    if not matches:
        raise LocateError(
            f'no block matching resource "{resource_type}" "{resource_name}" found under {root}; '
            "reporting failure rather than guessing a location"
        )
    if len(matches) > 1:
        where = ", ".join(f"{m.file}:{m.block_start_line}" for m in matches)
        raise LocateError(
            f'resource "{resource_type}" "{resource_name}" is ambiguous - found in {where}; '
            "a wrong file is worse than no edit, so this requires human disambiguation"
        )

    return matches[0]
