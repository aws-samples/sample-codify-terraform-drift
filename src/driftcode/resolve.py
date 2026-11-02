"""Trace a drifted attribute back to the source layer that supplies its value.

Knowing *which resource* drifted is not enough to know *what to edit*. The same attribute
can be a literal in the resource block, a value passed into a module, an entry in the
workspace's ``terraform.tfvars``, a default on a reusable module's variable, or something
supplied from outside the repository entirely. Those are different files with different
blast radii, and only some of them may be changed on the strength of drift observed in
one environment.

The distinction that matters is *how many consumers share the value*:

  * a literal in the resource block, a value passed in the caller's ``module`` block, or
    an entry in this workspace's own ``tfvars`` affects this workspace only - editable
  * a ``default`` on a variable inside a reusable module is shared by every caller, so
    codifying drift seen in one environment would silently change the others
  * a ``tfvars`` file outside the workspace directory is by construction shared
  * a value with no discoverable assignment comes from a ``-var`` flag, a ``TF_VAR_``
    environment variable, or the CI system - not editable from the repository at all

The first group is what the pattern codifies. The rest escalate. That boundary is
enforced in :mod:`driftcode.classify`; this module is what produces the evidence for it,
and without it every attribute resolves ``unknown`` and nothing is ever codified.

Resolution is textual and deterministic - no model, no provider, no network. Ambiguity
and anything unparsed resolve to a non-local layer, so the failure mode is escalation to
a human rather than an edit in the wrong file.

Only single, non-nested attributes assigned on one line are resolvable. A dotted path
into a nested block (``tag_specifications.0.tags.Name``) is a different edit shape than
an attribute line and is reported as such rather than approximated.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .locate import LocateError, block_extent, block_header, locate, parse_address

# --- layers ------------------------------------------------------------------------
#: Literal assigned directly in a resource block in the workspace's own root module.
RESOURCE_LITERAL = "resource_literal"
#: Literal assigned directly in a resource block inside a reusable module. Editing it
#: changes every caller of that module, not just this workspace, so it is not local.
MODULE_RESOURCE_LITERAL = "module_resource_literal"
#: Literal passed to the module in the caller's ``module`` block.
MODULE_INPUT = "module_input"
#: Entry in a ``tfvars`` file inside the workspace's own directory.
WORKSPACE_TFVARS = "workspace_tfvars"
#: ``default`` on a variable declared in the workspace's root module.
WORKSPACE_VARIABLE_DEFAULT = "workspace_variable_default"

#: ``default`` on a variable inside a reusable module - shared by every caller.
MODULE_VARIABLE_DEFAULT = "module_variable_default"
#: ``tfvars`` file outside the workspace directory.
SHARED_TFVARS = "shared_tfvars"
#: Declared variable with no assignment in the repository (-var, TF_VAR_, or CI).
EXTERNAL_VARIABLE = "external_variable"
#: Interpolation, function call, or reference to local./data./module. output.
EXPRESSION = "expression"
#: Dotted path into a nested block rather than a single attribute line.
NESTED_ATTRIBUTE = "nested_attribute"
#: Resolution failed. Deliberately terminal: unknown is never treated as safe.
UNKNOWN = "unknown"

#: Layers whose value is consumed by this workspace alone.
WORKSPACE_LOCAL_LAYERS = frozenset(
    {RESOURCE_LITERAL, MODULE_INPUT, WORKSPACE_TFVARS, WORKSPACE_VARIABLE_DEFAULT}
)

#: Depth cap on variable-to-caller recursion. Terraform forbids module cycles, but the
#: input here is untrusted text and a cap costs nothing.
MAX_HOPS = 8

#: Why each non-local layer is refused, for the escalation message. Kept beside the layer
#: definitions so a new layer cannot be added without deciding what to say about it.
NON_LOCAL_REASONS: dict[str, str] = {
    MODULE_RESOURCE_LITERAL: "the literal is inside a reusable module, so editing it "
    "changes the value for every workspace that calls that module, not just this one",
    MODULE_VARIABLE_DEFAULT: "the value is a default inside a reusable module, so it is "
    "shared by every workspace that calls that module",
    SHARED_TFVARS: "the value comes from a tfvars file outside this workspace, which other "
    "estates also consume",
    EXTERNAL_VARIABLE: "the value is supplied from outside the repository, by -var, a "
    "TF_VAR_ environment variable or the CI system, so no file edit can change it",
    EXPRESSION: "the value is produced by an expression, so there is no single literal to "
    "replace",
    NESTED_ATTRIBUTE: "the path addresses a value inside a nested block, which is a "
    "different edit than replacing an attribute's value",
    UNKNOWN: "the value's source could not be traced in the checked-out configuration",
}


def explain(layer: str) -> str:
    """Why a layer is not editable from this workspace. Unrecognised layers are refused."""
    if layer in WORKSPACE_LOCAL_LAYERS:
        return f"'{layer}' is local to this workspace"
    return NON_LOCAL_REASONS.get(
        layer, f"'{layer}' is not a recognised source layer, and unrecognised is not safe"
    )

_ASSIGNMENT = re.compile(r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(?P<rhs>\S.*?)\s*$")
_VAR_REF = re.compile(r"^var\.(?P<name>[A-Za-z_][A-Za-z0-9_-]*)$")
_NUMBER = re.compile(r"^-?\d+(?:\.\d+)?$")
_HEREDOC = re.compile(r"<<[-~]?\s*(?P<marker>[A-Za-z_][A-Za-z0-9_]*)")
_BOOLEANS = frozenset({"true", "false"})


@dataclass
class Hop:
    """One step in the resolution chain, kept for the audit trail on the pull request."""

    kind: str
    detail: str
    file: str | None = None
    line: int | None = None
    expression: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "file": self.file,
            "line": self.line,
            "expression": self.expression,
        }


@dataclass
class Resolution:
    """Where an attribute's value comes from, and where it would have to be edited."""

    attribute: str
    layer: str
    reason: str
    edit_file: str | None = None
    edit_line: int | None = None
    #: Identifier assigned on the edit line. It is not always the drifted attribute name:
    #: a value traced to tfvars is assigned there under the *variable's* name, and a
    #: variable default is assigned under the name ``default``. The verifier checks the
    #: edited line against this, so getting it from the trace rather than assuming the
    #: attribute name is what makes the containment check correct.
    edit_name: str | None = None
    expression: str | None = None
    chain: list[Hop] = field(default_factory=list)

    @property
    def is_workspace_local(self) -> bool:
        return self.layer in WORKSPACE_LOCAL_LAYERS

    def as_dict(self) -> dict[str, Any]:
        return {
            "attribute": self.attribute,
            "layer": self.layer,
            "reason": self.reason,
            "edit_file": self.edit_file,
            "edit_line": self.edit_line,
            "edit_name": self.edit_name,
            "expression": self.expression,
            "workspace_local": self.is_workspace_local,
            "chain": [h.as_dict() for h in self.chain],
        }


@dataclass
class _Step:
    """Internal result of one resolution step: a layer plus, when known, an edit site."""

    layer: str
    reason: str
    path: Path | None = None
    line: int | None = None
    expression: str | None = None
    name: str | None = None


# --- HCL text handling -------------------------------------------------------------


def strip_comment(line: str) -> str:
    """Remove a trailing ``#`` or ``//`` comment, ignoring occurrences inside strings."""
    out: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            out.append(char)
            escaped = True
        elif char == '"':
            in_string = not in_string
            out.append(char)
        elif not in_string and char == "#":
            break
        elif not in_string and char == "/" and line[index + 1 : index + 2] == "/":
            break
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _brace_delta(code: str) -> int:
    """Net brace depth change for a line, ignoring braces inside strings.

    Interpolation markers are inside strings by definition, so ``"${var.x}-suffix"``
    contributes nothing - which is why a nested block can be skipped reliably.
    """
    depth = 0
    in_string = False
    escaped = False
    for char in code:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            in_string = not in_string
        elif in_string:
            continue
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return depth


def top_level_assignments(lines: list[str], start_index: int, end_line: int) -> Iterator[tuple[int, str, str]]:
    """Yield ``(line_number, name, expression)`` for assignments in a block's own body.

    Assignments inside nested blocks are skipped: they belong to a different attribute
    path and editing one because a sibling drifted would be wrong.
    """
    depth = 0
    heredoc: str | None = None

    for index in range(start_index, min(end_line, len(lines))):
        raw = lines[index]

        if heredoc is not None:
            if raw.strip() == heredoc:
                heredoc = None
            continue

        code = strip_comment(raw)
        opener = _HEREDOC.search(code)
        if opener:
            heredoc = opener.group("marker")
            code = code[: opener.start()]

        if depth == 1:
            match = _ASSIGNMENT.match(code)
            if match:
                yield index + 1, match.group("name"), match.group("rhs").strip()

        depth += _brace_delta(code)


def is_literal(expression: str) -> bool:
    """Whether an expression is a constant with no references and no interpolation.

    Conservative by design. A multi-line list, a map, a concatenation or anything else
    not recognised here is reported as non-literal, which escalates rather than edits.
    """
    text = expression.strip().rstrip(",")
    if not text:
        return False
    if text in _BOOLEANS or _NUMBER.match(text):
        return True
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        inner = text[1:-1]
        if "${" in inner:
            return False
        # A second unescaped quote means this is not one string - a concatenation or a
        # comparison, neither of which is a value that can be edited in place.
        return not re.search(r'(?<!\\)"', inner)
    if text.startswith("[") and text.endswith("]"):
        elements = [e.strip() for e in text[1:-1].split(",") if e.strip()]
        return bool(elements) and all(is_literal(e) for e in elements)
    return False


_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


def literal_value(expression: str) -> tuple[bool, Any]:
    """Parse a constant expression into the Python value it denotes.

    Returns ``(False, None)`` for anything :func:`is_literal` rejects. The verifier
    compares values rather than text with this, so an edit that changes only quoting,
    alignment or a trailing comment is accepted while one that changes the value is not.
    """
    text = expression.strip().rstrip(",")
    if not is_literal(text):
        return False, None

    if text == "true":
        return True, True
    if text == "false":
        return True, False
    if _NUMBER.match(text):
        return True, float(text) if "." in text else int(text)

    if text[0] == '"':
        out: list[str] = []
        index = 1
        while index < len(text) - 1:
            char = text[index]
            if char == "\\" and index + 1 < len(text) - 1:
                out.append(_ESCAPES.get(text[index + 1], text[index + 1]))
                index += 2
                continue
            out.append(char)
            index += 1
        return True, "".join(out)

    values = []
    for element in (e.strip() for e in text[1:-1].split(",")):
        if not element:
            continue
        ok, value = literal_value(element)
        if not ok:
            return False, None
        values.append(value)
    return True, values


def _tf_files(directory: Path) -> list[Path]:
    """``.tf`` files declared directly in a directory - a Terraform module is flat."""
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.tf") if p.is_file())


def _find_block(files: list[Path], header: re.Pattern[str]) -> list[tuple[Path, list[str], int, int]]:
    """Locate every occurrence of a block header, with its extent."""
    found: list[tuple[Path, list[str], int, int]] = []
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for index, line in enumerate(lines):
            if header.match(line):
                try:
                    end = block_extent(lines, index)
                except LocateError:
                    continue
                found.append((path, lines, index, end))
    return found


# --- tfvars ------------------------------------------------------------------------


def _tfvars_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    names = sorted(
        p
        for p in directory.iterdir()
        if p.is_file() and (p.name.endswith(".tfvars") or p.name.endswith(".tfvars.json"))
    )
    return names


def tfvars_assignment(name: str, directory: Path) -> tuple[Path, int, str] | None:
    """Find ``name``'s assignment in a ``tfvars`` file in ``directory``.

    Later files win, matching how repeated ``-var-file`` arguments behave, so the last
    match is returned rather than the first.
    """
    hit: tuple[Path, int, str] | None = None
    for path in _tfvars_files(directory):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        if path.name.endswith(".json"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and name in data:
                # A JSON document has no meaningful line for a key; report the file only.
                hit = (path, 0, json.dumps(data[name]))
            continue

        for index, raw in enumerate(text.splitlines()):
            match = _ASSIGNMENT.match(strip_comment(raw))
            if match and match.group("name") == name:
                hit = (path, index + 1, match.group("rhs").strip())
    return hit


def _shared_tfvars_assignment(
    name: str, repo_root: Path, workspace_dir: Path
) -> tuple[Path, int, str] | None:
    """Find ``name`` assigned in a ``tfvars`` file outside the workspace directory."""
    workspace = workspace_dir.resolve()
    for path in sorted(repo_root.rglob("*.tfvars*")):
        if ".terraform" in path.parts or not path.is_file():
            continue
        if path.parent.resolve() == workspace:
            continue
        hit = tfvars_assignment(name, path.parent)
        if hit:
            return hit
    return None


def variable_default(name: str, directory: Path) -> tuple[Path, int, str] | None:
    """Find the ``default`` on ``variable "name"`` declared in ``directory``."""
    blocks = _find_block(_tf_files(directory), block_header("variable", name))
    if len(blocks) != 1:
        # No declaration, or a duplicate one that Terraform itself would reject.
        return None
    path, lines, start, end = blocks[0]
    for line_number, key, expression in top_level_assignments(lines, start, end):
        if key == "default":
            return path, line_number, expression
    return None


# --- resolution --------------------------------------------------------------------


def _relative(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _resolve_root_variable(
    name: str,
    repo_root: Path,
    workspace_dir: Path,
    chain: list[Hop],
) -> _Step:
    """Resolve a root-module variable to its value's layer and edit site.

    Precedence follows Terraform's: a ``tfvars`` entry overrides a declared default.
    """
    local = tfvars_assignment(name, workspace_dir)
    if local:
        path, line, expression = local
        chain.append(
            Hop("workspace_tfvars", f"var.{name}", _relative(path, repo_root), line, expression)
        )
        return _Step(
            WORKSPACE_TFVARS,
            f"var.{name} is set in {_relative(path, repo_root)}, which belongs to this "
            "workspace alone",
            path,
            line,
            expression,
            name,
        )

    shared = _shared_tfvars_assignment(name, repo_root, workspace_dir)
    if shared:
        path, line, expression = shared
        chain.append(
            Hop("shared_tfvars", f"var.{name}", _relative(path, repo_root), line, expression)
        )
        return _Step(
            SHARED_TFVARS,
            f"var.{name} is set in {_relative(path, repo_root)}, outside this workspace; "
            "editing it would change the estates that also consume that file",
            path,
            line,
            expression,
            name,
        )

    default = variable_default(name, workspace_dir)
    if default:
        path, line, expression = default
        chain.append(
            Hop("variable_default", f"var.{name}", _relative(path, repo_root), line, expression)
        )
        if not is_literal(expression):
            return _Step(
                EXPRESSION,
                f"var.{name} defaults to a non-literal expression, which has no single "
                "value to replace",
                path,
                line,
                expression,
                "default",
            )
        return _Step(
            WORKSPACE_VARIABLE_DEFAULT,
            f"var.{name} defaults in this workspace's root module and no tfvars overrides "
            "it, so the default is the effective value for this workspace only",
            path,
            line,
            expression,
            "default",
        )

    chain.append(Hop("external", f"var.{name} has no assignment in the repository"))
    return _Step(
        EXTERNAL_VARIABLE,
        f"var.{name} has no value in the repository; it is supplied by -var, a TF_VAR_ "
        "environment variable, or the CI system, so no file edit can change it",
    )


def _module_call_block(
    module_path: list[str], repo_root: Path, workspace_dir: Path
) -> tuple[Path, list[str], int, int] | None:
    """Find the ``module`` block that instantiates the innermost module in a path.

    A depth-one module is called from the workspace root module, which is where the search
    starts. Deeper nesting falls back to a repository-wide search and gives up if the call
    name is not unique, since guessing which caller applies would risk the wrong file.
    """
    if not module_path:
        return None
    header = block_header("module", module_path[-1])

    if len(module_path) == 1:
        blocks = _find_block(_tf_files(workspace_dir), header)
        if len(blocks) == 1:
            return blocks[0]
        return None

    candidates = [p for p in sorted(repo_root.rglob("*.tf")) if ".terraform" not in p.parts]
    blocks = _find_block(candidates, header)
    return blocks[0] if len(blocks) == 1 else None


def _resolve_variable(
    name: str,
    module_path: list[str],
    repo_root: Path,
    workspace_dir: Path,
    module_dir: Path,
    chain: list[Hop],
    hops: int,
) -> _Step:
    """Resolve ``var.name`` as seen from inside the module at ``module_path``."""
    if hops > MAX_HOPS:
        return _Step(UNKNOWN, f"variable resolution exceeded {MAX_HOPS} hops")

    if not module_path:
        return _resolve_root_variable(name, repo_root, workspace_dir, chain)

    call = _module_call_block(module_path, repo_root, workspace_dir)
    if call is None:
        chain.append(Hop("module_call", f"call to module.{module_path[-1]} not resolvable"))
        return _Step(
            UNKNOWN,
            f"the module block instantiating module.{module_path[-1]} could not be "
            "identified unambiguously",
        )

    call_path, call_lines, call_start, call_end = call
    for line_number, key, expression in top_level_assignments(call_lines, call_start, call_end):
        if key != name:
            continue

        chain.append(
            Hop(
                "module_input",
                f"module.{module_path[-1]}.{name}",
                _relative(call_path, repo_root),
                line_number,
                expression,
            )
        )

        if is_literal(expression):
            return _Step(
                MODULE_INPUT,
                f"the value is a literal in the module block in "
                f"{_relative(call_path, repo_root)}, which this workspace owns",
                call_path,
                line_number,
                expression,
                name,
            )

        forwarded = _VAR_REF.match(expression)
        if forwarded:
            return _resolve_variable(
                forwarded.group("name"),
                module_path[:-1],
                repo_root,
                workspace_dir,
                call_path.parent,
                chain,
                hops + 1,
            )

        return _Step(
            EXPRESSION,
            f"the module input is the expression {expression!r}, which has no single "
            "literal to replace",
            call_path,
            line_number,
            expression,
            name,
        )

    default = variable_default(name, module_dir)
    if default:
        path, line, expression = default
        chain.append(
            Hop("module_variable_default", f"var.{name}", _relative(path, repo_root), line, expression)
        )
        return _Step(
            MODULE_VARIABLE_DEFAULT,
            f"no caller passes {name}, so the value is the default in "
            f"{_relative(path, repo_root)}; that module is shared, and editing the default "
            "would change every workspace that calls it",
            path,
            line,
            expression,
            "default",
        )

    chain.append(Hop("external", f"var.{name} is neither passed nor defaulted"))
    return _Step(
        UNKNOWN,
        f"var.{name} is neither passed by the caller nor defaulted in the module",
    )


def resolve_attribute(
    address: str,
    attribute: str,
    repo_root: str | Path,
    workspace_dir: str | Path | None = None,
) -> Resolution:
    """Trace one drifted attribute of one resource to the layer that supplies its value.

    ``workspace_dir`` is the root module Terraform was run against - the directory passed
    to ``-chdir``. It is what makes "local to this workspace" a decidable question, so
    when it is omitted the repository root is assumed to be the root module.
    """
    root = Path(repo_root)
    workspace = Path(workspace_dir) if workspace_dir is not None else root
    chain: list[Hop] = []

    if "." in attribute:
        return Resolution(
            attribute=attribute,
            layer=NESTED_ATTRIBUTE,
            reason="a dotted path addresses a value inside a nested block, which is a "
            "different edit than replacing an attribute's value and is not attempted",
        )

    try:
        target = locate(address, root)
    except LocateError as exc:
        return Resolution(attribute=attribute, layer=UNKNOWN, reason=str(exc))

    resource_file = root / target.file
    chain.append(
        Hop("resource_block", address, target.file, target.block_start_line)
    )

    try:
        lines = resource_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        return Resolution(
            attribute=attribute,
            layer=UNKNOWN,
            reason=f"could not read {target.file}: {exc}",
            chain=chain,
        )

    assignment: tuple[int, str] | None = None
    for line_number, key, expression in top_level_assignments(
        lines, target.block_start_line - 1, target.block_end_line
    ):
        if key == attribute:
            assignment = (line_number, expression)

    if assignment is None:
        return Resolution(
            attribute=attribute,
            layer=UNKNOWN,
            reason=f"{attribute} is not assigned in the {address} block; the live value "
            "comes from a provider default, so there is no expression to trace",
            chain=chain,
        )

    line_number, expression = assignment
    chain.append(Hop("attribute", attribute, target.file, line_number, expression))

    if is_literal(expression):
        # A literal is only workspace-local if the block holding it is in the workspace's own
        # root module. The same literal inside a reusable module is shared by every caller of
        # that module - exactly like MODULE_VARIABLE_DEFAULT below - so the test has to be
        # "which module is this block in", not "is this value a literal". Getting this wrong
        # is not a cosmetic mislabel: in a repository where two environments call the same
        # module, one environment's drift would be written into the other's configuration.
        module_path, _, _ = parse_address(address)
        if module_path:
            return Resolution(
                attribute=attribute,
                layer=MODULE_RESOURCE_LITERAL,
                reason=f"assigned a literal in {target.file}, which belongs to module "
                f"{'.'.join(module_path)} rather than this workspace's root module; "
                + NON_LOCAL_REASONS[MODULE_RESOURCE_LITERAL],
                expression=expression,
                chain=chain,
            )
        if resource_file.parent.resolve() != workspace.resolve():
            # No module path, yet the file is not in the root module directory. Terraform
            # does not produce this from an ordinary layout, so the address and the checkout
            # disagree about where the resource lives and the safe reading is "not local".
            return Resolution(
                attribute=attribute,
                layer=MODULE_RESOURCE_LITERAL,
                reason=f"{target.file} is outside the root module directory "
                f"{_relative(workspace, root)}, so the block it holds is not known to be "
                "local to this workspace",
                expression=expression,
                chain=chain,
            )
        return Resolution(
            attribute=attribute,
            layer=RESOURCE_LITERAL,
            reason=f"assigned a literal in {target.file}, in this workspace's own root "
            "module, which no other workspace reads",
            edit_file=target.file,
            edit_line=line_number,
            edit_name=attribute,
            expression=expression,
            chain=chain,
        )

    reference = _VAR_REF.match(expression)
    if not reference:
        return Resolution(
            attribute=attribute,
            layer=EXPRESSION,
            reason=f"assigned the expression {expression!r}; interpolations, function calls "
            "and references to locals, data sources or module outputs have no single "
            "literal to replace",
            edit_file=target.file,
            edit_line=line_number,
            edit_name=attribute,
            expression=expression,
            chain=chain,
        )

    step = _resolve_variable(
        reference.group("name"),
        target.module_path,
        root,
        workspace,
        resource_file.parent,
        chain,
        hops=1,
    )

    return Resolution(
        attribute=attribute,
        layer=step.layer,
        reason=step.reason,
        edit_file=_relative(step.path, root) if step.path is not None else None,
        edit_line=step.line,
        edit_name=step.name,
        expression=step.expression,
        chain=chain,
    )


def resolve_attributes(
    address: str,
    attributes: list[str],
    repo_root: str | Path,
    workspace_dir: str | Path | None = None,
) -> list[Resolution]:
    return [resolve_attribute(address, a, repo_root, workspace_dir) for a in attributes]


def source_layers(
    address: str,
    attributes: list[str],
    repo_root: str | Path,
    workspace_dir: str | Path | None = None,
) -> dict[str, str]:
    """The attribute-to-layer mapping :func:`driftcode.classify.classify_resource` expects."""
    return {r.attribute: r.layer for r in resolve_attributes(address, attributes, repo_root, workspace_dir)}
