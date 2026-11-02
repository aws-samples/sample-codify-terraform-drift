"""The MCP server the agent talks to — and the reason the agent needs no credentials.

The obvious way to build this is a thin wrapper over the GitHub API: expose
``create_branch``, ``put_file``, ``create_pull`` as tools and let the model orchestrate them.
That is a mistake, even though it looks reasonable.

A tool surface is an authorization surface. If the agent can call ``create_pull``, then a
prompt-injected agent can open a pull request containing whatever it likes, and the verifier
becomes advisory — something that ran earlier and can be routed around, rather than something
the change must pass through. The deterministic boundary would exist on paper and not in the
call graph.

So the tools here are **semantic, not mechanical**. The agent gets:

  * ``get_task``       — re-read the work order it is bound to
  * ``read_file``      — but only files the work order names
  * ``submit_change``  — propose new contents for an authorized file
  * ``report_blocked`` — decline, which is a legitimate outcome

Nothing in that list writes to GitHub. ``submit_change`` stages a change and runs it through
:mod:`driftcode.verify` against the work order the server holds; the write only happens after
that passes, and it happens in the server's own code path. There is no tool that skips it.
The agent cannot name a file outside the work order, cannot reach a second repository, and
cannot see the plan output.

The server holds the work order, the checkout, the verifier and the GitHub credential. The
agent holds a task and a text editor's worth of capability. That asymmetry is the whole
security argument, and it is enforced here rather than requested in a prompt.

Transport is JSON-RPC over stdio, which is what an MCP host expects and what makes this
runnable under a hosted runtime without change.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..prompt import render_task
from ..verify import ACCEPT, verify
from .github import AdoptionConflict, GitHub, GitHubError
from .publish import FileEdit, escalate_without_pull, publish

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "driftcode-codify"

#: Advertised to the host. Descriptions are part of the interface: the agent reads them, so
#: they state the boundary rather than merely naming the parameters.
TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_task",
        "description": (
            "Return the codification task: the resource, the authorized attributes, and for "
            "each one the exact file, line and value to write. This is the whole of your "
            "instruction; nothing outside it is authorized."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_file",
        "description": (
            "Read a file from the checkout. Only files named in the task can be read; any "
            "other path is refused. Use this to see the exact text and indentation of the "
            "line you are about to change."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Repository-relative path."}},
            "required": ["path"],
        },
        },
    {
        "name": "submit_change",
        "description": (
            "Submit the full new contents of an authorized file. The change is checked "
            "against the task before anything is written: only the authorized line may "
            "differ, the identifier on it must be unchanged, and the value must equal the "
            "one observed in the cloud. A change that does not match is rejected and "
            "reported, and nothing is written. Submit each authorized file once."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string", "description": "Complete new file contents."},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "report_blocked",
        "description": (
            "Report that the task cannot be carried out as written — the line does not say "
            "what the task says, the file is missing, or the instruction is ambiguous. This "
            "is a correct outcome and is preferred over guessing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"],
        },
    },
]


#: Outcomes after which the session is closed. Reaching any of them is terminal: the change
#: has either been written or refused, and in both cases further staging must not be accepted.
#: Without this a session could accept a second edit *after* verification passed, which would
#: mean the diff that was checked is not the diff that gets written.
TERMINAL_OUTCOMES = frozenset(
    {"published", "verified_not_published", "publication_failed", "escalate_no_pull"}
)


class ToolError(Exception):
    """A refusal the agent is told about, as opposed to a server fault."""


@dataclass
class CodifySession:
    """One work order, one checkout, one bounded set of permitted operations."""

    work_order: dict[str, Any]
    repo_root: Path
    authorization: dict[str, Any]
    workspace_id: str
    base_branch: str = "main"
    base_sha: str = ""
    deployed_commit: str = ""
    gate_results: dict[str, Any] | None = None
    #: Injected so the session is testable without GitHub, and so a dry run can hold none.
    client: GitHub | None = None

    submitted: dict[str, str] = field(default_factory=dict)
    #: Every submission in order, including superseded ones. The verifier only ever sees the
    #: final content, but a reviewer should be able to see that the agent changed its mind.
    submissions: list[dict[str, Any]] = field(default_factory=list)
    blocked_reason: str | None = None
    result: dict[str, Any] | None = None

    @property
    def concluded(self) -> bool:
        return bool(self.result and self.result.get("outcome") in TERMINAL_OUTCOMES)

    @property
    def authorized_files(self) -> set[str]:
        return {s["file"] for s in self.work_order.get("edit_sites") or [] if s.get("file")}

    def _refuse_if_concluded(self, what: str) -> None:
        if self.concluded:
            raise ToolError(
                f"this session has already concluded as {self.result['outcome']!r}; {what} is "
                "no longer accepted. The change that was verified is the change that was "
                "written, and a later edit would break that correspondence."
            )

    # --- tools -------------------------------------------------------------------

    def get_task(self) -> str:
        return render_task(self.work_order)

    def read_file(self, path: str) -> str:
        """Read an authorized file. Path traversal and unauthorized files are refused."""
        if path not in self.authorized_files:
            raise ToolError(
                f"{path!r} is not named in the task. Readable files are: "
                f"{', '.join(sorted(self.authorized_files))}. Reading anything else is not "
                "authorized, and editing it would be rejected anyway."
            )

        try:
            # resolve() follows symlinks, so an authorized path that is a link out of the
            # checkout is caught here rather than read.
            resolved = (self.repo_root / path).resolve()
            inside = resolved.is_relative_to(self.repo_root.resolve())
        except (OSError, ValueError) as exc:
            # A null byte, an unreadable parent, or a resolution loop. Reported as a refusal
            # rather than allowed to surface as a server fault.
            raise ToolError(f"{path!r} cannot be resolved within the checkout: {exc}") from exc

        if not inside:
            # Defence in depth: the allowlist above already excludes this, but a path that
            # escapes the checkout is worth failing on explicitly rather than relying on one
            # check.
            raise ToolError(f"{path!r} resolves outside the checkout")
        if not resolved.is_file():
            raise ToolError(f"{path!r} does not exist in the checkout")

        return resolved.read_text(encoding="utf-8")

    def submit_change(self, path: str, content: str) -> dict[str, Any]:
        """Stage new contents for an authorized file, refusing an unauthorized path.

        Re-submitting a file replaces the previous staging. That is deliberate - an agent
        correcting itself is legitimate - but every submission is recorded, so a superseded
        one is visible rather than lost.
        """
        self._refuse_if_concluded("submitting a change")

        if path not in self.authorized_files:
            raise ToolError(
                f"{path!r} is not named in the task, so a change to it cannot be submitted. "
                f"Authorized files: {', '.join(sorted(self.authorized_files))}"
            )

        superseded = path in self.submitted
        self.submitted[path] = content
        self.submissions.append(
            {"path": path, "superseded_previous": superseded, "characters": len(content)}
        )

        remaining = sorted(self.authorized_files - set(self.submitted))
        return {
            "accepted_for_verification": path,
            "replaced_earlier_submission": superseded,
            "still_to_submit": remaining,
            "note": (
                "Staged. Nothing is written until every authorized file is submitted and the "
                "whole change passes verification against the task."
                if remaining
                else "All authorized files submitted; verification will run now."
            ),
        }

    def report_blocked(self, reason: str) -> dict[str, Any]:
        self._refuse_if_concluded("reporting blocked")
        self.blocked_reason = reason
        return {
            "recorded": True,
            "note": "Reported for human attention. Nothing was written, which is correct.",
        }

    # --- what the agent cannot reach --------------------------------------------

    def complete(self) -> dict[str, Any]:
        """Verify the staged change and, only if it passes, write it.

        Called by the orchestrator once the agent's turn ends — never by the agent. That is
        the point: the write is not reachable from the tool surface, so an agent that ignores
        every instruction still cannot produce a pull request.

        Idempotent. A second call returns the first outcome rather than publishing again: a
        retry belongs at the pipeline level, where the branch and signature make it converge,
        not here where it would re-commit and re-label.
        """
        if self.concluded:
            return self.result  # type: ignore[return-value]

        if self.blocked_reason is not None:
            self.result = escalate_without_pull(
                self.work_order, f"agent reported blocked: {self.blocked_reason}"
            )
            return self.result

        missing = sorted(self.authorized_files - set(self.submitted))
        if missing:
            self.result = escalate_without_pull(
                self.work_order,
                "the agent did not submit every authorized file",
                {"missing": missing},
            )
            return self.result

        diff = self._diff()
        verification = verify(diff, self.authorization)

        if verification["verdict"] != ACCEPT:
            # Deliberately no pull request. A failed gate opens a labelled one because the
            # drift is real and dangerous; a failed verification means the change is not the
            # change the work order authorized, so it has no standing to be reviewed.
            self.result = escalate_without_pull(
                self.work_order,
                "the submitted change did not match the work order",
                {"violations": verification["violations"]},
            )
            return self.result

        if self.client is None:
            self.result = {
                "outcome": "verified_not_published",
                "verification": verification,
                "note": "No GitHub client configured; verification passed but nothing written.",
            }
            return self.result

        try:
            published = publish(
                self.client,
                self.work_order,
                [FileEdit(path=p, content=c) for p, c in sorted(self.submitted.items())],
                self.base_branch,
                self.base_sha,
                self.workspace_id,
                gate_results=self.gate_results,
                verification=verification,
                deployed_commit=self.deployed_commit,
            )
        except (AdoptionConflict, GitHubError) as exc:
            # Kept distinct from a verification failure, because the remediation differs and
            # conflating them would mislead whoever reads this. The change was correct; the
            # write did not land. Retrying is safe - the branch and signature make publication
            # converge - whereas a rejected diff must never be retried as-is.
            self.result = {
                "outcome": "publication_failed",
                "verification": verification,
                "error": str(exc),
                "error_type": type(exc).__name__,
                "retryable": not isinstance(exc, AdoptionConflict),
                "note": (
                    "The change passed verification but could not be published. The drift is "
                    "still live and nothing is in front of a human."
                ),
            }
            return self.result

        self.result = {"outcome": "published", "verification": verification, **published.as_dict()}
        return self.result

    def _diff(self) -> str:
        """Unified diff of the staged contents against the checkout.

        Produced here rather than taken from the agent: a diff the agent supplied would be a
        claim about its own edit, and the verifier's job is to check the edit, not the claim.
        """
        import difflib

        chunks: list[str] = []
        for path, content in sorted(self.submitted.items()):
            before = (self.repo_root / path).read_text(encoding="utf-8").splitlines(keepends=True)
            after = content.splitlines(keepends=True)
            patch = "".join(
                difflib.unified_diff(before, after, fromfile=f"a/{path}", tofile=f"b/{path}")
            )
            if patch:
                chunks.append(f"diff --git a/{path} b/{path}\n{patch}")
        return "".join(chunks)


# --- JSON-RPC plumbing --------------------------------------------------------------


def dispatch(session: CodifySession, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Route a tools/call. Unknown tools are refused rather than ignored."""
    handlers: dict[str, Callable[..., Any]] = {
        "get_task": lambda: session.get_task(),
        "read_file": lambda: session.read_file(arguments["path"]),
        "submit_change": lambda: session.submit_change(arguments["path"], arguments["content"]),
        "report_blocked": lambda: session.report_blocked(arguments["reason"]),
    }

    handler = handlers.get(name)
    if handler is None:
        raise ToolError(
            f"no tool named {name!r}. Available: {', '.join(sorted(handlers))}. There is "
            "deliberately no tool that writes to a repository."
        )

    try:
        value = handler()
    except KeyError as exc:
        raise ToolError(f"missing required argument {exc.args[0]!r} for {name}") from exc

    text = value if isinstance(value, str) else json.dumps(value, indent=2, sort_keys=True)
    return {"content": [{"type": "text", "text": text}]}


def handle(session: CodifySession, message: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC message. Returns None for notifications."""
    method = message.get("method")
    request_id = message.get("id")

    def ok(result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    if method == "initialize":
        return ok(
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": "0.1.0"},
            }
        )

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "tools/list":
        return ok({"tools": TOOLS})

    if method == "tools/call":
        params = message.get("params") or {}
        try:
            return ok(dispatch(session, params.get("name", ""), params.get("arguments") or {}))
        except ToolError as exc:
            # Reported as tool output with isError, not as a protocol error: the agent should
            # see the refusal and its reason so it can correct course.
            return ok({"content": [{"type": "text", "text": str(exc)}], "isError": True})

    if method == "ping":
        return ok({})

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def serve(session: CodifySession, stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin and reply on stdout."""
    source = stdin or sys.stdin
    sink = stdout or sys.stdout

    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            sink.write(
                json.dumps(
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
                )
                + "\n"
            )
            sink.flush()
            continue

        response = handle(session, message)
        if response is not None:
            sink.write(json.dumps(response) + "\n")
            sink.flush()


__all__ = [
    "PROTOCOL_VERSION",
    "SERVER_NAME",
    "TOOLS",
    "TERMINAL_OUTCOMES",
    "CodifySession",
    "GitHubError",
    "ToolError",
    "dispatch",
    "handle",
    "serve",
]
