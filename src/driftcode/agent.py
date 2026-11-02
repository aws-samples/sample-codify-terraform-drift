"""Drive a model through one codification, over the same tools the MCP server exposes.

There are two ways to reach the agent: a hosted MCP server that a managed runtime talks to,
and this - a direct Bedrock Converse loop. They must not be two authorization surfaces. So
this does not reimplement the tools; it drives :class:`driftcode.mcp.server.CodifySession`,
the same object, through the same dispatch. Whatever the model does here it could do there,
and both are bounded by the same refusals.

A second code path with its own idea of what is authorized is how a boundary quietly stops
being one, and it would be invisible in tests that only exercise the first path.

The loop itself is deliberately unglamorous:

  * the standing instruction is the system prompt, the rendered work order is the first message
  * a tool call is dispatched to the session and its result returned, including refusals -
    the model should see *why* it was refused and correct course, not receive silence
  * turns are capped, because a model that neither submits nor declines would otherwise spin
    at cost forever; hitting the cap is a failure, not a completion
  * nothing here writes anything. Verification and publication happen in
    ``CodifySession.complete``, which the loop cannot reach

The model's prose is never used as a result. It is recorded for the audit trail and otherwise
ignored: what happened is whatever the session staged, and what is reported is whatever the
verifier found.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from .mcp.server import TOOLS, CodifySession, ToolError, dispatch
from .prompt import INSTRUCTION, render_task

#: A model that neither submits nor declines is stuck. Six turns is generous for a task that
#: names the file, the line and the value; a higher cap buys nothing but spend.
DEFAULT_MAX_TURNS = 6

#: Sonnet is the default because the task is small and heavily constrained - the work is
#: matching a file's conventions, not reasoning about infrastructure.
#:
#: Pinned to a dated version rather than a floating alias, for the same reason the provider
#: schema and the Terraform version are pinned: this pipeline is supposed to produce the same
#: diff for the same drift, and a model that changes underneath it cannot promise that. The
#: cost is that a pinned model eventually goes legacy - Bedrock then refuses it with an error
#: naming the model rather than the configuration, so this value needs review, not neglect.
DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"


class ConverseClient(Protocol):
    """The one Bedrock call this needs, narrowed so tests can supply a fake."""

    def converse(self, **kwargs: Any) -> dict[str, Any]: ...


def tool_config() -> dict[str, Any]:
    """Advertise the session's tools in Converse's shape.

    Built from the MCP tool list rather than restated, so the two transports cannot drift
    apart in what they claim to offer.
    """
    return {
        "tools": [
            {
                "toolSpec": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "inputSchema": {"json": tool["inputSchema"]},
                }
            }
            for tool in TOOLS
        ]
    }


@dataclass
class Turn:
    """One exchange, kept for the audit trail."""

    index: int
    stop_reason: str
    text: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "turn": self.index,
            "stop_reason": self.stop_reason,
            "text": self.text,
            "tool_calls": self.tool_calls,
        }


@dataclass
class AgentRun:
    turns: list[Turn]
    stopped_because: str
    submitted: list[str]
    blocked_reason: str | None
    usage: dict[str, int]

    @property
    def reached_cap(self) -> bool:
        return self.stopped_because == "turn_cap"

    def as_dict(self) -> dict[str, Any]:
        return {
            "turns": [t.as_dict() for t in self.turns],
            "stopped_because": self.stopped_because,
            "submitted": self.submitted,
            "blocked_reason": self.blocked_reason,
            "usage": self.usage,
            "reached_turn_cap": self.reached_cap,
        }


def bedrock_client(region: str) -> ConverseClient:
    """Construct the Bedrock runtime client, importing boto3 lazily.

    Lazy so the package keeps working - and keeps being testable - without boto3 installed,
    the same reason the ledger's DynamoDB adapter defers its import.
    """
    try:
        import boto3  # noqa: PLC0415 - deliberately lazy
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "invoking the agent needs boto3; install the 'aws' extra (pip install '.[aws]')"
        ) from exc

    return boto3.client("bedrock-runtime", region_name=region)


def run(
    session: CodifySession,
    client: ConverseClient,
    model_id: str = DEFAULT_MODEL_ID,
    max_turns: int = DEFAULT_MAX_TURNS,
    temperature: float = 0.0,
) -> AgentRun:
    """Drive the model until it submits, declines, or runs out of turns.

    ``temperature`` defaults to 0: the task has one correct answer, and sampling variety
    across retries would make an idempotent pipeline produce different diffs for the same
    drift.
    """
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": [{"text": render_task(session.work_order)}]}
    ]
    turns: list[Turn] = []
    usage = {"inputTokens": 0, "outputTokens": 0}
    stopped_because = "turn_cap"

    for index in range(1, max_turns + 1):
        response = client.converse(
            modelId=model_id,
            system=[{"text": INSTRUCTION}],
            messages=messages,
            toolConfig=tool_config(),
            inferenceConfig={"temperature": temperature},
        )

        for key in usage:
            usage[key] += (response.get("usage") or {}).get(key, 0)

        output = (response.get("output") or {}).get("message") or {}
        content = output.get("content") or []
        stop_reason = response.get("stopReason", "")

        turn = Turn(index=index, stop_reason=stop_reason)
        turn.text = " ".join(block["text"] for block in content if "text" in block).strip()

        uses = [block["toolUse"] for block in content if "toolUse" in block]
        if not uses:
            # The model replied in prose without calling a tool. Nothing was staged, so the
            # run is over: its prose is not a result.
            turns.append(turn)
            stopped_because = "no_tool_use"
            break

        messages.append({"role": "assistant", "content": content})

        results = []
        for use in uses:
            name, arguments = use.get("name", ""), use.get("input") or {}
            try:
                payload = dispatch(session, name, arguments)
                text = payload["content"][0]["text"]
                status = "success"
            except ToolError as exc:
                # Returned to the model rather than raised. A refusal it cannot see is a
                # refusal it cannot correct.
                text, status = str(exc), "error"

            turn.tool_calls.append({"name": name, "input": arguments, "status": status})
            results.append(
                {
                    "toolResult": {
                        "toolUseId": use.get("toolUseId"),
                        "content": [{"text": text}],
                        "status": status,
                    }
                }
            )

        turns.append(turn)
        messages.append({"role": "user", "content": results})

        if session.blocked_reason is not None:
            stopped_because = "reported_blocked"
            break
        if session.authorized_files and not (session.authorized_files - set(session.submitted)):
            stopped_because = "submitted_all"
            break

    return AgentRun(
        turns=turns,
        stopped_because=stopped_because,
        submitted=sorted(session.submitted),
        blocked_reason=session.blocked_reason,
        usage=usage,
    )


def summary(agent_run: AgentRun) -> str:
    """One line for a build log. The transcript goes to the artifact, not the console."""
    calls = sum(len(t.tool_calls) for t in agent_run.turns)
    return (
        f"agent: {len(agent_run.turns)} turn(s), {calls} tool call(s), "
        f"stopped because {agent_run.stopped_because}; "
        f"{len(agent_run.submitted)} file(s) submitted; "
        f"{agent_run.usage['inputTokens']}+{agent_run.usage['outputTokens']} tokens"
    )


__all__ = [
    "DEFAULT_MAX_TURNS",
    "DEFAULT_MODEL_ID",
    "AgentRun",
    "Turn",
    "bedrock_client",
    "run",
    "summary",
    "tool_config",
]
