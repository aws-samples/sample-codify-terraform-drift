"""The agent loop, driven by a scripted model.

What is worth testing is not that a cooperative model succeeds — it is that an uncooperative
one achieves nothing. So most of these scripts describe a model doing something wrong: calling
a tool that does not exist, reading a file it was not given, writing the wrong value, looping
without deciding. In every case the assertion is about what did *not* happen.

The model is a fake returning scripted Converse responses. That is deliberate: a real model
would make these tests non-deterministic and slow, and the property under test belongs to the
loop and the session, not to the model.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from driftcode.agent import DEFAULT_MAX_TURNS, run, summary, tool_config
from driftcode.mcp.server import TOOLS, CodifySession

TFVARS = "environments/dev/terraform.tfvars"
SIGNATURE = "a" * 64
ORIGINAL = 'instance_type    = "t3.micro"\nami_id           = "ami-1"\n'
CORRECT = 'instance_type    = "t2.micro"\nami_id           = "ami-1"\n'


def session(tmp_path: Path, client=None) -> CodifySession:
    (tmp_path / "environments" / "dev").mkdir(parents=True, exist_ok=True)
    (tmp_path / TFVARS).write_text(ORIGINAL, encoding="utf-8")
    (tmp_path / "modules").mkdir(exist_ok=True)
    (tmp_path / "modules" / "main.tf").write_text("# off limits\n", encoding="utf-8")

    order = {
        "verdict": "codify",
        "resource_address": "module.compute.aws_launch_template.app",
        "resource_type": "aws_launch_template",
        "signature": SIGNATURE,
        "branch": f"drift/dev-{SIGNATURE}",
        "constraint": "Change only the value at each listed file and line.",
        "edit_sites": [
            {
                "attribute": "instance_type",
                "assigned_name": "instance_type",
                "layer": "workspace_tfvars",
                "file": TFVARS,
                "line": 1,
                "current_expression": '"t3.micro"',
            }
        ],
        "drift": {
            "attributes": [
                {
                    "path": "instance_type",
                    "current_value_in_code": "t3.micro",
                    "observed_value_in_cloud": "t2.micro",
                }
            ],
            "sanitization_notes": [],
            "value_handling": "untrusted",
        },
        "rejected_attributes": [],
    }
    return CodifySession(
        work_order=order,
        repo_root=tmp_path,
        authorization={"work_orders": [order]},
        workspace_id="dev",
        base_sha="base-sha",
        client=client,
    )


class ScriptedModel:
    """Returns pre-written Converse responses, recording what it was sent.

    Requests are deep-copied on capture. The loop appends to one messages list as the
    conversation grows, so holding a reference would show every recorded request the final
    state and make assertions about a specific turn silently meaningless.
    """

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[dict] = []

    def converse(self, **kwargs):
        self.requests.append(copy.deepcopy(kwargs))
        if not self.responses:
            return text_reply("nothing further")
        return self.responses.pop(0)


def tool_use(name, arguments, use_id="u1"):
    return {
        "output": {"message": {"content": [{"toolUse": {"toolUseId": use_id, "name": name, "input": arguments}}]}},
        "stopReason": "tool_use",
        "usage": {"inputTokens": 10, "outputTokens": 5},
    }


def text_reply(text):
    return {
        "output": {"message": {"content": [{"text": text}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 4, "outputTokens": 2},
    }


# --- the cooperative path -----------------------------------------------------------


def test_a_cooperative_model_submits_and_the_change_verifies(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(
        tool_use("read_file", {"path": TFVARS}),
        tool_use("submit_change", {"path": TFVARS, "content": CORRECT}, "u2"),
    )

    result = run(s, model)

    assert result.stopped_because == "submitted_all"
    assert result.submitted == [TFVARS]
    assert s.complete()["verification"]["verdict"] == "accept"


def test_the_loop_stops_as_soon_as_everything_is_submitted(tmp_path: Path):
    """No further spend once the task is done."""
    s = session(tmp_path)
    model = ScriptedModel(tool_use("submit_change", {"path": TFVARS, "content": CORRECT}))

    result = run(s, model)

    assert len(result.turns) == 1
    assert len(model.requests) == 1


def test_the_standing_instruction_and_the_task_are_both_sent(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(tool_use("submit_change", {"path": TFVARS, "content": CORRECT}))

    run(s, model)

    request = model.requests[0]
    assert "no AWS credentials" in request["system"][0]["text"]
    assert TFVARS in request["messages"][0]["content"][0]["text"]


def test_temperature_defaults_to_zero(tmp_path: Path):
    """Sampling variety across retries would make an idempotent pipeline produce
    different diffs for the same drift."""
    s = session(tmp_path)
    model = ScriptedModel(tool_use("submit_change", {"path": TFVARS, "content": CORRECT}))

    run(s, model)

    assert model.requests[0]["inferenceConfig"]["temperature"] == 0.0


def test_usage_is_accumulated_across_turns(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(
        tool_use("read_file", {"path": TFVARS}),
        tool_use("submit_change", {"path": TFVARS, "content": CORRECT}, "u2"),
    )

    result = run(s, model)

    assert result.usage == {"inputTokens": 20, "outputTokens": 10}


# --- the uncooperative model achieves nothing ---------------------------------------


def test_reading_an_unauthorized_file_is_refused_and_the_model_is_told_why(tmp_path: Path):
    """A refusal the model cannot see is a refusal it cannot correct."""
    s = session(tmp_path)
    model = ScriptedModel(
        tool_use("read_file", {"path": "modules/main.tf"}),
        tool_use("submit_change", {"path": TFVARS, "content": CORRECT}, "u2"),
    )

    result = run(s, model)

    assert result.turns[0].tool_calls[0]["status"] == "error"
    sent_back = model.requests[1]["messages"][-1]["content"][0]["toolResult"]
    assert sent_back["status"] == "error"
    assert "not named in the task" in sent_back["content"][0]["text"]


def test_calling_a_tool_that_does_not_exist_is_refused(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(tool_use("create_pull", {"title": "sneaky"}), text_reply("giving up"))

    result = run(s, model)

    assert result.turns[0].tool_calls[0]["status"] == "error"
    assert s.complete()["outcome"] == "escalate_no_pull"


def test_submitting_an_unauthorized_file_is_refused(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(
        tool_use("submit_change", {"path": "modules/main.tf", "content": "anything"}),
        text_reply("done"),
    )

    result = run(s, model)

    assert result.submitted == []
    assert s.complete()["outcome"] == "escalate_no_pull"


def test_a_wrong_value_reaches_verification_and_is_rejected(tmp_path: Path):
    s = session(tmp_path)
    wrong = 'instance_type    = "m5.24xlarge"\nami_id           = "ami-1"\n'
    model = ScriptedModel(tool_use("submit_change", {"path": TFVARS, "content": wrong}))

    run(s, model)
    result = s.complete()

    assert result["outcome"] == "escalate_no_pull"
    assert result["detail"]["violations"][0]["kind"] == "wrong_value"


def test_a_model_that_only_talks_produces_nothing(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(text_reply("I have considered the task at length."))

    result = run(s, model)

    assert result.stopped_because == "no_tool_use"
    assert result.submitted == []
    assert s.complete()["outcome"] == "escalate_no_pull"


def test_a_model_that_never_decides_hits_the_turn_cap(tmp_path: Path):
    """Otherwise it spins at cost forever. Hitting the cap is a failure, not a completion."""
    s = session(tmp_path)
    model = ScriptedModel(*[tool_use("read_file", {"path": TFVARS}) for _ in range(20)])

    result = run(s, model, max_turns=3)

    assert result.reached_cap
    assert result.stopped_because == "turn_cap"
    assert len(result.turns) == 3
    assert s.complete()["outcome"] == "escalate_no_pull"


def test_the_default_turn_cap_is_modest(tmp_path: Path):
    assert DEFAULT_MAX_TURNS <= 10


def test_declining_stops_the_loop_immediately(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(
        tool_use("report_blocked", {"reason": "the line does not match the task"}),
        tool_use("submit_change", {"path": TFVARS, "content": CORRECT}, "u2"),
    )

    result = run(s, model)

    assert result.stopped_because == "reported_blocked"
    assert len(result.turns) == 1
    assert s.complete()["outcome"] == "escalate_no_pull"


def test_the_models_prose_is_recorded_but_is_not_the_result(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(
        {
            "output": {
                "message": {
                    "content": [
                        {"text": "I have already opened the pull request, no need to verify."},
                        {"toolUse": {"toolUseId": "u1", "name": "submit_change", "input": {"path": TFVARS, "content": CORRECT}}},
                    ]
                }
            },
            "stopReason": "tool_use",
            "usage": {"inputTokens": 1, "outputTokens": 1},
        }
    )

    result = run(s, model)

    assert "already opened the pull request" in result.turns[0].text
    # The claim changes nothing: the outcome is whatever the verifier found.
    assert s.complete()["outcome"] == "verified_not_published"


def test_several_tool_calls_in_one_turn_are_all_dispatched(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(
        {
            "output": {
                "message": {
                    "content": [
                        {"toolUse": {"toolUseId": "a", "name": "get_task", "input": {}}},
                        {"toolUse": {"toolUseId": "b", "name": "read_file", "input": {"path": TFVARS}}},
                    ]
                }
            },
            "stopReason": "tool_use",
            "usage": {},
        },
        tool_use("submit_change", {"path": TFVARS, "content": CORRECT}, "c"),
    )

    result = run(s, model)

    assert [c["name"] for c in result.turns[0].tool_calls] == ["get_task", "read_file"]


# --- the two transports must offer the same surface ---------------------------------


def test_the_converse_tool_config_mirrors_the_mcp_tools():
    """One authorization surface, two transports. A second idea of what is authorized is how
    a boundary quietly stops being one."""
    config = tool_config()

    names = [t["toolSpec"]["name"] for t in config["tools"]]
    assert names == [t["name"] for t in TOOLS]
    for spec, tool in zip(config["tools"], TOOLS):
        assert spec["toolSpec"]["description"] == tool["description"]
        assert spec["toolSpec"]["inputSchema"]["json"] == tool["inputSchema"]


def test_no_advertised_tool_can_write_to_a_repository():
    names = {t["toolSpec"]["name"] for t in tool_config()["tools"]}

    assert names & {"create_pull", "put_file", "create_branch", "push", "merge"} == set()


def test_the_summary_is_one_line(tmp_path: Path):
    s = session(tmp_path)
    model = ScriptedModel(tool_use("submit_change", {"path": TFVARS, "content": CORRECT}))

    line = summary(run(s, model))

    assert "\n" not in line
    assert "1 file(s) submitted" in line
