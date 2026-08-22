"""Phase 3 tests: llm fallback, agent pipeline, budgets, degrade."""

import json

import pytest

from aegis.agents.pipeline import AgentPipeline
from aegis.agents.reasoning import AGENTS, ReasoningAgent
from aegis.integrations.llm import LLMClient, LLMResult


class FakeLLM(LLMClient):
    """Stand-in for llama.cpp. Deterministic responses; no network."""

    def __init__(self, responses: dict | None = None, fail: bool = False,
                 bad_json: bool = False) -> None:
        self._responses = responses or {}
        self._fail = fail
        self._bad_json = bad_json
        self._calls: list[tuple] = []

    def complete_json(self, system: str, user: str, temperature: float = 0.0) -> LLMResult:
        if self._fail:
            raise RuntimeError("offline")  # simulate server down path (caught in _call)
        if self._bad_json:
            return LLMResult(ok=False, data={}, raw="not json",
                             degraded=True, error="unparseable")
        data = {"summary": "test", "evidence_ids": ["ev_1"], "confidence": 0.5,
                "classification": "benign", "investigate": False, "severity": "low"}
        return LLMResult(ok=True, data=data, raw=json.dumps(data))


class FailingLLM(LLMClient):
    def __init__(self) -> None:
        pass

    def complete_json(self, system, user, temperature=0.0) -> LLMResult:
        return LLMResult(ok=False, data={}, raw="", degraded=True, error="server down")


def test_llm_client_requires_url():
    with pytest.raises(ValueError):
        LLMClient(base_url="", model="x")


def test_llm_format_correction_pass():
    """Parse failure on attempt 1 -> attempt 2 carries corrective instruction."""

    class LiteralThenJSON(LLMClient):
        def __init__(self):
            self.prompts = []

        def _call(self, system, user, temperature):
            self.prompts.append(user)
            if len(self.prompts) == 1:
                # nested single quotes -> invalid as JSON AND Python literal
                return "{'classification': 'benign', 'reason': 'failed both 'a' and 'b' params'}"
            return '{"classification": "benign", "reason": "ok"}'

    llm = LiteralThenJSON()
    r = llm.complete_json("sys", "user prompt")
    assert r.ok is True
    assert r.data["classification"] == "benign"
    assert "not valid strict JSON" in llm.prompts[1]


def test_agent_pipeline_all_steps_ok():
    llm = FakeLLM()
    pipe = AgentPipeline(llm)
    steps, results = pipe.run({"incident_id": "inc-1"}, {})
    assert len(steps) == len(AGENTS) == 5
    assert all(s.ok for s in steps)
    assert set(results) == set(AGENTS)


def test_pipeline_degrades_and_stops():
    llm = FailingLLM()
    pipe = AgentPipeline(llm)
    steps, results = pipe.run({"incident_id": "inc-1"}, {})
    # first agent degrades -> pipeline stops, no autonomous action
    assert steps[0].degraded is True
    assert not any(s.ok for s in steps)
    assert len(steps) == 1


def test_reasoning_agent_output_schema():
    llm = FakeLLM()
    agent = ReasoningAgent("A1", llm)
    r = agent.run({"incident_id": "inc-1"})
    assert r.ok
    assert "evidence_ids" in r.data


def test_pipeline_time_budget_enforced():
    import time

    class SlowLLM(LLMClient):
        def __init__(self) -> None:
            pass

        def complete_json(self, system, user, temperature=0.0) -> LLMResult:
            time.sleep(0.6)
            return LLMResult(ok=True, data={"summary": "s"}, raw='{"summary":"s"}')

    pipe = AgentPipeline(SlowLLM(), budgets={
        "steps_per_agent": 1, "tool_calls_per_incident": 50, "time_per_agent_ms": 100,
    })
    steps, _ = pipe.run({"incident_id": "inc-1"}, {})
    assert steps[0].degraded is True
    assert steps[0].error == "time budget exceeded"


def test_unknown_agent_rejected():
    llm = FakeLLM()
    with pytest.raises(ValueError):
        ReasoningAgent("A9", llm)


def test_extract_json_strips_think_and_fences():
    from aegis.integrations.llm import _extract_json

    assert json.loads(_extract_json("<think>reason</think>{\"a\": 1}")) == {"a": 1}
    assert json.loads(_extract_json("```json\n{\"b\": [1, 2]}\n```")) == {"b": [1, 2]}
    assert json.loads(_extract_json("prefix {\"c\": {\"d\": \"x\"}} trail")) == {"c": {"d": "x"}}
    # models batch two tool calls in one reply -> first object wins
    assert json.loads(_extract_json(
        "{\"tool\": \"a\"} {\"tool\": \"b\"}"
    )) == {"tool": "a"}
    # Python-literal style (single quotes) observed from Ornith
    assert json.loads(_extract_json(
        "{'classification': 'benign', 'severity': 'low', 'n': 1}"
    )) == {"classification": "benign", "severity": "low", "n": 1}
    # contraction inside single-quoted value (A3 live failure)
    assert json.loads(_extract_json(
        "{'summary': 'the process doesn't exist', 'hypotheses': []}"
    )) == {"summary": "the process doesn\u2019t exist", "hypotheses": []}
    with pytest.raises(ValueError):
        _extract_json("")


# -- agentic loop (debt #2) --

FINAL_A2 = {"summary": "s", "hypotheses": [], "evidence_ids": ["ev_1"],
            "open_questions": []}


class ScriptedLLM(LLMClient):
    """Pops scripted responses per call; records prompts."""

    def __init__(self, script: list[dict]) -> None:
        self._script = list(script)
        self.prompts: list[str] = []

    def complete_json(self, system, user, temperature=0.0) -> LLMResult:
        self.prompts.append(user)
        return LLMResult(ok=True, data=self._script.pop(0), raw="{}")


@pytest.fixture
def reg():
    from aegis.tools.registry import build_read_tools
    from aegis.tools.telemetry import InMemoryTelemetry, TelemetryEvent

    events = [
        TelemetryEvent(event_id="1", channel="sysmon", action="ProcessCreate",
                       host="win-vm", process_name="powershell.exe",
                       process_pid="100", process_parent="winword.exe",
                       command_line="powershell -enc SQBFAFA="),
        TelemetryEvent(event_id="3", channel="sysmon", action="NetworkConnect",
                       host="win-vm", process_name="powershell.exe",
                       process_pid="100", destination_ip="185.220.101.4"),
    ]
    return build_read_tools(InMemoryTelemetry(events))


def test_agentic_uses_tool_then_finalizes(reg):
    llm = ScriptedLLM([
        {"tool": "get_process_tree", "args": {"host": "win-vm"}},
        dict(FINAL_A2),
    ])
    r = ReasoningAgent("A2", llm).run({"incident_id": "inc-1"}, registry=reg)
    assert r.ok is True
    assert r.tool_calls == 1
    # second prompt must contain the observation from the real tool result
    assert "powershell.exe" in llm.prompts[1]
    assert "Observation 1" in llm.prompts[1]


def test_agentic_unauthorized_tool_observed_not_fatal(reg):
    llm = ScriptedLLM([
        {"tool": "isolate_host", "args": {"host": "win-vm"}},
        dict(FINAL_A2),
    ])
    r = ReasoningAgent("A2", llm).run({"incident_id": "inc-1"}, registry=reg)
    assert r.ok is True
    assert r.tool_calls == 0  # denied call doesn't count as executed
    assert "ERROR" in llm.prompts[1]


def test_agentic_budget_exhausted_degrades(reg):
    llm = ScriptedLLM([  # always requests tools, never finalizes
        {"tool": "search_events", "args": {"host": "win-vm"}},
        {"tool": "search_events", "args": {"event_id": "3"}},
        {"tool": "search_events", "args": {"limit": 1}},
    ])
    r = ReasoningAgent("A4", llm).run({"incident_id": "inc-1"},
                                      registry=reg, max_steps=3)
    assert r.ok is False
    assert r.degraded is True
    assert "budget" in r.error


def test_agentic_a5_can_fetch_policy(reg):
    final = {"summary": "s", "recommended_actions": ["isolate_host"],
             "rationale": "r", "risks": [], "evidence_ids": []}
    llm = ScriptedLLM([
        {"tool": "get_policy", "args": {"incident_type": "powershell"}},
        final,
    ])
    r = ReasoningAgent("A5", llm).run({}, registry=reg)
    assert r.ok and r.tool_calls == 1
    assert "isolate_host" in llm.prompts[1]