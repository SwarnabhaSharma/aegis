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