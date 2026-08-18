"""Agent pipeline driver (Phase 3). Sequential A1->A5, store-mediated handoff,
per-agent budgets, deterministic degrade on LLM failure.

If any agent degrades (LLM down/unparseable), the incident cannot proceed to
autonomous action: pipeline stops and flags escalate-needed. Fail-safe.
"""

import time
from dataclasses import dataclass

from aegis.agents.reasoning import AGENTS, ReasoningAgent
from aegis.integrations.llm import LLMClient

# Budgets (doc D-006/007). Escalate when exceeded.
DEFAULT_BUDGETS = {
    "steps_per_agent": 1,  # one LLM call per stage in Phase 3 (multi-turn later)
    "tool_calls_per_incident": 50,
    "time_per_agent_ms": 120_000,
}


@dataclass
class PipelineStep:
    agent: str
    ok: bool
    degraded: bool
    elapsed_ms: int
    error: str = ""


class AgentPipeline:
    def __init__(self, llm: LLMClient, budgets: dict | None = None) -> None:
        self._llm = llm
        self._agents = {a: ReasoningAgent(a, llm) for a in AGENTS}
        self._budgets = budgets or DEFAULT_BUDGETS

    def run(self, incident_summary: dict, tool_calls: dict) -> tuple[list[PipelineStep], dict]:
        """Run all agents. Returns (steps, results_by_agent)."""
        steps: list[PipelineStep] = []
        results: dict = {}
        tool_budget = self._budgets["tool_calls_per_incident"]
        consumed = 0

        # cumulative context: each agent sees prior outputs (store-mediated)
        context = dict(incident_summary)
        for agent_id in AGENTS:
            if consumed >= tool_budget:
                steps.append(PipelineStep(agent_id, ok=False, degraded=True,
                                          elapsed_ms=0, error="tool budget exceeded"))
                break
            tool_results = tool_calls.get(agent_id, "")
            start = time.monotonic()
            r = self._agents[agent_id].run(context, tool_results)
            elapsed = int((time.monotonic() - start) * 1000)

            if elapsed > self._budgets["time_per_agent_ms"]:
                steps.append(PipelineStep(agent_id, ok=False, degraded=True,
                                          elapsed_ms=elapsed, error="time budget exceeded"))
                break
            if not r.ok:
                steps.append(PipelineStep(agent_id, ok=False, degraded=r.degraded,
                                          elapsed_ms=elapsed, error=r.error))
                # fail-safe: no reasoning, no autonomous action
                results[agent_id] = r
                break

            steps.append(PipelineStep(agent_id, ok=True, degraded=r.degraded,
                                      elapsed_ms=elapsed))
            results[agent_id] = r
            context[agent_id] = r.data  # cumulative handoff
            consumed += len(tool_results) // 500  # rough tool-call accounting

        return steps, results