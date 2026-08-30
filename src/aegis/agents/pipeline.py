"""Agent pipeline driver (Phase 3, agentic since debt #2). Sequential A1->A5,
store-mediated handoff, per-agent budgets, deterministic degrade on failure.

Registry mode: agents call read tools themselves (ReAct-lite); tool-call
budgets count real calls. Without a registry, legacy single-shot string mode.
If any agent degrades, the incident cannot proceed to autonomous action:
pipeline stops and flags escalate-needed. Fail-safe.
"""

import time
from dataclasses import dataclass

from aegis.agents.reasoning import AGENTS, ReasoningAgent
from aegis.integrations.llm import LLMClient

# Budgets (doc D-006/007). Escalate when exceeded.
DEFAULT_BUDGETS = {
    "steps_per_agent": 1,  # LLM turns in legacy mode
    "tool_steps_per_agent": 6,  # max tool iterations in agentic mode
    "tool_calls_per_incident": 50,
# measured: 9B reasoning model 35-90s/call x up to 6 turns + corrective
# passes; 600s covers loaded-server worst case while still bounding
"time_per_agent_ms": 600_000,
}


@dataclass
class PipelineStep:
    agent: str
    ok: bool
    degraded: bool
    elapsed_ms: int
    error: str = ""


class AgentPipeline:
    def __init__(self, llm: LLMClient, budgets: dict | None = None,
                 registry=None, controls=None) -> None:
        self._llm = llm
        self._registry = registry
        self._controls = controls  # ControlState (§17); None = unrestricted
        self._budgets = {**DEFAULT_BUDGETS, **(budgets or {})}
        self._agents = {
            a: ReasoningAgent(a, llm) for a in AGENTS
        }

    def run(self, incident_summary: dict, tool_calls: dict) -> tuple[list[PipelineStep], dict]:
        """Run all agents. Returns (steps, results_by_agent)."""
        steps: list[PipelineStep] = []
        results: dict = {}

        # §17 emergency controls: operator pause/safe-mode halts autonomy
        # entirely; disabled agents fail-safe-stop the run at their stage.
        if self._controls is not None and self._controls.autonomy_blocked():
            steps.append(PipelineStep("A1", ok=False, degraded=True,
                                      elapsed_ms=0,
                                      error="autonomy paused by operator"))
            return steps, results

        tool_budget = self._budgets["tool_calls_per_incident"]
        consumed = 0

        # cumulative context: each agent sees prior outputs (store-mediated)
        context = dict(incident_summary)
        inc_id = context.get("incident_id", "")
        for agent_id in AGENTS:
            if consumed >= tool_budget:
                steps.append(PipelineStep(agent_id, ok=False, degraded=True,
                                          elapsed_ms=0, error="tool budget exceeded"))
                break
            if self._controls is not None and agent_id in self._controls.disabled_agents:
                steps.append(PipelineStep(agent_id, ok=False, degraded=True,
                                          elapsed_ms=0,
                                          error="agent disabled by operator"))
                break
            # §17 mid-run cancel: re-check between agents
            if (self._controls is not None
                    and self._controls.is_cancelled(inc_id)):
                steps.append(PipelineStep(agent_id, ok=False, degraded=True,
                                          elapsed_ms=0,
                                          error="cancelled by operator"))
                break
            tool_results = tool_calls.get(agent_id, "")
            start = time.monotonic()
            r = self._agents[agent_id].run(
                context,
                tool_results,
                registry=self._registry,
                max_steps=self._budgets["tool_steps_per_agent"],
                controls=self._controls,
            )
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
            consumed += r.tool_calls  # real accounting in agentic mode

        return steps, results