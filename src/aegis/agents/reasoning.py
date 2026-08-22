"""Reasoning agents A1-A5 (Phase 3, Phase C G.1).

Two modes:
- single-shot (legacy): caller passes pre-digested tool_results string.
- agentic (Phase 7 debt #2): agent iterates -- requests tools via
  {"tool": name, "args": {...}}, gets observations, then answers with its
  output schema. Registry enforces authorization; budget caps steps;
  exhaustion -> deterministic degrade (fail-safe R-001).

Output is typed JSON, evidence-linked. Agents propose; never act (ADR-005).
"""

import json
from dataclasses import dataclass

from aegis.integrations.llm import LLMClient, LLMResult

AGENTS = ["A1", "A2", "A3", "A4", "A5"]

AGENT_ROLE = {
    "A1": "triage",
    "A2": "investigation",
    "A3": "correlation",
    "A4": "threat_analysis",
    "A5": "response_planning",
}

_OUTPUT_SCHEMA = {
    "A1": {
        "classification": "str", "severity": "str", "investigate": "bool",
        "reason": "str", "evidence_ids": "list",
    },
    "A2": {
        "summary": "str", "hypotheses": "list", "evidence_ids": "list",
        "open_questions": "list",
    },
    "A3": {
        "summary": "str", "attack_chain": "list", "affected_assets": "list",
        "evidence_ids": "list",
    },
    "A4": {
        "summary": "str", "assessment": "str", "confidence": "float",
        "attack_mapping": "str", "evidence_ids": "list",
    },
    "A5": {
        "summary": "str", "recommended_actions": "list", "rationale": "str",
        "risks": "list", "evidence_ids": "list",
    },
}


@dataclass
class AgentResult:
    agent: str
    ok: bool
    data: dict
    degraded: bool = False
    error: str = ""
    tool_calls: int = 0


def _fmt_observation(obs) -> str:
    """Compact text view of a tool result for the next prompt."""
    if isinstance(obs, list):
        rows = []
        for e in obs[:6]:
            if hasattr(e, "event_id"):
                row = f"ev{e.event_id} {e.process_name or e.action} pid={e.process_pid}"
                if e.process_parent:
                    row += f" parent={e.process_parent}"
                if e.command_line:
                    row += f" cmd={e.command_line[:80]}"
                if e.destination_ip:
                    row += f" -> {e.destination_ip}:{e.destination_port}"
                if e.file_path:
                    row += f" file={e.file_path}"
                rows.append(row)
            else:
                rows.append(str(e)[:160])
        return "\n".join(rows) or "(empty)"
    if isinstance(obs, dict):
        return json.dumps(obs, default=str)[:400]
    return str(obs)[:400]


class ReasoningAgent:
    def __init__(self, agent_id: str, llm: LLMClient) -> None:
        if agent_id not in AGENTS:
            raise ValueError(f"unknown agent: {agent_id}")
        self.agent_id = agent_id
        self._llm = llm

    def run(self, incident_summary: dict, tool_results: str = "",
            registry=None, max_steps: int = 2) -> AgentResult:
        if registry is None:
            return self._single_shot(incident_summary, tool_results)
        return self._agentic(incident_summary, registry, max_steps, tool_results)

    # -- legacy single-shot --

    def _single_shot(self, incident_summary: dict, tool_results: str) -> AgentResult:
        result: LLMResult = self._llm.complete_json(
            self._system_prompt([]),
            self._user_prompt(incident_summary, [], tool_results),
        )
        return AgentResult(
            agent=self.agent_id,
            ok=result.ok,
            data=result.data,
            degraded=result.degraded,
            error=result.error,
        )

    # -- agentic loop --

    def _agentic(self, incident_summary: dict, registry, max_steps: int,
                 tool_results: str = "") -> AgentResult:
        tool_names = registry.authorized_tools(self.agent_id)
        # analyst-provided context (correlation, ATT&CK candidates) seeds the loop
        observations: list[str] = (
            [f"Analyst-provided context:\n{tool_results}"] if tool_results else []
        )
        used = 0
        for turn in range(1, max_steps + 1):
            result = self._llm.complete_json(
                self._system_prompt(tool_names),
                self._user_prompt(incident_summary, observations)
                + f"\n\n[Tool turn {turn} of {max_steps}. Reply with exactly ONE "
                "tool call OR your FINAL answer JSON.]",
            )
            if not result.ok:
                return AgentResult(self.agent_id, ok=False, data={}, degraded=True,
                                   error=result.error, tool_calls=used)
            data = result.data
            if "tool" not in data:
                return AgentResult(self.agent_id, ok=True, data=data,
                                   tool_calls=used)
            name = str(data.get("tool", ""))
            args = data.get("args") or {}
            try:
                obs = registry.call(name, self.agent_id, **args)
            except Exception as e:  # unknown/unauthorized/bad args: observe, don't crash
                observations.append(f"{name}: ERROR ({e})")
                continue
            used += 1
            observations.append(f"{name}({args}):\n{_fmt_observation(obs)}")
        return AgentResult(
            self.agent_id, ok=False, data={}, degraded=True,
            error="tool-step budget exceeded before final answer", tool_calls=used,
        )

    # -- prompts --

    def _system_prompt(self, tool_names: list[str]) -> str:
        system = (
            "You are the security operations analyst agent for Aegis. "
            "You reason from evidence only. Never invent evidence, tools, or results. "
            "You are a reasoning component: you cannot execute actions."
        )
        if tool_names:
            system += (
                "\n\nTools you may use: " + ", ".join(tool_names) + ".\n"
                "To call one, reply ONLY with: {\"tool\": \"<name>\", \"args\": {...}}\n"
                "Exactly ONE tool call per reply; make additional calls in later turns.\n"
                "After reviewing observations, reply with your FINAL answer as strict "
                f"JSON matching this schema:\n{_OUTPUT_SCHEMA[self.agent_id]}\n"
                "Every claim must reference evidence_ids that exist in the supplied "
                "context. If evidence is insufficient, say so and set confidence low."
            )
        else:
            system += (
                "\nNo tools are available to you. Reply with strictly valid JSON "
                f"matching this schema:\n{_OUTPUT_SCHEMA[self.agent_id]}"
            )
        return system

    def _user_prompt(self, incident_summary: dict, observations: list[str],
                     tool_results: str = "") -> str:
        parts = [f"Incident context:\n{incident_summary}"]
        if tool_results:
            parts.append(f"Tool results available:\n{tool_results}")
        for i, obs in enumerate(observations, 1):
            parts.append(f"Observation {i}:\n{obs}")
        return "\n\n".join(parts)