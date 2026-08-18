"""Reasoning agents A1-A5 (Phase 3, Phase C G.1).

Each agent = one LLM call over a cumulative incident summary + its allowed
tools. Output is typed JSON, evidence-linked. Agents propose; never act
(ADR-005). Store-mediated handoff: no direct agent->agent calls.
"""

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


class ReasoningAgent:
    def __init__(self, agent_id: str, llm: LLMClient) -> None:
        if agent_id not in AGENTS:
            raise ValueError(f"unknown agent: {agent_id}")
        self.agent_id = agent_id
        self._llm = llm

    def run(self, incident_summary: dict, tool_results: str = "") -> AgentResult:
        schema = _OUTPUT_SCHEMA[self.agent_id]
        system = (
            "You are the security operations analyst agent for Aegis. "
            "You reason from evidence only. Never invent evidence, tools, or results. "
            "Return strictly valid JSON matching this schema:\n"
            f"{schema}\n"
            "Every claim you make must reference evidence_ids that exist in the supplied context. "
            "If evidence is insufficient, say so in summary and set confidence low. "
            "You are a reasoning component: you cannot execute actions."
        )
        user = (
            f"Incident context:\n{incident_summary}\n"
            f"Tool results available:\n{tool_results or '(none)'}"
        )
        result: LLMResult = self._llm.complete_json(system, user)
        return AgentResult(
            agent=self.agent_id,
            ok=result.ok,
            data=result.data,
            degraded=result.degraded,
            error=result.error,
        )