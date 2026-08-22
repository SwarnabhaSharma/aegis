"""E2E slice (Phases 1-6, in-memory, ponytail)."""

from aegis.incidents.schema import IncidentState
from scripts.run_slice import run_slice


def test_slice_resolved():
    res = run_slice(host="win-vm", llm_mode="fake", confidence=0.95, evidence_count=4)
    assert res["incident"].state == IncidentState.RESOLVED
    assert res["trace"][-1] == "RESOLVED"
    assert res["verifications"][0].passed is True


def test_slice_policy_deny():
    res = run_slice(host="critical-box", llm_mode="fake", confidence=0.95, evidence_count=4)
    assert res["incident"].state == IncidentState.FAILED
    assert "critical" in res["decision"].reason or res["decision"].decision.value == "DENY"


def test_slice_degraded_pipeline():
    # Fake LLM that returns degraded -> runner should ESCALATE (fail-safe)
    from aegis.agents.pipeline import AgentPipeline
    from aegis.incidents.ingestion import ingest_alert
    from aegis.incidents.schema import IncidentState
    from aegis.incidents.store import InMemoryStore
    from aegis.integrations.llm import LLMClient, LLMResult
    from aegis.orchestrator.engine import Orchestrator

    class BadLLM(LLMClient):
        def __init__(self):
            pass

        def complete_json(self, system, user, temperature=0.0):
            return LLMResult(ok=False, data={}, raw="", degraded=True, error="down")

    store = InMemoryStore()
    orch = Orchestrator(store)
    inc = ingest_alert(store, source="synthetic", fields={"severity": "high"},
                       incident_type="powershell")
    orch.transition(inc.id, IncidentState.TRIAGING, "orchestrator", "test")
    pipe = AgentPipeline(BadLLM())
    steps, _ = pipe.run({"incident_id": inc.id}, {})
    assert any(s.degraded for s in steps)
