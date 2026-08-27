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


def test_slice_generates_audit_events():
    """§26: slice investigate() must produce audit-* events."""
    from aegis.audit import AuditRecorder
    from aegis.incidents.store import InMemoryStore
    from aegis.slice import investigate

    store = InMemoryStore()
    from aegis.incidents.ingestion import ingest_alert

    inc = ingest_alert(store, source="t", fields={"host": "win-vm"},
                       incident_type="powershell")
    audit = AuditRecorder()
    from aegis.integrations.llm import LLMClient, LLMResult

    class Fake(LLMClient):
        def __init__(self):
            pass
        def complete_json(self, system, user, temperature=0.0):
            return LLMResult(ok=True, data={
                "classification": "malicious", "severity": "high",
                "investigate": True, "reason": "synthetic",
                "evidence_ids": [], "summary": "s", "hypotheses": [],
                "open_questions": [], "attack_chain": [],
                "affected_assets": [], "assessment": "malicious",
                "confidence": 0.95, "attack_techniques": [],
            }, raw="{}")

    investigate(store, inc.id, Fake(), audit=audit)
    categories = [e.category for e in audit.events]
    assert "pipeline_stage" in categories or "tool_call" in categories
