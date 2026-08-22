"""API layer tests (debt #3). FakeLLM + InMemoryStore; no network, no ES."""

import pytest
from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.incidents.schema import IncidentState
from aegis.incidents.store import InMemoryStore
from aegis.integrations.llm import LLMClient, LLMResult


class FakeLLM(LLMClient):
    def __init__(self):
        pass

    def complete_json(self, system, user, temperature=0.0):
        data = {"summary": "s", "hypotheses": [], "evidence_ids": [],
                "open_questions": [], "classification": "malicious",
                "severity": "high", "investigate": True, "reason": "r",
                "assessment": "malicious", "confidence": 0.95,
                "attack_mapping": "T1059.001", "recommended_actions": [],
                "rationale": "r", "risks": []}
        return LLMResult(ok=True, data=data, raw="{}")


@pytest.fixture()
def client():
    app = create_app(store=InMemoryStore(), llm=FakeLLM())
    return TestClient(app), app


def test_create_and_get(client):
    c, _ = client
    r = c.post("/incidents", json={"source": "t",
                                   "fields": {"host": "win-vm", "severity": "high"}})
    assert r.status_code == 200
    inc_id = r.json()["id"]
    assert r.json()["state"] == "NEW"
    g = c.get(f"/incidents/{inc_id}")
    assert g.status_code == 200
    assert g.json()["fields"]["host"] == "win-vm"


def test_get_missing_404(client):
    c, _ = client
    assert c.get("/incidents/nope").status_code == 404


def test_investigate_auto_allow_path(client):
    c, _ = client
    inc_id = c.post("/incidents", json={
        "fields": {"host": "win-vm", "severity": "high"}}).json()["id"]
    r = c.post(f"/incidents/{inc_id}/investigate")
    assert r.status_code == 200
    body = r.json()
    # slice.investigate persists 3 synthetic evidence records; FakeLLM conf
    # 0.95 + win-vm low criticality -> policy auto-ALLOW.
    assert body["decision"]["decision"] == "ALLOW"
    assert body["incident"]["state"] == "AUTHORIZED"
    assert body["evidence_count"] == 3


def test_approve_gate_requires_awaiting_state(client):
    c, app = client
    inc_id = c.post("/incidents", json={"fields": {}}).json()["id"]
    r = c.post(f"/incidents/{inc_id}/approve")
    assert r.status_code == 409

    # drive to AWAITING_APPROVAL via orchestrator then approve
    from aegis.orchestrator.engine import Orchestrator

    orch = Orchestrator(app.state.store)
    orch.transition(inc_id, IncidentState.TRIAGING, "orchestrator", "t")
    orch.transition(inc_id, IncidentState.INVESTIGATING, "orchestrator", "i")
    orch.transition(inc_id, IncidentState.CORRELATING, "orchestrator", "c")
    orch.transition(inc_id, IncidentState.ASSESSING, "orchestrator", "a")
    orch.transition(inc_id, IncidentState.RESPONSE_PLANNED, "orchestrator", "p")
    orch.transition(inc_id, IncidentState.AWAITING_APPROVAL, "orchestrator", "w")

    ok = c.post(f"/incidents/{inc_id}/approve")
    assert ok.status_code == 200
    assert ok.json()["state"] == "AUTHORIZED"
    assert c.post(f"/incidents/{inc_id}/approve").status_code == 409


def test_timeline_endpoint(client):
    c, _ = client
    inc_id = c.post("/incidents", json={"fields": {}}).json()["id"]
    assert c.get(f"/incidents/{inc_id}/timeline").json() == []