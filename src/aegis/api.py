"""HTTP API layer (debt #3). Thin adapter over the deterministic engine.

No new logic: ingest / inspect / investigate / approve wrap existing
functions. Store selection mirrors the runner (AEGIS_STORE=es).
"""

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from aegis.agents.pipeline import AgentPipeline
from aegis.config import get_settings
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.schema import IncidentState
from aegis.integrations.llm import LLMClient
from aegis.orchestrator.engine import Orchestrator
from aegis.policies.engine import Decision, evaluate


class AlertIn(BaseModel):
    source: str = "api"
    fields: dict = {}
    incident_type: str = "powershell"


def _make_store():
    if os.getenv("AEGIS_STORE") == "es":
        from elasticsearch import Elasticsearch

        from aegis.incidents.es_store import ElasticsearchStore

        s = get_settings()
        es = Elasticsearch(
            s.es_host, basic_auth=(s.es_user, s.es_password),
            verify_certs=s.es_verify_certs, request_timeout=60,
        )
        return ElasticsearchStore(es)
    from aegis.incidents.store import InMemoryStore

    return InMemoryStore()


def create_app(store=None, llm=None) -> FastAPI:
    app = FastAPI(title="Aegis", version="0.1.0")
    st = store or _make_store()
    app.state.store = st  # exposed for tests/introspection
    orch = Orchestrator(st)
    settings = get_settings()
    default_llm = llm  # None -> construct per-call from settings

    def _get(incident_id: str):
        inc = st.get(incident_id)
        if inc is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return inc

    @app.post("/incidents")
    def create_incident(alert: AlertIn):
        inc = ingest_alert(st, alert.source, alert.fields, alert.incident_type)
        return inc.model_dump()

    @app.get("/incidents/{incident_id}")
    def get_incident(incident_id: str):
        return _get(incident_id).model_dump()

    @app.get("/incidents/{incident_id}/timeline")
    def get_timeline(incident_id: str):
        _get(incident_id)
        return [e.model_dump() for e in st.timeline(incident_id)]

    @app.get("/incidents/{incident_id}/evidence")
    def get_evidence(incident_id: str):
        _get(incident_id)
        return [e.model_dump() for e in st.evidence(incident_id)]

    @app.post("/incidents/{incident_id}/investigate")
    def investigate(incident_id: str):
        # ponytail: mirrors scripts/run_slice.py flow; consolidate when the
        # slice runner moves into src (single orchestration path).
        inc = _get(incident_id)
        orch.transition(incident_id, IncidentState.TRIAGING,
                        "orchestrator", "api investigate")
        llm = default_llm or LLMClient(settings.llm_base_url, settings.llm_model)
        pipe = AgentPipeline(llm)
        summary = {
            "incident_id": incident_id,
            "host": inc.fields.get("host", "unknown"),
            "type": inc.type,
            "summary": f"Incident type {inc.type} on {inc.fields.get('host', 'unknown')}",
        }
        steps, results = pipe.run(summary, {})
        if any(not s.ok for s in steps):
            orch.transition(incident_id, IncidentState.ESCALATED,
                            "orchestrator", "pipeline degraded")
            raise HTTPException(status_code=502, detail={
                "error": "pipeline degraded; escalated to human",
                "steps": [vars(s) for s in steps],
            })
        for to_state in (IncidentState.INVESTIGATING, IncidentState.CORRELATING,
                         IncidentState.ASSESSING, IncidentState.RESPONSE_PLANNED):
            orch.transition(incident_id, to_state, "orchestrator", "pipeline progress")

        confidence = 0.0
        a4 = results.get("A4")
        if a4 and isinstance(a4.data.get("confidence"), (int, float)):
            confidence = float(a4.data["confidence"])
        facts = {"host": inc.fields.get("host"), "confidence": confidence,
                 "evidence_count": len(st.evidence(incident_id))}
        decision = evaluate("isolate_host", facts)
        if decision.decision == Decision.DENY:
            orch.transition(incident_id, IncidentState.FAILED,
                            "orchestrator", decision.reason)
        elif decision.decision == Decision.APPROVE:
            orch.transition(incident_id, IncidentState.AWAITING_APPROVAL,
                            "orchestrator", "human approval required")
        else:
            orch.transition(incident_id, IncidentState.AUTHORIZED,
                            "orchestrator", "auto-allow by policy")
        return {
            "incident": st.get(incident_id).model_dump(),
            "steps": [vars(s) for s in steps],
            "decision": {"decision": decision.decision.value,
                         "reason": decision.reason,
                         "policy_version": decision.policy_version},
        }

    @app.post("/incidents/{incident_id}/approve")
    def approve(incident_id: str):
        _get(incident_id)
        current = st.get(incident_id).state
        if current != IncidentState.AWAITING_APPROVAL:
            raise HTTPException(
                status_code=409, detail=f"cannot approve from state {current.value}")
        updated = orch.transition(incident_id, IncidentState.AUTHORIZED,
                                  "operator", "approved via api")
        return updated.model_dump()

    return app


app = create_app()
