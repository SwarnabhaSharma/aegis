"""HTTP API layer (debt #3). Thin adapter over the deterministic engine.

No new logic: ingest / inspect / investigate / approve wrap existing
functions. Store selection mirrors the runner (AEGIS_STORE=es).
"""

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from aegis.audit import AuditRecorder
from aegis.config import get_settings
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.schema import IncidentState
from aegis.integrations.llm import LLMClient
from aegis.orchestrator.engine import Orchestrator

_TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates"


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


def create_app(store=None, llm=None, controls=None) -> FastAPI:
    from aegis.controls import ControlState

    app = FastAPI(title="Aegis", version="0.1.0")
    _STATIC = Path(__file__).resolve().parents[2] / "static"
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
    st = store or _make_store()
    app.state.store = st  # exposed for tests/introspection
    orch = Orchestrator(st)
    settings = get_settings()
    default_llm = llm  # None -> construct per-call from settings
    ctl = controls if controls is not None else ControlState.from_env()
    app.state.controls = ctl

    def _get(incident_id: str):
        inc = st.get(incident_id)
        if inc is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return inc

    @app.post("/incidents")
    def create_incident(alert: AlertIn):
        inc = ingest_alert(st, alert.source, alert.fields, alert.incident_type)
        return inc.model_dump()

    @app.get("/incidents")
    def list_incidents(state: str = "", severity: str = ""):
        """Console UI: list all incidents with optional state/severity filter."""
        out = []
        for iid in st.all_incident_ids():
            inc = st.get(iid)
            if inc is None:
                continue
            if state and inc.state.value != state:
                continue
            if severity and inc.severity != severity:
                continue
            out.append(inc.model_dump())
        out.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return out

    @app.get("/incidents/{incident_id}")
    def get_incident(incident_id: str):
        return _get(incident_id).model_dump()

    @app.get("/incidents/{incident_id}/timeline")
    def get_timeline(incident_id: str):
        _get(incident_id)
        return [e.model_dump() for e in st.timeline(incident_id)]

    @app.get("/incidents/{incident_id}/transitions")
    def get_transitions(incident_id: str):
        _get(incident_id)
        return [vars(t) for t in st.transitions(incident_id)]

    @app.get("/incidents/{incident_id}/evidence")
    def get_evidence(incident_id: str):
        _get(incident_id)
        return [e.model_dump() for e in st.evidence(incident_id)]

    @app.get("/incidents/{incident_id}/records/{kind}")
    def get_records(incident_id: str, kind: str):
        _get(incident_id)
        return st.records(incident_id, kind)

    @app.post("/incidents/{incident_id}/investigate")
    def investigate(incident_id: str):
        # Consolidated orchestration via aegis.slice (single path with CLI).
        # Agentic registry only when the store itself is ES-backed — keeps
        # memory-store tests offline-deterministic regardless of VM state.
        _get(incident_id)
        import aegis.slice as sl

        registry = None
        audit_rec = None
        if st.__class__.__name__ == "ElasticsearchStore":
            try:
                _, registry = sl.build_registry(controls=ctl)
            except Exception:
                pass  # telemetry unreachable: single-shot fallback
            from aegis.audit import AuditRecorder

            es_client = st._es  # ponytail: recorder reuses the store's client
            audit_rec = AuditRecorder(es=es_client)
            audit_rec.ensure_index()
        llm = default_llm or LLMClient(settings.llm_base_url, settings.llm_model)
        res = sl.investigate(st, incident_id, llm, registry=registry,
                             audit=audit_rec, controls=ctl)
        if not res["ok"]:
            raise HTTPException(status_code=502, detail={
                "error": "pipeline degraded; escalated to human",
                "steps": [vars(s) for s in res["steps"]],
                "errors": res["errors"],
            })
        decision = res["decision"]
        return {
            "incident": st.get(incident_id).model_dump(),
            "steps": [vars(s) for s in res["steps"]],
            "evidence_count": res["evidence_count"],
            "validation": res.get("validation", {}),
            "manifest": res.get("manifest", {}),
            "related": [{"incident_id": r["incident_id"], "shared": r["shared"]}
                        for r in res["related"]],
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
        from datetime import UTC, datetime

        st.add_record("approval", incident_id, {
            "actor": "operator", "decision": "approve",
            "timestamp": datetime.now(UTC).isoformat(),
            "from_state": current.value,
        })
        return updated.model_dump()

    @app.post("/incidents/{incident_id}/override")
    def emergency_override(incident_id: str, decision: str = "ALLOW"):
        """§17 emergency override: operator forces a policy decision."""
        from aegis.policies.engine import Decision, evaluate

        _get(inc_id := incident_id)
        if decision not in ("ALLOW", "DENY"):
            raise HTTPException(status_code=400, detail="decision must be ALLOW or DENY")
        d = Decision[decision]
        evaluate("override", {}, override=d, store=st, incident_id=inc_id)
        from datetime import UTC, datetime

        st.add_record("policy", inc_id, {
            "action": "override", "decision": decision,
            "actor": "operator", "reason": "emergency override",
            "timestamp": datetime.now(UTC).isoformat(),
            "overridden": True,
        })
        return {"incident_id": inc_id, "decision": decision,
                "reason": "operator emergency override"}

    @app.get("/controls")
    def get_controls():
        return {
            "paused": ctl.paused,
            "safe_mode": ctl.safe_mode,
            "require_approval_all": ctl.require_approval_all,
            "disabled_agents": sorted(ctl.disabled_agents),
            "revoked_tools": sorted(ctl.revoked_tools),
        }

    @app.post("/controls/{action}")
    def set_controls(action: str, target: str = ""):
        """Operator emergency controls (§17). LLM-independent."""
        if action == "pause":
            ctl.pause()
        elif action == "resume":
            ctl.resume()
        elif action == "disable_agent" and target:
            ctl.disable_agent(target)
        elif action == "enable_agent" and target:
            ctl.enable_agent(target)
        elif action == "revoke_tool" and target:
            ctl.revoke_tool(target)
        elif action == "restore_tool" and target:
            ctl.restore_tool(target)
        elif action == "require_approval_all":
            ctl.require_approval_all = True
        elif action == "allow_auto":
            ctl.require_approval_all = False
        elif action == "safe_mode":
            ctl.enter_safe_mode()
        elif action == "restore_normal":
            ctl.restore_normal()
        elif action == "cancel_incident" and target:
            ctl.cancel_incident(target)
        elif action == "uncancel_incident" and target:
            ctl.uncancel_incident(target)
        else:
            raise HTTPException(status_code=400, detail=f"unknown action: {action}")
        is_es = st.__class__.__name__ == "ElasticsearchStore"
        audit_rec = AuditRecorder(es=getattr(st, "_es", None) if is_es else None)
        audit_rec.record("operator_control", actor="operator", action=action, target=target)
        return get_controls()

    # -- console UI (§28) --

    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

    @app.get("/", response_class=HTMLResponse)
    def console_index(request: Request):
        incidents = []
        for iid in st.all_incident_ids():
            inc = st.get(iid)
            if inc is not None:
                d = inc.model_dump()
                d["created_at"] = str(d["created_at"])[:19]
                d["updated_at"] = str(d["updated_at"])[:19]
                incidents.append(d)
        incidents.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        controls = {
            "paused": ctl.paused, "safe_mode": ctl.safe_mode,
            "require_approval_all": ctl.require_approval_all,
            "disabled_agents": sorted(ctl.disabled_agents),
            "revoked_tools": sorted(ctl.revoked_tools),
        }
        return templates.TemplateResponse(
            request, "index.html", {"incidents": incidents, "controls": controls})

    @app.get("/incidents/{incident_id}/console",
             response_class=HTMLResponse)
    def console_incident(request: Request, incident_id: str):
        inc = _get(incident_id)
        inc_d = inc.model_dump()
        inc_d["created_at"] = str(inc_d["created_at"])[:19]
        inc_d["updated_at"] = str(inc_d["updated_at"])[:19]
        timeline = []
        for e in st.timeline(incident_id):
            td = e.model_dump()
            td["ts"] = str(td["ts"])[:19]
            timeline.append(td)
        evidence = [e.model_dump() for e in st.evidence(incident_id)]
        transitions = []
        for t in st.transitions(incident_id):
            tv = vars(t)
            tv["ts"] = str(tv["ts"])[:19]
            tv["from_state"] = tv["from_state"].value
            tv["to_state"] = tv["to_state"].value
            transitions.append(tv)
        records = {kind: st.records(incident_id, kind)
                   for kind in ("agentrun", "toolcall", "policy",
                                "verification", "manifest", "attack_mapping")}
        return templates.TemplateResponse(
            request, "incident.html", {"incident": inc_d,
                                       "timeline": timeline, "evidence": evidence,
                                       "transitions": transitions, "records": records,
                                       "incident_id": incident_id})

    @app.get("/incidents/{incident_id}/privacy",
             response_class=HTMLResponse)
    def console_privacy(request: Request, incident_id: str):
        _get(incident_id)  # 404 if missing
        evidence = [e.model_dump() for e in st.evidence(incident_id)]
        records = {"agentrun": st.records(incident_id, "agentrun")}
        return templates.TemplateResponse(
            request, "privacy.html", {"incident_id": incident_id,
                                      "evidence": evidence, "records": records})

    @app.get("/incidents/{incident_id}/response",
             response_class=HTMLResponse)
    def console_response(request: Request, incident_id: str):
        inc = _get(incident_id)
        inc_d = inc.model_dump()
        inc_d["created_at"] = str(inc_d["created_at"])[:19]
        inc_d["updated_at"] = str(inc_d["updated_at"])[:19]
        records = {kind: st.records(incident_id, kind)
                   for kind in ("agentrun", "policy", "verification",
                                "attack_mapping")}
        return templates.TemplateResponse(
            request, "response.html", {"incident_id": incident_id,
                                       "incident": inc_d, "records": records})

    @app.get("/console/audit", response_class=HTMLResponse)
    def console_audit(request: Request):
        """Audit replay: reads from the in-memory AuditRecorder's events list
        (covers the current process). For ES-backed runs use /incidents/{id}/audit
        via the ES index."""
        events = []
        audit_rec = getattr(app.state, "audit_recorder", None)
        if audit_rec is not None:
            events = [{"category": e.category, "actor": e.actor,
                       "ts": e.ts.isoformat(), "incident_id": e.incident_id,
                       "seq": e.seq, "hash": e.hash[:12],
                       "detail": e.detail}
                      for e in audit_rec.events]
        return templates.TemplateResponse(
            request, "audit.html", {"events": events})

    @app.get("/incidents/{incident_id}/analyst-view")
    def analyst_view(incident_id: str):
        """§10 analyst view: evidence with tokenized PII (reversible)."""
        _get(incident_id)
        from aegis.privacy.gateway import get_gateway
        gw = get_gateway()
        evidence = []
        for ev in st.evidence(incident_id):
            ev_d = ev.model_dump()
            # tokenize sensitive fields for analyst display
            for key in ("command_line", "file_path", "user"):
                val = ev_d.get("data", {}).get(key)
                if val:
                    ev_d["data"][key] = gw.analyst_view(str(val))
            evidence.append(ev_d)
        return {"incident_id": incident_id, "evidence": evidence,
                "vault_tokens": gw.vault.tokens()}

    @app.post("/incidents/{incident_id}/reveal")
    def reveal_tokens(incident_id: str, tokens: list[str]):
        """§10 reveal: de-tokenize specific tokens back to originals."""
        _get(incident_id)
        from aegis.privacy.gateway import get_gateway
        gw = get_gateway()
        originals = {}
        for tok in tokens:
            revealed = gw.vault.reveal(tok)
            if revealed != tok:
                originals[tok] = revealed
        return {"revealed": originals}

    @app.get("/incidents/{incident_id}/integrity")
    def integrity_check(incident_id: str):
        """§18: verify audit chain + evidence hash integrity."""
        _get(incident_id)
        from aegis.audit import verify_evidence_integrity
        audit_rec = getattr(app.state, "audit_recorder", None)
        chain_ok = audit_rec.verify_chain() if audit_rec else None
        evidence = st.evidence(incident_id)
        ev_result = verify_evidence_integrity(evidence)
        return {"incident_id": incident_id, "audit_chain": chain_ok,
                "evidence": ev_result}

    return app


app = create_app()
