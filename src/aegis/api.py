"""HTTP API layer (debt #3). Thin adapter over the deterministic engine.

No new logic: ingest / inspect / investigate / approve wrap existing
functions. Store selection mirrors the runner (AEGIS_STORE=es).
"""

import uuid
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
from aegis.infrastructure import get_es_client
from aegis.infrastructure import make_store as _make_store
from aegis.integrations.llm import LLMClient
from aegis.orchestrator.engine import Orchestrator

_TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates"


class AlertIn(BaseModel):
    source: str = "api"
    fields: dict = {}
    incident_type: str = "powershell"


def create_app(store=None, llm=None, controls=None) -> FastAPI:
    from starlette.middleware.base import BaseHTTPMiddleware

    from aegis.controls import ControlState

    app = FastAPI(title="Aegis", version="0.1.0",
                  description="Autonomous SOC Platform — AI agents with deterministic guardrails",
                  docs_url="/docs", redoc_url=None)
    _STATIC = Path(__file__).resolve().parents[2] / "static"
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
    st = store or _make_store()[0]
    app.state.store = st  # exposed for tests/introspection
    orch = Orchestrator(st)
    settings = get_settings()
    default_llm = llm  # None -> construct per-call from settings
    ctl = controls if controls is not None else ControlState.from_env()
    app.state.controls = ctl

    # §17 request tracing: correlation ID on every request
    @app.middleware("http")
    async def correlation_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:12])
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # §17 API key auth: skip for console UI (HTML) and health endpoints
    # ponytail: in dev (aegis_env == "dev") and empty key, auth is disabled.
    # In prod, require a key — fail closed.
    if settings.aegis_api_key or settings.aegis_env == "dev":
        class AuthMiddleware(BaseHTTPMiddleware):
            SKIP_PATHS = {"/health", "/ready", "/docs", "/openapi.json"}
            # Exact paths that skip auth (console HTML pages only)
            SKIP_CONSOLE = {"/console/audit"}

            async def dispatch(self, request: Request, call_next):
                path = request.url.path
                if (path in self.SKIP_PATHS
                        or path.startswith("/static")
                        or path in self.SKIP_CONSOLE
                        or path.startswith("/incidents/") and path.endswith("/console")
                        or path.startswith("/incidents/") and "/console/" in path):
                    return await call_next(request)
                if not settings.aegis_api_key:
                    return await call_next(request)
                key = request.headers.get("X-API-Key", "")
                if key != settings.aegis_api_key:
                    from fastapi.responses import JSONResponse
                    return JSONResponse({"detail": "invalid or missing API key"},
                                        status_code=401)
                return await call_next(request)

        app.add_middleware(AuthMiddleware)

    def _get(incident_id: str):
        inc = st.get(incident_id)
        if inc is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return inc

    @app.post("/incidents", tags=["incidents"])
    def create_incident(alert: AlertIn):
        inc = ingest_alert(st, alert.source, alert.fields, alert.incident_type)
        return inc.model_dump()

    @app.get("/incidents", tags=["incidents"])
    def list_incidents(state: str = "", severity: str = "", q: str = "",
                       sort: str = "created", order: str = "desc",
                       page: int = 1, limit: int = 50):
        """Phase3: queue search/filter/sort/page. List shape unchanged.

        q matches id/type/host/severity/state substring (case-insensitive).
        sort: created|severity|state. limit capped 100.
        # ponytail: slice-in-memory; ES-backed pagination if volume matters.
        """
        SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                    "unknown": 4, "info": 5}
        ql = q.strip().lower()
        out = []
        for iid in st.all_incident_ids():
            inc = st.get(iid)
            if inc is None:
                continue
            if state and inc.state.value != state:
                continue
            if severity and inc.severity != severity:
                continue
            if ql:
                hay = " ".join([inc.id, inc.type, inc.severity,
                                inc.state.value,
                                str((inc.fields or {}).get("host", ""))]).lower()
                if ql not in hay:
                    continue
            out.append(inc.model_dump())
        reverse = order != "asc"
        if sort == "severity":
            # desc = most severe first (critical first = rank ascending).
            out.sort(key=lambda x: SEV_RANK.get(str(x.get("severity", "")).lower(), 9),
                     reverse=(order == "asc"))
        elif sort == "state":
            out.sort(key=lambda x: str(x.get("state", "")), reverse=reverse)
        else:
            out.sort(key=lambda x: str(x.get("created_at", "")), reverse=reverse)
        page = max(page, 1)
        limit = min(max(limit, 1), 100)
        start = (page - 1) * limit
        return out[start:start + limit]

    @app.get("/incidents/{incident_id}", tags=["incidents"])
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

    STAGES = ["Triage", "Investigate", "Assess", "Respond", "Verify"]
    STAGE_OF = {"NEW": 0, "TRIAGING": 0, "INVESTIGATING": 1,
                "CORRELATING": 1, "ASSESSING": 2, "RESPONSE_PLANNED": 2,
                "AWAITING_APPROVAL": 3, "AUTHORIZED": 3, "EXECUTING": 3,
                "VERIFYING": 4, "RESOLVED": 4}

    @app.get("/incidents/{incident_id}/replay")
    def get_replay(incident_id: str):
        """Phase4: merged chronology (timeline + transitions + approvals).

        Policy/verification records carry no timestamps, so they stay in
        their own cards; untimestamped entries noted via `partial: true`.
        """
        inc = _get(incident_id)
        items = []
        try:
            for e in st.timeline(incident_id):
                d = e.model_dump()
                items.append({"ts": str(d.get("ts", "")), "actor": d.get("actor", "-"),
                              "action": d.get("action", "-"), "detail": d.get("detail", ""),
                              "kind": "timeline"})
        except Exception:
            pass
        try:
            for t in st.transitions(incident_id):
                v = vars(t)
                items.append({"ts": str(v.get("ts", "")),
                              "actor": str(v.get("actor", "-")),
                              "action": f"{v['from_state'].value} → {v['to_state'].value}",
                              "detail": v.get("reason", ""), "kind": "transition"})
        except Exception:
            pass
        try:
            for a in st.records(incident_id, "approval") or []:
                items.append({"ts": str(a.get("timestamp", "")),
                              "actor": a.get("actor", "operator"),
                              "action": f"approval:{a.get('decision', '?')}",
                              "detail": a.get("from_state", ""), "kind": "approval"})
        except Exception:
            pass
        items.sort(key=lambda x: x["ts"])
        state = inc.state.value
        return {"incident_id": incident_id, "state": state,
                "stages": STAGES, "stage_index": STAGE_OF.get(state),
                "replay": items,
                "partial": True}

    @app.post("/incidents/{incident_id}/investigate", tags=["pipeline"])
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

    @app.post("/incidents/{incident_id}/approve", tags=["operator"])
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

    @app.post("/incidents/{incident_id}/deny")
    def deny(incident_id: str):
        _get(incident_id)
        current = st.get(incident_id).state
        if current != IncidentState.AWAITING_APPROVAL:
            raise HTTPException(
                status_code=409, detail=f"cannot deny from state {current.value}")
        updated = orch.transition(incident_id, IncidentState.FAILED,
                                   "operator", "denied via api")
        from datetime import UTC, datetime

        st.add_record("approval", incident_id, {
            "actor": "operator", "decision": "deny",
            "timestamp": datetime.now(UTC).isoformat(),
            "from_state": current.value,
        })
        return updated.model_dump()

    @app.post("/incidents/{incident_id}/override", tags=["operator"])
    def emergency_override(incident_id: str, decision: str = "ALLOW"):
        """§17 emergency override: operator forces a policy decision."""
        import logging

        from aegis.policies.engine import Decision, evaluate

        _get(inc_id := incident_id)
        if decision not in ("ALLOW", "DENY"):
            raise HTTPException(status_code=400, detail="decision must be ALLOW or DENY")
        logging.warning("EMERGENCY OVERRIDE: incident=%s decision=%s", inc_id, decision)
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

    @app.get("/dashboard", response_class=HTMLResponse)
    def console_dashboard(request: Request):
        incidents = []
        for iid in st.all_incident_ids():
            inc = st.get(iid)
            if inc is not None:
                incidents.append(inc)

        from collections import Counter
        by_state = Counter(i.state.value for i in incidents)
        by_severity = Counter(i.severity for i in incidents)

        recent = sorted(incidents, key=lambda i: i.created_at, reverse=True)[:10]

        operations = None
        try:
            operations = _get_ops_loop().status()
        except Exception:
            pass

        return templates.TemplateResponse(request, "dashboard.html", {
            "stats": {
                "total": len(incidents),
                "by_state": dict(by_state),
                "by_severity": dict(by_severity),
            },
            "recent": recent,
            "operations": operations,
        })

    @app.get("/api/dashboard/stats")
    def api_dashboard_stats():
        incidents = []
        for iid in st.all_incident_ids():
            inc = st.get(iid)
            if inc is not None:
                incidents.append(inc)

        from collections import Counter
        by_state = Counter(i.state.value for i in incidents)
        by_severity = Counter(i.severity for i in incidents)
        by_type = Counter(i.type for i in incidents)
        by_host = Counter(i.fields.get("host", "unknown") for i in incidents)

        timeline = {}
        for i in incidents:
            day = str(i.created_at)[:10]
            timeline[day] = timeline.get(day, 0) + 1

        return {
            "total": len(incidents),
            "by_state": dict(by_state),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "by_host": dict(by_host),
            "timeline": dict(sorted(timeline.items())),
        }

    @app.get("/api/overview")
    def api_overview():
        """Phase2: real-data overview aggregation. No fake metrics.

        response_success_pct = RESOLVED/total (None when total==0).
        threats_enriched = TI tool calls + ATT&CK mappings observed.
        Partial-data safe: per-incident failures degrade to skipped count.
        """
        from collections import Counter
        from datetime import UTC, datetime, timedelta

        TI_TOOLS = {"lookup_ip", "lookup_hash", "lookup_domain",
                    "lookup_cve", "get_threat_intelligence"}
        TERMINAL = {"RESOLVED", "FAILED", "ESCALATED", "CANCELLED"}
        ACTIVE_INVESTIGATING = {"TRIAGING", "INVESTIGATING", "CORRELATING",
                                "ASSESSING", "RESPONSE_PLANNED"}

        incidents = []
        skipped = 0
        for iid in st.all_incident_ids():
            try:
                inc = st.get(iid)
                if inc is not None:
                    incidents.append(inc)
            except Exception:
                skipped += 1

        by_state = Counter(i.state.value for i in incidents)
        by_severity = Counter(i.severity for i in incidents)
        by_type = Counter(i.type for i in incidents)
        by_host = Counter((i.fields or {}).get("host", "unknown")
                          for i in incidents)

        now = datetime.now(UTC)
        day_ago = now - timedelta(hours=24)
        week_ago = now - timedelta(days=7)

        def _ts(v):
            try:
                s = str(v)[:19]
                return datetime.fromisoformat(s).replace(tzinfo=UTC)
            except Exception:
                return None

        active = sum(1 for i in incidents if i.state.value not in TERMINAL)
        new_24h = sum(1 for i in incidents
                      if (_ts(i.created_at) or now) >= day_ago)
        trend7 = {}
        for i in incidents:
            ts = _ts(i.created_at)
            if ts is None or ts < week_ago:
                continue
            day = str(i.created_at)[:10]
            d = trend7.setdefault(day, {"total": 0, "high": 0})
            d["total"] += 1
            if str(i.severity).lower() in ("high", "critical"):
                d["high"] += 1

        ti_lookups = 0
        attack_mappings = 0
        agent_feed = []
        for inc in sorted(incidents, key=lambda x: str(x.created_at),
                          reverse=True)[:20]:
            try:
                runs = st.records(inc.id, "agentrun") or []
                calls = st.records(inc.id, "toolcall") or []
                maps = st.records(inc.id, "attack_mapping") or []
            except Exception:
                skipped += 1
                continue
            ti_lookups += sum(1 for c in calls
                              if c.get("tool") in TI_TOOLS)
            attack_mappings += len(maps)
            for r in runs[-5:]:
                agent_feed.append({
                    "incident_id": inc.id,
                    "agent": r.get("agent", "?"),
                    "ok": r.get("ok"),
                    "degraded": r.get("degraded", False),
                    "error": r.get("error", ""),
                })
        agent_feed = agent_feed[:10]

        total = len(incidents)
        resolved = by_state.get("RESOLVED", 0)
        ops = None
        try:
            ops = _get_ops_loop().status()
        except Exception:
            pass

        recent = []
        for i in sorted(incidents, key=lambda x: str(x.created_at),
                        reverse=True)[:8]:
            recent.append({
                "id": i.id, "severity": i.severity, "type": i.type,
                "host": (i.fields or {}).get("host", "-"),
                "state": i.state.value,
                "created_at": str(i.created_at)[:19],
                "updated_at": str(i.updated_at)[:19],
            })

        return {
            "total": total,
            "active": active,
            "awaiting_approval": by_state.get("AWAITING_APPROVAL", 0),
            "investigating": sum(by_state.get(s, 0)
                                 for s in ACTIVE_INVESTIGATING),
            "resolved": resolved,
            "failed": by_state.get("FAILED", 0) + by_state.get("ESCALATED", 0),
            "new_24h": new_24h,
            "response_success_pct": (round(resolved / total * 100)
                                     if total else None),
            "threats_enriched": ti_lookups + attack_mappings,
            "ti_lookups": ti_lookups,
            "attack_mappings": attack_mappings,
            "by_state": dict(by_state),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "top_assets": [{"host": h, "count": c}
                           for h, c in by_host.most_common(5)],
            "trend7": dict(sorted(trend7.items())),
            "recent": recent,
            "agent_feed": agent_feed,
            "pending_approvals": (ops or {}).get("pending_approvals", 0),
            "loop_running": (ops or {}).get("running"),
            "skipped": skipped,
        }

    AGENT_ROLES = {"A1": "Triage", "A2": "Evidence", "A3": "Correlation",
                   "A4": "ATT&CK Mapping", "A5": "Recommendations"}

    def _agent_feed(limit: int = 20):
        """Phase5: global agent activity from stored runs. Read-only.

        Status derived, never exposes private reasoning.
        # ponytail: scan-in-memory; index records if volume matters.
        """
        out = []
        try:
            ids = st.all_incident_ids()
        except Exception:
            return out
        seen = []
        for iid in ids:
            try:
                inc = st.get(iid)
            except Exception:
                continue
            if inc is not None:
                seen.append(inc)
        seen.sort(key=lambda x: str(x.created_at), reverse=True)
        for inc in seen:
            try:
                runs = st.records(inc.id, "agentrun") or []
                calls = st.records(inc.id, "toolcall") or []
            except Exception:
                continue
            tools_by_agent: dict[str, list] = {}
            for tc in calls:
                tools_by_agent.setdefault(tc.get("agent", "?"), []).append(tc.get("tool", "?"))
            for r in runs:
                ok, deg = r.get("ok"), r.get("degraded", False)
                status = "completed" if ok and not deg else ("degraded" if deg else "failed")
                out.append({
                    "incident_id": inc.id,
                    "host": (inc.fields or {}).get("host", "-"),
                    "severity": inc.severity,
                    "incident_state": inc.state.value,
                    "agent": r.get("agent", "?"),
                    "role": AGENT_ROLES.get(r.get("agent", ""), "-"),
                    "status": status,
                    "ok": ok, "degraded": deg,
                    "error": r.get("error", ""),
                    "llm_attempts": r.get("llm_attempts", 1),
                    "tools": sorted(set(tools_by_agent.get(r.get("agent", "?"), []))),
                    "updated": str(inc.updated_at)[:19],
                })
                if len(out) >= limit:
                    return out
        return out

    @app.get("/api/agents/activity")
    def api_agents_activity(limit: int = 20):
        limit = min(max(limit, 1), 100)
        return {"activity": _agent_feed(limit)}

    @app.get("/console/agents", response_class=HTMLResponse)
    def console_agents(request: Request, limit: int = 20):
        limit = min(max(limit, 1), 100)
        return templates.TemplateResponse(
            request, "agents.html", {"activity": _agent_feed(limit), "limit": limit})

    @app.get("/console/controls", response_class=HTMLResponse)
    def console_controls(request: Request):
        return templates.TemplateResponse(request, "controls.html", {
            "controls": ctl,
        })

    @app.post("/console/controls/toggle/{action}")
    def console_controls_toggle(action: str):
        from fastapi.responses import RedirectResponse
        msg = ""
        if action == "pause":
            if ctl.paused:
                ctl.resume()
                msg = "Resumed"
            else:
                ctl.pause()
                msg = "Paused"
        elif action == "safe_mode":
            if ctl.safe_mode:
                ctl.restore_normal()
                msg = "Safe mode exited"
            else:
                ctl.enter_safe_mode()
                msg = "Safe mode enabled"
        elif action == "approval_all":
            ctl.require_approval_all = not ctl.require_approval_all
            msg = "Require approval toggled"
        return RedirectResponse(f"/console/controls?toast={msg}", status_code=303)

    @app.post("/console/controls/agent/{action}")
    def console_controls_agent(action: str, agent_id: str = ""):
        from fastapi.responses import RedirectResponse
        msg = ""
        if action == "disable" and agent_id:
            ctl.disable_agent(agent_id)
            msg = f"Agent {agent_id} disabled"
        elif action == "enable" and agent_id:
            ctl.enable_agent(agent_id)
            msg = f"Agent {agent_id} enabled"
        return RedirectResponse(f"/console/controls?toast={msg}", status_code=303)

    @app.post("/console/controls/tool/{action}")
    def console_controls_tool(action: str, tool_name: str = ""):
        from fastapi.responses import RedirectResponse
        msg = ""
        if action == "revoke" and tool_name:
            ctl.revoke_tool(tool_name)
            msg = f"Tool {tool_name} revoked"
        elif action == "restore" and tool_name:
            ctl.restore_tool(tool_name)
            msg = f"Tool {tool_name} restored"
        return RedirectResponse(f"/console/controls?toast={msg}", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    def console_index(request: Request, state: str = "", severity: str = "",
                      q: str = "", sort: str = "created", order: str = "desc",
                      page: int = 1, limit: int = 25):
        SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                    "unknown": 4, "info": 5}
        ql = q.strip().lower()
        incidents = []
        for iid in st.all_incident_ids():
            inc = st.get(iid)
            if inc is None:
                continue
            if state and inc.state.value != state:
                continue
            if severity and inc.severity != severity:
                continue
            if ql:
                hay = " ".join([inc.id, inc.type, inc.severity,
                                inc.state.value,
                                str((inc.fields or {}).get("host", ""))]).lower()
                if ql not in hay:
                    continue
            d = inc.model_dump()
            d["created_at"] = str(d["created_at"])[:19]
            d["updated_at"] = str(d["updated_at"])[:19]
            incidents.append(d)
        reverse = order != "asc"
        if sort == "severity":
            incidents.sort(key=lambda x: SEV_RANK.get(str(x.get("severity", "")).lower(), 9),
                           reverse=(order == "asc"))
        elif sort == "state":
            incidents.sort(key=lambda x: str(x.get("state", "")), reverse=reverse)
        else:
            incidents.sort(key=lambda x: str(x.get("created_at", "")), reverse=reverse)
        total = len(incidents)
        page = max(page, 1)
        limit = min(max(limit, 1), 100)
        start = (page - 1) * limit
        incidents = incidents[start:start + limit]
        controls = {
            "paused": ctl.paused, "safe_mode": ctl.safe_mode,
            "require_approval_all": ctl.require_approval_all,
            "disabled_agents": sorted(ctl.disabled_agents),
            "revoked_tools": sorted(ctl.revoked_tools),
        }
        return templates.TemplateResponse(
            request, "index.html", {"incidents": incidents, "controls": controls,
                                    "q": q, "state": state, "severity": severity,
                                    "sort": sort, "order": order,
                                    "page": page, "limit": limit, "total": total})

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
                                "verification", "manifest", "attack_mapping",
                                "approval")}
        replay = []
        for t in timeline:
            replay.append({"ts": t.get("ts", ""), "actor": t.get("actor", "-"),
                           "action": t.get("action", "-"),
                           "detail": t.get("detail", ""), "kind": "timeline"})
        for t in transitions:
            replay.append({"ts": t.get("ts", ""), "actor": t.get("actor", "-"),
                           "action": f"{t['from_state']} → {t['to_state']}",
                           "detail": t.get("reason", ""), "kind": "transition"})
        for a in records.get("approval") or []:
            replay.append({"ts": str(a.get("timestamp", ""))[:19],
                           "actor": a.get("actor", "operator"),
                           "action": f"approval:{a.get('decision', '?')}",
                           "detail": a.get("from_state", ""), "kind": "approval"})
        replay.sort(key=lambda x: x["ts"])
        return templates.TemplateResponse(
            request, "incident.html", {"incident": inc_d,
                                       "timeline": timeline, "evidence": evidence,
                                       "transitions": transitions, "records": records,
                                       "replay": replay,
                                       "stages": STAGES,
                                       "stage_index": STAGE_OF.get(inc.state.value),
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
                                "attack_mapping", "approval",
                                "response_action", "manifest")}
        evidence = [e.model_dump() for e in st.evidence(incident_id)]
        return templates.TemplateResponse(
            request, "response.html", {"incident_id": incident_id,
                                       "incident": inc_d, "records": records,
                                       "evidence": evidence})

    @app.get("/console/audit", response_class=HTMLResponse)
    def console_audit(request: Request, category: str = "", actor: str = ""):
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
        cats = sorted({e["category"] for e in events})
        actors = sorted({e["actor"] for e in events})
        if category:
            events = [e for e in events if e["category"] == category]
        if actor:
            events = [e for e in events if e["actor"] == actor]
        return templates.TemplateResponse(
            request, "audit.html", {"events": events, "cats": cats,
                                    "actors": actors, "category": category,
                                    "actor": actor})

    @app.get("/incidents/{incident_id}/console/graph", response_class=HTMLResponse)
    def console_graph(request: Request, incident_id: str):
        """Evidence graph visualization page."""
        _get(incident_id)
        return templates.TemplateResponse(
            request, "graph.html", {"incident_id": incident_id})

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

    # -- console form actions (redirect back to detail) --

    @app.post("/incidents/{incident_id}/console/approve")
    def console_approve(incident_id: str):
        from fastapi.responses import RedirectResponse
        _get(incident_id)
        current = st.get(incident_id).state
        if current == IncidentState.AWAITING_APPROVAL:
            orch.transition(incident_id, IncidentState.AUTHORIZED,
                            "operator", "approved via console")
        return RedirectResponse(f"/incidents/{incident_id}/console?toast=Approved",
                                status_code=303)

    @app.post("/incidents/{incident_id}/console/deny")
    def console_deny(incident_id: str):
        from fastapi.responses import RedirectResponse
        _get(incident_id)
        current = st.get(incident_id).state
        if current == IncidentState.AWAITING_APPROVAL:
            orch.transition(incident_id, IncidentState.FAILED,
                            "operator", "denied via console")
        return RedirectResponse(f"/incidents/{incident_id}/console?toast=Denied",
                                status_code=303)

    @app.post("/controls/console/cancel/{incident_id}")
    def console_cancel(incident_id: str):
        from fastapi.responses import RedirectResponse
        ctl.cancel_incident(incident_id)
        return RedirectResponse(f"/incidents/{incident_id}/console",
                                status_code=303)

    # -- console: operations --

    @app.get("/console/operations", response_class=HTMLResponse)
    def console_operations(request: Request):
        loop = _get_ops_loop()
        status = loop.status()
        approvals = loop.approval_queue.all_requests()
        return templates.TemplateResponse(
            request, "operations.html",
            {"status": status, "approvals": approvals})

    @app.post("/console/operations/start")
    def console_operations_start():
        from fastapi.responses import RedirectResponse
        loop = _get_ops_loop()
        loop.start()
        return RedirectResponse("/console/operations?toast=Loop+started", status_code=303)

    @app.post("/console/operations/stop")
    def console_operations_stop():
        from fastapi.responses import RedirectResponse
        loop = _get_ops_loop()
        loop.stop()
        return RedirectResponse("/console/operations?toast=Loop+stopped", status_code=303)

    @app.post("/console/operations/cycle")
    def console_operations_cycle():
        from fastapi.responses import RedirectResponse
        loop = _get_ops_loop()
        result = loop.run_cycle()
        msg = f"Cycle complete: {result.get('processed', 0)} processed"
        return RedirectResponse(f"/console/operations?toast={msg}", status_code=303)

    @app.post("/console/operations/approvals/{request_id}/approve")
    def console_operations_approve(request_id: str):
        from fastapi.responses import RedirectResponse
        loop = _get_ops_loop()
        loop.approval_queue.approve(request_id)
        return RedirectResponse("/console/operations?toast=Approved", status_code=303)

    @app.post("/console/operations/approvals/{request_id}/deny")
    def console_operations_deny(request_id: str):
        from fastapi.responses import RedirectResponse
        loop = _get_ops_loop()
        loop.approval_queue.deny(request_id)
        return RedirectResponse("/console/operations?toast=Denied", status_code=303)

    # -- health & readiness --

    @app.get("/health")
    def health():
        """Liveness probe — service is running."""
        return {"status": "ok"}

    @app.get("/ready")
    def ready():
        """Readiness probe — service can handle requests."""
        try:
            st.all_incident_ids()
            return {"status": "ready"}
        except Exception as e:
            return {"status": "not ready", "error": str(e)}, 503

    # -- graph endpoint --

    @app.get("/incidents/{incident_id}/graph")
    def get_graph(incident_id: str):
        """§14 evidence graph: nodes + typed edges."""
        _get(incident_id)
        from aegis.intel.graph import load_graph
        nodes, edges = load_graph(st, incident_id)
        return {"incident_id": incident_id, "nodes": nodes, "edges": edges}

    # -- elastic integration --

    @app.get("/elastic/status", tags=["elastic"])
    def elastic_status():
        """Check ES connection + alert index status."""
        try:
            es_client = get_es_client()
            resp = es_client.count(index=settings.es_alert_index)
            return {"connected": True, "alert_count": resp["count"],
                    "alert_index": settings.es_alert_index}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    @app.post("/elastic/poll", tags=["elastic"])
    def elastic_poll():
        """One poll cycle: fetch uningested alerts → normalize → ingest."""
        from aegis.integrations.elastic_adapter import ElasticAlertPoller
        es_client = get_es_client()
        poller = ElasticAlertPoller(es=es_client, alert_index=settings.es_alert_index, store=st)
        incidents = poller.poll_once()
        return {"polled": len(incidents),
                "incident_ids": [i.id for i in incidents]}

    @app.post("/elastic/synthetic", tags=["elastic"])
    def elastic_synthetic(count: int = 5):
        """Generate synthetic alerts for demo."""
        from aegis.integrations.elastic_adapter import generate_synthetic_alerts
        count = min(count, 100)  # ponytail: cap to prevent abuse
        es_client = get_es_client()
        written = generate_synthetic_alerts(
            es=es_client, index=settings.es_alert_index, count=count)
        return {"generated": written, "index": settings.es_alert_index}

    # -- autonomous operations loop --

    from aegis.operations.loop import OperationsLoop

    _ops_loop: OperationsLoop | None = None

    def _get_ops_loop() -> OperationsLoop:
        nonlocal _ops_loop
        if _ops_loop is None:
            if default_llm is not None:
                loop_llm = default_llm
            else:
                from aegis.slice import FakeLLM
                loop_llm = FakeLLM()
            _ops_loop = OperationsLoop(st, loop_llm, controls=ctl)
        return _ops_loop

    @app.post("/operations/start", tags=["operations"])
    def operations_start(poll_interval: int | None = None):
        loop = _get_ops_loop()
        if poll_interval is not None:
            loop._poll_interval = poll_interval
        loop.start()
        return {"status": "started", **loop.status()}

    @app.post("/operations/stop", tags=["operations"])
    def operations_stop():
        loop = _get_ops_loop()
        loop.stop()
        return {"status": "stopped", **loop.status()}

    @app.get("/operations/status", tags=["operations"])
    def operations_status():
        return _get_ops_loop().status()

    @app.post("/operations/cycle", tags=["operations"])
    def operations_cycle():
        """Run one poll cycle manually (for testing/demo)."""
        return _get_ops_loop().run_cycle()

    @app.get("/operations/approvals", tags=["operations"])
    def operations_approvals():
        queue = _get_ops_loop().approval_queue
        return {"requests": [vars(r) for r in queue.all_requests()],
                **queue.stats()}

    @app.post("/operations/approvals/{request_id}/approve", tags=["operations"])
    def operations_approve(request_id: str):
        queue = _get_ops_loop().approval_queue
        req = queue.approve(request_id)
        if req is None:
            raise HTTPException(404, "Request not found or already resolved")
        return vars(req)

    @app.post("/operations/approvals/{request_id}/deny", tags=["operations"])
    def operations_deny(request_id: str):
        queue = _get_ops_loop().approval_queue
        req = queue.deny(request_id)
        if req is None:
            raise HTTPException(404, "Request not found or already resolved")
        return vars(req)

    return app


app = create_app()
