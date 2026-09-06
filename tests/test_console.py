"""Console UI rendering + operations API route tests."""

import pytest
from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore
from aegis.slice import FakeLLM


@pytest.fixture()
def client():
    app = create_app(store=InMemoryStore(), llm=FakeLLM())
    return TestClient(app), app


def _seed_incidents(store, n=2):
    ids = []
    for _ in range(n):
        inc = ingest_alert(store, "synthetic",
                           {"severity": "high", "host": "win-vm",
                            "process": "powershell.exe"},
                           incident_type="powershell")
        ids.append(inc.id)
    return ids


# --- Console UI pages render 200 ---

def test_dashboard_renders(client):
    c, _ = client
    r = c.get("/dashboard")
    assert r.status_code == 200
    assert "Overview" in r.text


def test_overview_endpoint_empty(client):
    c, _ = client
    r = c.get("/api/overview")
    assert r.status_code == 200
    d = r.json()
    assert d["total"] == 0
    assert d["response_success_pct"] is None
    assert d["recent"] == [] and d["agent_feed"] == []


def test_incidents_search_and_page(client):
    c, app = client
    _seed_incidents(app.state.store)
    assert len(c.get("/incidents", params={"q": "win-vm"}).json()) == 2
    assert c.get("/incidents", params={"q": "no-such-host"}).json() == []
    assert len(c.get("/incidents", params={"page": 2, "limit": 1}).json()) == 1


def test_replay_merged_shape(client):
    c, app = client
    ids = _seed_incidents(app.state.store)
    r = c.get(f"/incidents/{ids[0]}/replay")
    assert r.status_code == 200
    d = r.json()
    assert d["stages"] == ["Triage", "Investigate", "Assess", "Respond", "Verify"]
    assert d["stage_index"] == 0
    assert isinstance(d["replay"], list)


def test_p3a_stamped_records_merge(client):
    """P3a: writers stamp ts + data fields; replay merges all five kinds."""
    import aegis.slice as sl

    c, app = client
    st = app.state.store
    inc = _seed_incidents(st)[0]
    res = sl.investigate(st, inc, sl.FakeLLM())
    assert res["ok"]
    pol = st.records(inc, "policy")
    assert pol and pol[0].get("timestamp")
    runs = st.records(inc, "agentrun")
    assert runs and runs[0].get("data_requested")
    kinds = {i["kind"] for i in c.get(f"/incidents/{inc}/replay").json()["replay"]}
    assert {"timeline", "transition", "policy"} <= kinds


def test_agents_activity_empty(client):
    c, _ = client
    r = c.get("/api/agents/activity")
    assert r.status_code == 200
    assert r.json() == {"activity": []}
    r = c.get("/console/agents")
    assert r.status_code == 200
    assert "Agent Activity" in r.text


def test_response_chain_renders(client):
    c, app = client
    ids = _seed_incidents(app.state.store)
    r = c.get(f"/incidents/{ids[0]}/response")
    assert r.status_code == 200
    assert "Recommendation" in r.text and "Verification" in r.text
    assert "Approve" in r.text or "No approval step reached" in r.text


def test_privacy_log_and_audit_filter(client):
    c, app = client
    ids = _seed_incidents(app.state.store)
    r = c.get(f"/incidents/{ids[0]}/privacy")
    assert r.status_code == 200
    assert "Data Access Log" in r.text
    r = c.get("/console/audit", params={"category": "no-such-cat"})
    assert r.status_code == 200


def test_no_innerhtml_sinks():
    """P0: API/telemetry strings must reach textContent, never innerHTML."""
    import pathlib

    for tpl in (pathlib.Path(__file__).resolve().parents[1] / "templates").glob("*.html"):
        src = tpl.read_text(encoding="utf-8")
        hits = [ln for ln in src.splitlines()
                if "innerHTML" in ln and "textContent only" not in ln]
        assert not hits, f"{tpl.name}: {hits}"


def test_incidents_index_renders(client):
    c, app = client
    _seed_incidents(app.state.store)
    r = c.get("/")
    assert r.status_code == 200
    assert "Incidents" in r.text


def test_incident_detail_renders(client):
    c, app = client
    ids = _seed_incidents(app.state.store)
    r = c.get(f"/incidents/{ids[0]}/console")
    assert r.status_code == 200


def test_operations_renders(client):
    c, _ = client
    r = c.get("/console/operations")
    assert r.status_code == 200
    assert "Autonomous Operations" in r.text


def test_controls_renders(client):
    c, _ = client
    r = c.get("/console/controls")
    assert r.status_code == 200
    assert "Emergency Controls" in r.text


def test_audit_renders(client):
    c, _ = client
    r = c.get("/console/audit")
    assert r.status_code == 200


def test_graph_renders(client):
    c, app = client
    ids = _seed_incidents(app.state.store)
    r = c.get(f"/incidents/{ids[0]}/console/graph")
    assert r.status_code == 200
    assert "Evidence Graph" in r.text


# --- Operations API routes ---

def test_operations_status(client):
    c, _ = client
    r = c.get("/operations/status")
    assert r.status_code == 200
    body = r.json()
    assert "running" in body
    assert "processed" in body


def test_operations_start_stop(client):
    c, _ = client
    r = c.post("/operations/start")
    assert r.status_code == 200
    assert r.json()["running"] is True

    r = c.post("/operations/stop")
    assert r.status_code == 200
    assert r.json()["running"] is False


def test_operations_cycle(client):
    c, _ = client
    r = c.post("/operations/cycle")
    assert r.status_code == 200


def test_operations_approvals(client):
    c, _ = client
    r = c.get("/operations/approvals")
    assert r.status_code == 200
    assert "requests" in r.json()


# --- Controls console routes ---

def test_controls_toggle_pause(client):
    c, _ = client
    r = c.post("/console/controls/toggle/pause", follow_redirects=False)
    assert r.status_code == 303
    assert "toast=" in r.headers["location"]


def test_controls_toggle_safe_mode(client):
    c, _ = client
    r = c.post("/console/controls/toggle/safe_mode", follow_redirects=False)
    assert r.status_code == 303


def test_controls_agent_disable_enable(client):
    c, _ = client
    r = c.post("/console/controls/agent/disable?agent_id=A1",
               follow_redirects=False)
    assert r.status_code == 303

    r = c.post("/console/controls/agent/enable?agent_id=A1",
               follow_redirects=False)
    assert r.status_code == 303


def test_controls_tool_revoke_restore(client):
    c, _ = client
    r = c.post("/console/controls/tool/revoke?tool_name=read_process_tree",
               follow_redirects=False)
    assert r.status_code == 303

    r = c.post("/console/controls/tool/restore?tool_name=read_process_tree",
               follow_redirects=False)
    assert r.status_code == 303


# --- Operations console routes ---

def test_operations_console_start_stop(client):
    c, _ = client
    r = c.post("/console/operations/start", follow_redirects=False)
    assert r.status_code == 303
    assert "toast=" in r.headers["location"]

    r = c.post("/console/operations/stop", follow_redirects=False)
    assert r.status_code == 303


def test_operations_console_approve_deny(client):
    c, _ = client
    # Enqueue first via API
    from aegis.operations.loop import OperationsLoop
    loop = OperationsLoop(InMemoryStore(), FakeLLM())
    req = loop.approval_queue.enqueue("inc-test", "isolate_host", "reason")

    # Approve via console
    r = c.post(f"/console/operations/approvals/{req.id}/approve",
               follow_redirects=False)
    assert r.status_code == 303


def test_console_auth_gates_html_and_json(client):
    """P2: with a key configured, console renders 403 page, API gets 401."""
    from aegis.config import get_settings

    settings = get_settings()
    old = settings.aegis_api_key
    settings.aegis_api_key = "test-key"
    try:
        c, app = client
        ids = _seed_incidents(app.state.store)
        r = c.get("/dashboard")
        assert r.status_code == 403
        assert "Restricted" in r.text
        assert ids[0] not in r.text  # no incident data leaks
        r = c.get("/incidents")
        assert r.status_code == 401
        r = c.get("/dashboard", headers={"X-API-Key": "test-key"})
        assert r.status_code == 200
        r = c.get("/health")
        assert r.status_code == 200
    finally:
        settings.aegis_api_key = old
