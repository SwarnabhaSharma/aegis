"""Phase 2 tests: tool registry authorization, read tools, evidence + timeline."""

import pytest

from aegis.incidents.evidence import evidence_from_tool_result
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore
from aegis.orchestrator.engine import Orchestrator
from aegis.orchestrator.state_machine import ORCHESTRATOR
from aegis.tools.registry import (
    AGENT_INVESTIGATION,
    AGENT_PLANNER,
    AGENT_THREAT,
    build_read_tools,
)
from aegis.tools.telemetry import InMemoryTelemetry, TelemetryEvent

EVENTS = [
    TelemetryEvent(
        event_id="1", channel="sysmon", action="ProcessCreate", host="win-vm",
        process_name="powershell.exe", process_pid="100",
        process_parent="winword.exe", process_parent_pid="50",
        command_line="powershell -enc SQBFAFA=",
    ),
    TelemetryEvent(
        event_id="3", channel="sysmon", action="NetworkConnect", host="win-vm",
        process_name="powershell.exe", process_pid="100",
        destination_ip="185.220.101.4", destination_port="443",
    ),
    TelemetryEvent(
        event_id="11", channel="sysmon", action="FileCreate", host="win-vm",
        process_name="powershell.exe", process_pid="100", file_path="C:\\evil.ps1",
    ),
]


@pytest.fixture
def registry():
    return build_read_tools(InMemoryTelemetry(EVENTS))


def test_search_events(registry):
    results = registry.call("search_events", AGENT_INVESTIGATION, event_id="1", host="win-vm")
    assert len(results) == 1
    assert results[0].process_name == "powershell.exe"


def test_unauthorized_agent_rejected(registry):
    with pytest.raises(PermissionError):
        registry.call("get_process_tree", AGENT_PLANNER, host="win-vm")


def test_unknown_tool_rejected(registry):
    with pytest.raises(KeyError):
        registry.call("isolate_host", AGENT_INVESTIGATION)


def test_process_tree(registry):
    results = registry.call("get_process_tree", AGENT_INVESTIGATION, host="win-vm", pid="100")
    assert all(e.event_id == "1" for e in results)


def test_lookup_ip_known_malicious(registry):
    r = registry.call("lookup_ip", AGENT_THREAT, ip="185.220.101.4")
    assert r["known_malicious"] is True
    r2 = registry.call("lookup_ip", AGENT_THREAT, ip="8.8.8.8")
    assert r2["known_malicious"] is False


def test_get_policy(registry):
    r = registry.call("get_policy", AGENT_PLANNER, incident_type="powershell")
    assert len(r) == 1
    assert r[0].action == "isolate_host"


def test_evidence_and_timeline():
    store = InMemoryStore()
    inc = ingest_alert(store, source="kibana", fields={}, incident_type="powershell")
    orch = Orchestrator(store)
    orch.transition(inc.id, "TRIAGING", ORCHESTRATOR)

    evs = evidence_from_tool_result(inc.id, "search_events", EVENTS[:1])
    for ev in evs:
        store.add_evidence(ev)

    assert len(store.evidence(inc.id)) == 1
    assert store.evidence(inc.id)[0].collection_method == "search_events"
    # timeline: 1 transition + 1 evidence
    assert len(store.timeline(inc.id)) == 2
    assert store.timeline(inc.id)[0].action == "transition"
    assert store.timeline(inc.id)[1].action == "evidence"


def test_evidence_links_source():
    ev = evidence_from_tool_result("inc-1", "get_process_tree", EVENTS)[0]
    assert ev.incident_id == "inc-1"
    assert ev.data["process"] == "powershell.exe"
    assert ev.data["host"] == "win-vm"
