"""Phase 1 tests: state machine, ingestion, orchestrator flow."""

import pytest

from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.schema import IncidentState
from aegis.incidents.store import InMemoryStore
from aegis.orchestrator.engine import Orchestrator
from aegis.orchestrator.state_machine import (
    OPERATOR,
    ORCHESTRATOR,
    InvalidTransition,
    can_transition,
)


def test_happy_path_transition_table():
    assert can_transition(ORCHESTRATOR, IncidentState.NEW, IncidentState.TRIAGING)
    assert can_transition(ORCHESTRATOR, IncidentState.VERIFYING, IncidentState.RESOLVED)
    assert can_transition(ORCHESTRATOR, IncidentState.REOPENED, IncidentState.INVESTIGATING)


def test_invalid_transition_rejected():
    # NEW -> EXECUTING is not allowed for orchestrator
    assert not can_transition(ORCHESTRATOR, IncidentState.NEW, IncidentState.EXECUTING)
    # LLM agent has no transition rights at all
    assert not can_transition("A1", IncidentState.NEW, IncidentState.TRIAGING)


def test_fail_safe_targets_from_any_state():
    assert can_transition(ORCHESTRATOR, IncidentState.INVESTIGATING, IncidentState.ESCALATED)
    assert can_transition(ORCHESTRATOR, IncidentState.AWAITING_APPROVAL, IncidentState.FAILED)


def test_ingest_creates_new_incident():
    store = InMemoryStore()
    inc = ingest_alert(
        store, source="kibana", fields={"severity": "high"}, incident_type="powershell"
    )
    assert inc.state == IncidentState.NEW
    assert inc.type == "powershell"
    assert store.get(inc.id) is not None


def test_orchestrator_full_cycle():
    store = InMemoryStore()
    orch = Orchestrator(store)
    inc = ingest_alert(store, source="kibana", fields={}, incident_type="powershell")

    path = [
        IncidentState.TRIAGING,
        IncidentState.INVESTIGATING,
        IncidentState.CORRELATING,
        IncidentState.ASSESSING,
        IncidentState.RESPONSE_PLANNED,
        IncidentState.AWAITING_APPROVAL,
    ]
    for target in path:
        inc = orch.transition(inc.id, target, ORCHESTRATOR)

    # operator approves
    inc = orch.transition(inc.id, IncidentState.AUTHORIZED, OPERATOR)
    assert inc.state == IncidentState.AUTHORIZED

    for target in (IncidentState.EXECUTING, IncidentState.VERIFYING):
        inc = orch.transition(inc.id, target, ORCHESTRATOR)
    assert inc.state == IncidentState.VERIFYING

    inc = orch.transition(inc.id, IncidentState.RESOLVED, ORCHESTRATOR)
    assert inc.state == IncidentState.RESOLVED
    assert inc.version >= len(path) + 4


def test_unauthorized_actor_rejected():
    store = InMemoryStore()
    orch = Orchestrator(store)
    inc = ingest_alert(store, source="kibana", fields={}, incident_type="powershell")
    with pytest.raises(InvalidTransition):
        orch.transition(inc.id, IncidentState.TRIAGING, "A1")


def test_transition_logged():
    store = InMemoryStore()
    orch = Orchestrator(store)
    inc = ingest_alert(store, source="kibana", fields={}, incident_type="powershell")
    orch.transition(inc.id, IncidentState.TRIAGING, ORCHESTRATOR)
    assert len(store.transitions(inc.id)) == 1
    assert store.transitions(inc.id)[0].to_state == IncidentState.TRIAGING
