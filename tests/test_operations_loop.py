"""Tests for operations loop — single-cycle and status."""

from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore
from aegis.operations.loop import OperationsLoop
from aegis.slice import FakeLLM


def _make_store_with_alerts(n=3):
    store = InMemoryStore()
    for _ in range(n):
        ingest_alert(store, "synthetic",
                     {"severity": "high", "host": "win-vm",
                      "process": "powershell.exe"},
                     incident_type="powershell")
    return store


def test_status_initial():
    store = _make_store_with_alerts()
    loop = OperationsLoop(store, FakeLLM(), poll_interval=999)
    status = loop.status()
    assert status["running"] is False
    assert status["processed"] == 0
    assert status["pending_approvals"] == 0
    assert status["poll_interval"] == 999


def test_run_cycle_processes_one():
    store = _make_store_with_alerts(1)
    loop = OperationsLoop(store, FakeLLM(), poll_interval=999)
    result = loop.run_cycle()
    assert result["processed"] == 1
    assert loop.state.processed == 1


def test_run_cycle_nothing_to_do():
    store = InMemoryStore()  # empty
    loop = OperationsLoop(store, FakeLLM(), poll_interval=999)
    result = loop.run_cycle()
    assert result["processed"] == 0
    assert result["reason"] == "no new incidents"


def test_start_stop():
    store = _make_store_with_alerts(1)
    loop = OperationsLoop(store, FakeLLM(), poll_interval=999)
    loop.start()
    assert loop.state.running is True
    loop.stop()
    assert loop.state.running is False
