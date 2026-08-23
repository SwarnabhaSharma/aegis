"""Phase 5: simulated executor + idempotency."""

import pytest

from aegis.executor.executor import SimulatedExecutor
from aegis.tools.registry import build_response_tools


def test_isolate_sets_isolated():
    ex = SimulatedExecutor()
    r = ex.isolate_host("win-vm", "inc-1")
    assert r.isolated is True
    assert r.status == "isolated"
    assert ex.is_isolated("win-vm") is True


def test_idempotent_second_call_same_key():
    ex = SimulatedExecutor()
    r1 = ex.isolate_host("win-vm", "inc-1")
    r2 = ex.isolate_host("win-vm", "inc-1")
    assert r1 == r2
    assert len(ex.actions) == 1


def test_explicit_idempotency_key():
    ex = SimulatedExecutor()
    r1 = ex.isolate_host("win-vm", "inc-1", idempotency_key="k1")
    r2 = ex.isolate_host("win-vm", "inc-1", idempotency_key="k1")
    r3 = ex.isolate_host("win-vm", "inc-1", idempotency_key="k2")
    assert r1 == r2
    assert r3.status == "already_isolated"
    assert len(ex.actions) == 2


def test_different_hosts_independent():
    ex = SimulatedExecutor()
    ex.isolate_host("win-vm", "inc-1")
    assert ex.is_isolated("other-host") is False
    ex.isolate_host("other-host", "inc-2")
    assert ex.is_isolated("win-vm") is True


def test_response_tool_restricted_to_executor():
    ex = SimulatedExecutor()
    reg = build_response_tools(ex)
    r = reg.call("isolate_host", "D1", host="win-vm", incident_id="inc-1")
    assert r.isolated is True
    with pytest.raises(PermissionError):
        reg.call("isolate_host", "A1", host="win-vm", incident_id="inc-1")


def test_unknown_tool_rejected():
    ex = SimulatedExecutor()
    reg = build_response_tools(ex)
    with pytest.raises(KeyError):
        reg.call("nonexistent_action", "D1", host="win-vm", incident_id="inc-1")
