"""Phase 6: verifier — full set, simulated, generic retry."""

import pytest

from aegis.executor.executor import SimulatedExecutor
from aegis.incidents.schema import IncidentState
from aegis.tools.registry import build_verify_tools
from aegis.verifier.verifier import SimulatedVerifier


def test_verify_host_isolated_pass():
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex)
    ex.isolate_host("win-vm", "inc-1")
    v = vf.verify_host_isolated("win-vm", "inc-1")
    assert v.passed is True
    assert v.actual == "isolated:true"


def test_verify_host_isolated_fail():
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex)
    v = vf.verify_host_isolated("win-vm", "inc-1")
    assert v.passed is False
    assert vf.next_state(v) == IncidentState.REOPENED


def test_retry_escalates_after_limit():
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex, max_retries=2)
    v1 = vf.verify_host_isolated("win-vm", "inc-1")
    assert vf.next_state(v1) == IncidentState.REOPENED
    v2 = vf.verify_host_isolated("win-vm", "inc-1")
    assert vf.next_state(v2) == IncidentState.ESCALATED


def test_pass_resolves_immediately():
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex, max_retries=2)
    # fail once, then fix host and pass — should resolve, not escalate
    vf.verify_host_isolated("win-vm", "inc-1")
    vf.next_state(vf.log[-1])
    ex.isolate_host("win-vm", "inc-1")
    v = vf.verify_host_isolated("win-vm", "inc-1")
    assert vf.next_state(v) == IncidentState.RESOLVED


def test_verify_process_terminated():
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex)
    v = vf.verify_process_terminated("win-vm", "1000", "inc-1")
    assert v.passed is False
    ex.terminate_process("win-vm", "1000")
    v2 = vf.verify_process_terminated("win-vm", "1000", "inc-1")
    assert v2.passed is True


def test_verify_indicator_blocked():
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex)
    v = vf.verify_indicator_blocked("185.220.101.4", "inc-1")
    assert v.passed is False
    ex.block_indicator("185.220.101.4")
    assert vf.verify_indicator_blocked("185.220.101.4", "inc-1").passed is True


def test_verify_persistence_removed():
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex)
    v = vf.verify_persistence_removed("win-vm", "inc-1")
    assert v.passed is False
    ex.remove_persistence("win-vm")
    assert vf.verify_persistence_removed("win-vm", "inc-1").passed is True


def test_verify_tools_gated_to_d2():
    ex = SimulatedExecutor()
    vf = SimulatedVerifier(ex)
    reg = build_verify_tools(vf)
    reg.call("verify_host_isolated", "D2", host="win-vm", incident_id="inc-1")
    with pytest.raises(PermissionError):
        reg.call("verify_host_isolated", "A1", host="win-vm", incident_id="inc-1")
