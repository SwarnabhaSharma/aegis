"""T2 tests: emergency controls (§17), new read tools, executor/verify loop,
ActionSpec, registry-gated execution (#7)."""

import pytest

from aegis.controls import ControlState
from aegis.executor.executor import SimulatedExecutor
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.schema import IncidentState
from aegis.incidents.store import InMemoryStore
from aegis.slice import execute_and_verify
from aegis.tools.registry import build_read_tools, build_response_tools
from aegis.tools.telemetry import InMemoryTelemetry, TelemetryEvent


class FakeLLM:
    """Minimal offline LLM stand-in for pipeline tests."""

    def __init__(self):
        pass

    def complete_json(self, system, user, temperature=0.0):
        from aegis.integrations.llm import LLMResult

        data = {"summary": "s", "hypotheses": [], "evidence_ids": [],
                "open_questions": [], "classification": "malicious",
                "severity": "high", "investigate": True, "reason": "r",
                "assessment": "malicious", "confidence": 0.95,
                "attack_mapping": "", "recommended_actions": [],
                "rationale": "r", "risks": []}
        return LLMResult(ok=True, data=data, raw="{}")


def _telemetry():
    return InMemoryTelemetry([
        TelemetryEvent(event_id="11", channel="sysmon", action="FileCreate",
                       host="win-vm", process_name="powershell.exe",
                       file_path="C:\\ProgramData\\payload.dll"),
        TelemetryEvent(event_id="4624", channel="Security", action="Logon",
                       host="win-vm", user="alice"),
        TelemetryEvent(event_id="1", channel="sysmon", action="ProcessCreate",
                       host="win-vm", process_name="explorer.exe"),
    ])


# -- §17 emergency controls --

def test_pause_blocks_pipeline():
    from aegis.agents.pipeline import AgentPipeline

    ctl = ControlState()
    ctl.pause()
    pipe = AgentPipeline(FakeLLM(), controls=ctl)
    steps, _ = pipe.run({"incident_id": "i"}, {})
    assert steps[0].degraded is True
    assert "paused" in steps[0].error


def test_safe_mode_implies_pause_and_approval():
    ctl = ControlState()
    ctl.enter_safe_mode()
    assert ctl.autonomy_blocked() is True
    assert ctl.require_approval_all is True
    ctl.restore_normal()
    assert ctl.autonomy_blocked() is False


def test_disabled_agent_stops_run():
    from aegis.agents.pipeline import AgentPipeline

    ctl = ControlState()
    ctl.disable_agent("A3")
    pipe = AgentPipeline(FakeLLM(), controls=ctl)
    steps, _ = pipe.run({"incident_id": "i"}, {})
    # A1, A2 ok; A3 disabled -> fail-safe stop
    assert [s.agent for s in steps] == ["A1", "A2", "A3"]
    assert steps[-1].error == "agent disabled by operator"


def test_revoked_tool_rejected_at_registry():
    reg = build_read_tools(_telemetry())
    ctl = ControlState()
    reg.controls = ctl
    reg.call("lookup_ip", "A4", ip="8.8.8.8")  # allowed pre-revocation
    ctl.revoke_tool("lookup_ip")
    with pytest.raises(PermissionError, match="revoked by operator"):
        reg.call("lookup_ip", "A4", ip="8.8.8.8")
    ctl.restore_tool("lookup_ip")
    reg.call("lookup_ip", "A4", ip="9.9.9.9")


def test_require_approval_all_flips_allow(tmp_path=None):
    # exercised via slice.investigate: ALLOW -> AWAITING_APPROVAL state
    from aegis.slice import run_full_slice

    ctl = ControlState()
    ctl.require_approval_all = True
    res = run_full_slice(host="win-vm", llm_mode="fake", controls=ctl)
    # slice auto-approves in CLI mode; but decision record must show APPROVE
    assert res["decision"].decision.value == "APPROVE"


# -- new read tools --

def test_get_file_activity():
    reg = build_read_tools(_telemetry())
    ev = reg.call("get_file_activity", "A2", host="win-vm")
    assert len(ev) == 1
    assert ev[0].file_path.endswith("payload.dll")


def test_get_authentication_events():
    reg = build_read_tools(_telemetry())
    ev = reg.call("get_authentication_events", "A2", host="win-vm")
    assert len(ev) == 1 and ev[0].user == "alice"


def test_get_host_details():
    reg = build_read_tools(_telemetry())
    d = reg.call("get_host_details", "A1", host="win-vm")
    assert d["seen"] is True
    assert d["event_count"] == 3
    assert "sysmon" in d["channels"]


# -- executor/verifier loop closed (#11) --

def test_terminate_and_verify_pass_naturally():
    ex = SimulatedExecutor()
    from aegis.verifier.verifier import SimulatedVerifier

    vf = SimulatedVerifier(ex)
    ex.terminate_process("win-vm", "1000")
    v = vf.verify_process_terminated("win-vm", "1000", "inc-1")
    assert v.passed is True


def test_block_indicator_and_verify():
    ex = SimulatedExecutor()
    from aegis.verifier.verifier import SimulatedVerifier

    vf = SimulatedVerifier(ex)
    ex.block_indicator("185.220.101.4")
    assert vf.verify_indicator_blocked("185.220.101.4", "inc-1").passed is True


def test_remove_persistence_and_verify():
    ex = SimulatedExecutor()
    from aegis.verifier.verifier import SimulatedVerifier

    vf = SimulatedVerifier(ex)
    ex.remove_persistence("win-vm")
    assert vf.verify_persistence_removed("win-vm", "inc-1").passed is True


# -- ActionSpec (#16) + registry-gated execution (#7) --

def test_response_tools_carry_action_specs():
    ex = SimulatedExecutor()
    reg = build_response_tools(ex)
    for name in ("isolate_host", "terminate_process", "block_indicator"):
        spec = reg.get(name).spec
        assert spec["expected_result"]
        assert spec["verification_method"]
        assert spec["failure_behavior"]


def _drive_to_authorized(store, inc_id):
    from aegis.orchestrator.engine import Orchestrator

    orch = Orchestrator(store)
    for st in (IncidentState.TRIAGING, IncidentState.INVESTIGATING,
               IncidentState.CORRELATING, IncidentState.ASSESSING,
               IncidentState.RESPONSE_PLANNED, IncidentState.AUTHORIZED):
        orch.transition(inc_id, st, "orchestrator", "test")


def test_execution_through_registry_gate():
    store = InMemoryStore()

    # route through the gate like the slice tail does (incident AUTHORIZED)
    inc = ingest_alert(store, source="t", fields={"host": "win-vm"},
                       incident_type="powershell")
    _drive_to_authorized(store, inc.id)
    verifications = execute_and_verify(store, inc.id, "win-vm",
                                       controls=ControlState())
    assert verifications[0].passed is True

    # revoked isolate_host must now block execution entirely (fresh incident:
    # the first one is RESOLVED, and EXECUTING from RESOLVED is invalid)
    ctl = ControlState()
    ctl.revoke_tool("isolate_host")
    inc2 = ingest_alert(store, source="t", fields={"host": "win-vm"},
                        incident_type="powershell")
    _drive_to_authorized(store, inc2.id)
    with pytest.raises(PermissionError, match="revoked"):
        execute_and_verify(store, inc2.id, "win-vm", controls=ctl)


def test_env_seeded_controls(monkeypatch):
    monkeypatch.setenv("AEGIS_SAFE_MODE", "1")
    ctl = ControlState.from_env()
    assert ctl.autonomy_blocked() is True
    assert ctl.require_approval_all is True