"""WP-B tests: most-specific-wins precedence + conditional permissions (§11)."""

import pytest

from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore
from aegis.policies.engine import Decision, evaluate
from aegis.policies.permissions import PermissionContext
from aegis.policies.store import Policy


def _pol(conditions, approval=False, version="1.0"):
    return Policy(action="isolate_host", conditions=conditions,
                  approval_required=approval, risk_class="HIGH", version=version)


FACTS_OK = {"host": "win-vm", "confidence": 0.95, "evidence_count": 4}


# -- precedence: most-specific wins --

def test_specific_overrides_general():
    general = _pol({"confidence": ">= 0.90"}, approval=False, version="1.0")
    specific = _pol({"confidence": ">= 0.90", "evidence_count": ">= 3"},
                    approval=True, version="2.0")
    r = evaluate("isolate_host", FACTS_OK, policies=[general, specific])
    # specific (2 conditions) wins over general (1) even though both pass
    assert r.decision is Decision.APPROVE
    assert r.policy_version == "2.0"


def test_general_fallback_when_specific_fails():
    general = _pol({"confidence": ">= 0.90"}, approval=False, version="1.0")
    specific = _pol({"confidence": ">= 0.90",
                     "evidence_count": ">= 10"}, approval=True, version="2.0")
    r = evaluate("isolate_host", FACTS_OK, policies=[general, specific])
    # specific fails (evidence 4 < 10); generalized fallback to general -> ALLOW
    assert r.decision is Decision.ALLOW
    assert "generalized fallback" in r.reason


def test_all_fail_denies():
    p = _pol({"confidence": ">= 0.99"})
    r = evaluate("isolate_host", FACTS_OK, policies=[p])
    assert r.decision is Decision.DENY


def test_equal_specificity_disagreement_denies():
    a = _pol({"confidence": ">= 0.90"}, approval=False, version="1.0")
    b = _pol({"confidence": ">= 0.90"}, approval=True, version="1.0")
    r = evaluate("isolate_host", {"confidence": 0.95}, policies=[a, b])
    assert r.decision is Decision.DENY
    assert "top specificity" in r.reason


def test_version_breaks_tie():
    lo = _pol({"confidence": ">= 0.90"}, approval=True, version="1.0")
    hi = _pol({"confidence": ">= 0.90"}, approval=False, version="3.1")
    r = evaluate("isolate_host", {"confidence": 0.95}, policies=[lo, hi])
    assert r.decision is Decision.ALLOW
    assert r.policy_version == "3.1"


# -- §11 conditional permissions --

def test_min_state_gate_blocks_early_stage():
    from aegis.tools.registry import build_read_tools
    from aegis.tools.telemetry import InMemoryTelemetry

    reg = build_read_tools(InMemoryTelemetry([]))

    ctx_early = PermissionContext(incident_state="INVESTIGATING")
    reg._permission_provider = lambda agent: ctx_early
    with pytest.raises(PermissionError):
        reg.call("get_authentication_events", "A2", host="win-vm")

    ctx_late = PermissionContext(incident_state="CORRELATING")
    reg._permission_provider = lambda agent: ctx_late
    out = reg.call("get_authentication_events", "A2", host="win-vm")
    assert out == []


def test_min_confidence_gate():
    ctx_low = PermissionContext(incident_state="ASSESSING", confidence=0.4)
    # confidence gate expressed via requires on a tool:
    from aegis.tools.registry import Tool, ToolRegistry

    t = Tool(name="t", schema_in={}, risk_class="READ", reversible=True,
             allowed_agents={"A4"},
             requires={"min_confidence": 0.8},
             func=lambda: {"ok": True})
    reg = ToolRegistry()
    reg.register(t)
    reg._permission_provider = lambda a: ctx_low
    with pytest.raises(PermissionError, match="confidence"):
        reg.call("t", "A4")
    ctx_hi = PermissionContext(incident_state="ASSESSING", confidence=0.95)
    reg._permission_provider = lambda a: ctx_hi
    assert reg.call("t", "A4") == {"ok": True}


def test_forbidden_criticality_gate():
    from aegis.tools.registry import Tool, ToolRegistry

    t = Tool(name="t", schema_in={}, risk_class="READ", reversible=True,
             allowed_agents={"A4"},
             requires={"forbidden_criticality": "critical"},
             func=lambda: {})
    reg = ToolRegistry()
    reg.register(t)
    reg._permission_provider = lambda a: PermissionContext(
        asset_criticality="critical")
    with pytest.raises(PermissionError, match="asset is critical"):
        reg.call("t", "A4")


# -- slice wires per-agent stage context --

def test_slice_sets_permission_provider():
    from aegis.slice import investigate

    store = InMemoryStore()
    inc = ingest_alert(store, source="t",
                       fields={"host": "win-vm"}, incident_type="powershell")

    captured = {}

    class FakeReg:
        controls = None
        calls = []

        def set_permission_provider(self, fn):
            captured["fn"] = fn

        def authorized_tools(self, agent):
            return []

        def call(self, name, agent, **kwargs):
            return []

    import aegis.slice as sl

    class FakeOrch:
        def __init__(self, store):
            pass

        def transition(self, inc_id, to_state, actor, reason):
            return None

    real_orch = sl.Orchestrator
    sl.Orchestrator = FakeOrch
    try:
        res = investigate(store, inc.id, _FakeLLM(), registry=FakeReg())
    finally:
        sl.Orchestrator = real_orch

    ctx = captured["fn"]("A4")
    assert ctx.incident_state == "ASSESSING"
    # zero persisted evidence -> policy DENY (honest)
    assert res["decision"].decision.value == "DENY"
    assert res["evidence_count"] == 0


class _FakeLLM:
    def __init__(self):
        pass

    @property
    def model_tag(self):
        return "fake"

    def complete_json(self, system, user, temperature=0.0):
        from aegis.integrations.llm import LLMResult

        data = {"summary": "s", "hypotheses": [], "evidence_ids": [],
                "open_questions": [], "classification": "malicious",
                "severity": "high", "investigate": True, "reason": "r",
                "assessment": "malicious", "confidence": 0.95,
                "attack_mapping": "", "recommended_actions": [],
                "rationale": "r", "risks": []}
        return LLMResult(ok=True, data=data, raw="{}")