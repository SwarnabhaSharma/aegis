"""Phase 4 tests: policy engine (ADR-006, J.2). Table-driven."""

import pytest

from aegis.policies.engine import Decision, evaluate
from aegis.policies.store import Policy

# shared facts matching the PowerShell slice (phase-d O.3)
ALLOW_FACTS = {"host": "win-vm", "confidence": 0.95, "evidence_count": 4}
LOW_CONF = {"host": "win-vm", "confidence": 0.80, "evidence_count": 4}
FEW_EV = {"host": "win-vm", "confidence": 0.95, "evidence_count": 2}
CRITICAL = {"host": "critical-box", "confidence": 0.95, "evidence_count": 4}

CASES = [
    # (facts, override, expected)
    (ALLOW_FACTS, None, Decision.ALLOW),                                   # auto-allow
    (LOW_CONF, None, Decision.DENY),                                       # low confidence
    (FEW_EV, None, Decision.DENY),                                         # few evidence
    (CRITICAL, None, Decision.DENY),                                       # critical asset
    (ALLOW_FACTS, Decision.ALLOW, Decision.ALLOW),                         # override
    (ALLOW_FACTS, Decision.DENY, Decision.DENY),                           # override
]


@pytest.mark.parametrize("facts,override,expected", CASES)
def test_policy_cases(facts, override, expected):
    r = evaluate("isolate_host", facts, override=override)
    assert r.decision is expected
    assert r.action == "isolate_host"


def test_no_policy_for_action_denies():
    r = evaluate("escalate_privileges", ALLOW_FACTS)
    assert r.decision is Decision.DENY
    assert r.reason == "no policy for action"


def test_dry_run_does_not_change_decision():
    r = evaluate("isolate_host", ALLOW_FACTS, dry_run=True)
    assert r.decision is Decision.ALLOW
    assert r.dry_run is True
    assert r.overridden is False


def test_override_recorded():
    r = evaluate("isolate_host", ALLOW_FACTS, override=Decision.DENY)
    assert r.decision is Decision.DENY
    assert r.overridden is True
    assert r.policy_version == "override"


def test_conflict_denies_failsafe():
    # identical versions that disagree -> fail-safe DENY
    allow = _pol({"confidence": ">= 0.90"}, approval=False, version="2.0")
    approve = _pol({"confidence": ">= 0.90"}, approval=True, version="2.0")
    r = evaluate("isolate_host", {"confidence": 0.95}, policies=[allow, approve])
    assert r.decision is Decision.DENY
    assert "top specificity" in r.reason


def test_newer_version_wins_same_specificity():
    old = _pol({"confidence": ">= 0.90"}, approval=True, version="1.0")
    new = _pol({"confidence": ">= 0.90"}, approval=False, version="2.0")
    r = evaluate("isolate_host", {"confidence": 0.95}, policies=[old, new])
    assert r.decision is Decision.ALLOW
    assert r.policy_version == "2.0"


def _pol(conditions, approval=False, version="1.0"):
    return Policy(action="isolate_host", conditions=conditions,
                  approval_required=approval, risk_class="HIGH", version=version)


def test_approval_required_yields_approve():
    p = Policy(action="isolate_host", conditions={"confidence": ">= 0.90"},
               approval_required=True, risk_class="HIGH", version="1.0")
    r = evaluate("isolate_host", {"confidence": 0.95}, policies=[p])
    assert r.decision is Decision.APPROVE


def test_unknown_condition_op_rejected():
    p = Policy(action="isolate_host", conditions={"confidence": "~ 0.90"},
               approval_required=False, risk_class="HIGH", version="1.0")
    with pytest.raises(ValueError, match="unsupported condition op"):
        evaluate("isolate_host", {"confidence": 0.95}, policies=[p])


def test_present_condition():
    p = Policy(action="isolate_host", conditions={"threat_mapping": "present"},
               approval_required=False, risk_class="HIGH", version="1.0")
    assert evaluate("isolate_host", {"threat_mapping": "T1059.001"},
                    policies=[p]).decision is Decision.ALLOW
    assert evaluate("isolate_host", {"threat_mapping": None},
                    policies=[p]).decision is Decision.DENY