"""WP-D tests: hash-chain tamper evidence, retry capture, data fields (§18)."""

import sys

sys.path.insert(0, "scripts")

from aegis.audit import AuditRecorder
from aegis.integrations.llm import LLMClient


def test_chain_valid_when_untampered():
    rec = AuditRecorder()
    for i in range(5):
        rec.record("pipeline_stage", "inc-1", actor=f"A{i}", ok=True)
    assert rec.verify_chain() is True


def test_chain_detects_tampering():
    rec = AuditRecorder()
    rec.record("policy_decision", "inc-1", actor="p", decision="DENY")
    rec.record("tool_call", "inc-1", actor="A2", tool="search_events")
    # attacker edits an earlier event in place
    rec.events[0].detail["decision"] = "ALLOW"
    assert rec.verify_chain() is False


def test_chain_detects_deleted_event():
    rec = AuditRecorder()
    rec.record("a", "inc-1")
    rec.record("b", "inc-1")
    rec.record("c", "inc-1")
    del rec.events[1]
    assert rec.verify_chain() is False


def test_seq_and_prev_hash_link():
    rec = AuditRecorder()
    e1 = rec.record("a", "inc-1")
    e2 = rec.record("b", "inc-1")
    assert e1.seq == 0 and e1.prev_hash == ""
    assert e2.seq == 1 and e2.prev_hash == e1.hash


# -- LLM attempt counting (§18 retries) --

class LiteralThenJSON(LLMClient):
    def __init__(self):
        self.prompts = []

    def _call(self, system, user, temperature):
        self.prompts.append(user)
        if len(self.prompts) == 1:
            return "{'classification': 'benign', 'reason': 'failed both 'a' and 'b''}"
        return '{"classification": "benign"}'


def test_corrective_pass_recorded_in_attempts():
    llm = LiteralThenJSON()
    r = llm.complete_json("sys", "user")
    assert r.ok is True
    assert r.attempts == 2
    assert "not valid strict JSON" in llm.prompts[1]


def test_first_try_records_one_attempt():
    class OneShot(LLMClient):
        def __init__(self):
            pass

        def _call(self, system, user, temperature):
            return '{"ok": 1}'

    r = OneShot().complete_json("s", "u")
    assert r.ok is True and r.attempts == 1