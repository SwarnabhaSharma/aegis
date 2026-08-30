"""Tamper hash chain tests (§18). Evidence integrity + audit chain verification."""

from aegis.audit import AuditRecorder
from aegis.incidents.evidence import Evidence, evidence_from_tool_result


def _fake_event(event_id="1", host="win-vm"):
    class E:
        pass
    e = E()
    e.event_id = event_id
    e.host = host
    e.action = "ProcessCreate"
    e.process_name = "powershell.exe"
    e.process_pid = "1000"
    e.process_parent = "cmd.exe"
    e.command_line = "powershell -enc test"
    e.file_path = ""
    e.destination_ip = ""
    e.destination_port = ""
    e.user = ""
    e.raw = None
    return e


# -- evidence hash --

def test_evidence_hash_deterministic():
    ev = Evidence(incident_id="inc-1", source="test", collection_method="test")
    h1 = ev.compute_hash()
    h2 = ev.compute_hash()
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_evidence_hash_changes_on_data_mutate():
    ev = Evidence(incident_id="inc-1", source="test", collection_method="test")
    h1 = ev.compute_hash()
    ev.data["host"] = "different-host"
    ev.hash = ev.compute_hash()
    assert ev.hash != h1


def test_evidence_hash_changes_on_id_mutate():
    ev = Evidence(incident_id="inc-1", source="test", collection_method="test")
    h1 = ev.compute_hash()
    ev.id = "ev-tampered"
    ev.hash = ev.compute_hash()
    assert ev.hash != h1


def test_evidence_from_tool_result_computes_hash():
    events = [_fake_event()]
    records = evidence_from_tool_result("inc-1", "test", events)
    assert len(records) == 1
    assert records[0].hash
    assert len(records[0].hash) == 64


# -- audit chain --

def test_chain_valid_when_untampered():
    rec = AuditRecorder()
    for i in range(5):
        rec.record("test", f"inc-{i}", actor="tester", seq=i)
    assert rec.verify_chain()


def test_chain_detects_tampering():
    rec = AuditRecorder()
    for i in range(3):
        rec.record("test", f"inc-{i}", actor="tester")
    rec.events[1].detail["actor"] = "tampered"
    assert not rec.verify_chain()


def test_chain_detects_deleted_event():
    rec = AuditRecorder()
    for i in range(5):
        rec.record("test", f"inc-{i}", actor="tester")
    rec.events.pop(2)
    assert not rec.verify_chain()


def test_chain_empty_is_valid():
    rec = AuditRecorder()
    assert rec.verify_chain()


# -- evidence integrity verification --

def test_verify_evidence_integrity_clean():
    from aegis.audit import verify_evidence_integrity

    events = [_fake_event(), _fake_event("3")]
    records = evidence_from_tool_result("inc-1", "test", events)
    result = verify_evidence_integrity(records)
    assert result["ok"] is True
    assert result["mismatches"] == []


def test_verify_evidence_integrity_detects_tamper():
    from aegis.audit import verify_evidence_integrity

    events = [_fake_event()]
    records = evidence_from_tool_result("inc-1", "test", events)
    # tamper with data after hash was computed
    records[0].data["host"] = "TAMPERED"
    result = verify_evidence_integrity(records)
    assert result["ok"] is False
    assert len(result["mismatches"]) == 1
    assert result["mismatches"][0]["id"] == records[0].id
