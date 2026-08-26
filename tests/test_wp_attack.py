"""ATT&CK mapping tests: structured A4 output, validation gate, MAPPED_TO
edges, eval metric math."""

import sys

sys.path.insert(0, "scripts")

from aegis.agents.validation import validate_attack_mapping
from aegis.incidents.evidence import Evidence
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore


class _R:
    def __init__(self, data):
        self.data = data


def _store_with_evidence():
    store = InMemoryStore()
    inc = ingest_alert(store, source="t", fields={}, incident_type="powershell")
    store.add_evidence(Evidence(incident_id=inc.id, source="t",
                                collection_method="c"))
    real_id = store.evidence(inc.id)[0].id
    return store, inc.id, real_id


def test_valid_mapping_kept():
    store, inc_id, ev_id = _store_with_evidence()
    results = {"A4": _R({"attack_techniques": [
        {"id": "T1059.001", "confidence": 0.9,
         "evidence_ids": [ev_id]},
    ]})}
    report = validate_attack_mapping(store, inc_id, results)
    assert report == {}
    kept = results["A4"].data["attack_techniques"]
    assert kept[0]["id"] == "T1059.001"
    assert kept[0]["evidence_ids"] == [ev_id]


def test_unknown_technique_stripped():
    store, inc_id, ev_id = _store_with_evidence()
    results = {"A4": _R({"attack_techniques": [
        {"id": "T9999.999", "confidence": 0.9, "evidence_ids": [ev_id]},
        {"id": "T1059.001", "confidence": 0.8, "evidence_ids": [ev_id]},
    ]})}
    report = validate_attack_mapping(store, inc_id, results)
    ids = [t["id"] for t in results["A4"].data["attack_techniques"]]
    assert ids == ["T1059.001"]
    assert report["A4"]["stripped_count"] == 1
    assert (results["A4"].data["stripped_attack_techniques"][0]["reason"]
            == "unknown technique")


def test_no_evidence_cited_stripped_strict_mode():
    store, inc_id, _ = _store_with_evidence()
    results = {"A4": _R({"attack_techniques": [
        {"id": "T1059.001", "confidence": 0.9, "evidence_ids": ["ev-fake"]},
        {"id": "T1071.001", "confidence": 0.7, "evidence_ids": []},
    ]})}
    report = validate_attack_mapping(store, inc_id, results)
    assert results["A4"].data["attack_techniques"] == []
    assert report["A4"]["stripped_count"] == 2
    reasons = {s["reason"] for s in
               results["A4"].data["stripped_attack_techniques"]}
    assert any("no valid evidence" in r for r in reasons)


def test_malformed_entries_stripped():
    store, inc_id, _ = _store_with_evidence()
    results = {"A4": _R({"attack_techniques": ["T1059.001", 42]})}
    report = validate_attack_mapping(store, inc_id, results)
    assert report["A4"]["stripped_count"] == 2


# -- graph MAPPED_TO edges --

def test_mapped_to_edge_created_in_slice():
    """Direct: run investigate on a store we control."""
    import aegis.slice as sl
    from aegis.incidents.evidence import Evidence as Ev
    from aegis.incidents.ingestion import ingest_alert
    from aegis.incidents.store import InMemoryStore

    store = InMemoryStore()
    inc = ingest_alert(store, source="t",
                       fields={"host": "win-vm", "severity": "high",
                               "process": "powershell.exe", "pid": "1000"},
                       incident_type="powershell")
    # pre-seed the evidence id FakeLLM will cite so it survives validation
    store.add_evidence(Ev(id="ev-1", incident_id=inc.id, source="t",
                          collection_method="seed"))
    res = sl.investigate(store, inc.id, sl.FakeLLM())
    recs = store.records(inc.id, "attack_mapping")
    assert len(recs) == 1
    techs = recs[0]["techniques"]
    assert techs[0]["id"] == "T1059.001"
    assert (recs[0]["data_version"].startswith("stix-")
            or recs[0]["data_version"].startswith("embedded-"))
    edges = [r for r in store.records(inc.id, "edge")
             if r.get("relationship") == "MAPPED_TO"]
    assert any(e["src_id"] == "ev:ev-1" for e in edges)
    assert res is not None


# -- eval metric math --

def test_mapping_accuracy_math():
    from scripts.run_eval import _mapping_metrics

    rows = [
        {"expected_techniques": {"T1059.001", "T1071.001"},
         "mapped_techniques": {"T1059.001", "T1027"}},   # TP=1 FP=1 FN=1
        {"expected_techniques": {"T1003.001"},
         "mapped_techniques": {"T1003.001"}},             # TP=1
        {"expected_techniques": set(), "mapped_techniques": set()},
    ]
    m = _mapping_metrics(rows)
    assert m["mapping_precision"] == round(2 / 3, 3)
    assert m["mapping_recall"] == round(2 / 3, 3)