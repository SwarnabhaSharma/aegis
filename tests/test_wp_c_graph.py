"""WP-C tests: evidence graph model (edges, traverse, cross-incident, expiry)."""

import sys

sys.path.insert(0, "scripts")

from datetime import UTC, datetime, timedelta

from aegis.agents.validation import validate_evidence
from aegis.incidents.evidence import Evidence
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore
from aegis.intel.graph import (
    build_incident_edges,
    cross_incident_ioc_edges,
    load_graph,
    persist_edges,
    serialize_edges,
    traverse,
)


def _ev(inc_id, event_id, **data):
    return Evidence(incident_id=inc_id, source="t", collection_method="test",
                    data={"event_id": event_id, "host": "win-vm", **data})


def _canned(store, inc_id):
    """Word -> powershell -> C2 + payload chain as evidence records."""
    evs = [
        _ev(inc_id, "1", process="WINWORD.EXE", pid="500"),
        _ev(inc_id, "1", process="powershell.exe", pid="1000",
            process_parent="WINWORD.EXE",
            command_line="powershell -enc AAAA"),
        _ev(inc_id, "3", process="powershell.exe", pid="1000",
            destination_ip="185.220.101.4"),
        _ev(inc_id, "11", process="powershell.exe", pid="1000",
            file_path="C:\\ProgramData\\payload.dll"),
    ]
    for e in evs:
        store.add_evidence(e)
    return evs


def test_build_edges_types():
    store = InMemoryStore()
    inc = ingest_alert(store, source="t", fields={}, incident_type="powershell")
    evs = _canned(store, inc.id)
    edges = build_incident_edges(evs, inc.id)
    rels = {(e["src_type"], e["relationship"], e["dst_type"]) for e in edges}
    assert ("evidence", "BELONGS_TO_HOST", "asset") in rels
    assert ("evidence", "CONNECTED_TO", "indicator") in rels
    # powershell network/file events anchored to the pid-1000 process-create
    proc = next(e for e in evs if e.data.get("pid") == "1000"
                and e.data["event_id"] == "1")
    pid = f"ev:{proc.id}"
    assert any(e["src_id"] == pid and e["relationship"] == "CONNECTED_TO"
               for e in edges)
    assert any(e["src_id"] == pid and e["relationship"] == "WROTE_FILE"
               for e in edges)


def test_persist_and_load_graph():
    store = InMemoryStore()
    inc = ingest_alert(store, source="t", fields={}, incident_type="powershell")
    evs = _canned(store, inc.id)
    edges = build_incident_edges(evs, inc.id)
    n = persist_edges(store, inc.id, edges)
    assert n == len(edges)
    nodes, loaded = load_graph(store, inc.id)
    assert len(loaded) == len(edges)
    types = {nd["type"] for nd in nodes}
    assert {"evidence", "asset", "indicator"} <= types


def test_traverse_from_process_reaches_indicator():
    store = InMemoryStore()
    inc = ingest_alert(store, source="t", fields={}, incident_type="powershell")
    evs = _canned(store, inc.id)
    edges = build_incident_edges(evs, inc.id)
    proc = next(e for e in evs if e.data.get("pid") == "1000"
                and e.data["event_id"] == "1")
    reach = traverse(edges, f"ev:{proc.id}", max_hops=3)
    dst_types = {e["dst_type"] for e in reach}
    assert "indicator" in dst_types


def test_cross_incident_shared_ioc_edges():
    store = InMemoryStore()
    a = ingest_alert(store, source="t", fields={"host": "win-vm"},
                     incident_type="powershell")
    b = ingest_alert(store, source="t", fields={"host": "win-vm"},
                     incident_type="powershell")
    c = ingest_alert(store, source="t", fields={"host": "other"},
                     incident_type="powershell")
    for inc in (a, b):
        store.add_evidence(_ev(inc.id, "3", destination_ip="185.220.101.4"))
    store.add_evidence(_ev(c.id, "3", destination_ip="10.0.0.9",
                           host="other-box"))

    edges = cross_incident_ioc_edges(store, a.id)
    targets = {e["dst_id"] for e in edges}
    assert f"incident:{b.id}" in targets
    assert f"incident:{c.id}" not in targets
    assert all(e["relationship"] == "SHARED_INDICATOR" for e in edges)


def test_serialize_edges_text():
    txt = serialize_edges([
        {"src_id": "ev:1", "relationship": "CONNECTED_TO",
         "dst_id": "ioc:1.2.3.4", "confidence": 0.85},
    ])
    assert "-[CONNECTED_TO]->" in txt and "ioc:1.2.3.4" in txt
    assert serialize_edges([]) == "(empty graph)"


# -- §14: expiration enforced by validator --

def test_validator_treats_expired_evidence_as_absent():
    store = InMemoryStore()
    inc = ingest_alert(store, source="t", fields={}, incident_type="powershell")
    expired = Evidence(
        incident_id=inc.id, source="t", collection_method="c",
        observed_at=datetime.now(UTC) - timedelta(hours=2),
        valid_until=datetime.now(UTC) - timedelta(hours=1),
    )
    store.add_evidence(expired)

    class R:
        data = {"summary": "x", "evidence_ids": [expired.id]}

    results = {"A2": R()}
    report = validate_evidence(store, inc.id, results)
    # expired ref stripped exactly like a fabricated one
    assert results["A2"].data["evidence_ids"] == []
    assert report["A2"]["fabricated"] == [expired.id]


# -- ADR-021 justification exists --

def test_graph_justification_documented():
    import re

    from pathlib import Path

    adr = Path(__file__).resolve().parent.parent / "docs" / "adr.md"
    src = adr.read_text(encoding="utf-8")
    assert re.search(r"ADR-021", src), "ADR-021 (evidence graph) missing"
