"""Live-ES ElasticsearchStore integration. Opt-in: AEGIS_INTEGRATION=1.

Run when VM up + .env has creds:
    $env:AEGIS_INTEGRATION="1"; python -m pytest tests/integration/test_es_store.py -v
"""

import os
import uuid

import pytest

es_lib = pytest.importorskip("elasticsearch")
from aegis.incidents.es_store import ElasticsearchStore  # noqa: E402
from aegis.incidents.evidence import Evidence, TimelineEntry  # noqa: E402
from aegis.incidents.schema import IncidentState  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("AEGIS_INTEGRATION") != "1",
    reason="live-ES integration; set AEGIS_INTEGRATION=1",
)


@pytest.fixture()
def store():
    client = es_lib.Elasticsearch(
        "http://192.168.56.105:9200", basic_auth=("elastic", "Mhz03ph9kPS5p2nkq1fZ"),
        verify_certs=False, request_timeout=30,
    )
    prefix = f"aegis-test-{uuid.uuid4().hex[:8]}"
    yield ElasticsearchStore(client, prefix=prefix)
    try:
        client.indices.delete(index=f"{prefix}-incidents,{prefix}-steps")
    except es_lib.NotFoundError:
        pass
    client.close()


def test_create_get_roundtrip(store):
    from aegis.incidents.schema import Incident

    inc = Incident(source_alert_id="al-1", type="powershell", severity="high")
    store.create(inc)
    got = store.get(inc.id)
    assert got is not None
    assert got.id == inc.id
    assert got.state == IncidentState.NEW


def test_get_missing_returns_none(store):
    assert store.get("inc-does-not-exist") is None


def test_update_state_bumps_version(store):
    from aegis.incidents.schema import Incident

    inc = Incident(source_alert_id="al-1", type="powershell")
    store.create(inc)
    updated = store.update_state(inc.id, IncidentState.TRIAGING, "orchestrator", "test")
    assert updated.version == 2
    assert updated.state == IncidentState.TRIAGING
    assert store.get(inc.id).version == 2


def test_stale_update_conflicts(store):
    from aegis.incidents.schema import Incident

    inc = Incident(source_alert_id="al-1", type="powershell")
    store.create(inc)
    store.update_state(inc.id, IncidentState.TRIAGING, "orchestrator", "first")
    # stale writer: captured doc state is now behind; write via store's own
    # write path with wrong seq_no -> wrapped ValueError
    stale = store.get(inc.id)
    store.update_state(inc.id, IncidentState.INVESTIGATING, "orchestrator", "second")
    with pytest.raises(ValueError, match="conflict"):
        store._write(stale, if_seq_no=0, if_primary_term=1)


def test_transitions_evidence_timeline_ordering(store):
    from aegis.incidents.schema import Incident, Transition

    inc = Incident(source_alert_id="al-1", type="powershell")
    store.create(inc)
    for to_s in (IncidentState.TRIAGING, IncidentState.INVESTIGATING):
        store.add_transition(Transition(
            incident_id=inc.id, from_state=IncidentState.NEW,
            to_state=to_s, actor="orchestrator", reason="t",
        ))
        store.add_evidence(Evidence(incident_id=inc.id, source="tool:x",
                                    collection_method="search_events"))
    store.add_timeline(TimelineEntry(incident_id=inc.id, actor="op",
                                     action="note", detail="manual"))
    trs = store.transitions(inc.id)
    evs = store.evidence(inc.id)
    tl = store.timeline(inc.id)
    assert len(trs) == 2 and trs[0].to_state == IncidentState.TRIAGING
    assert len(evs) == 2
    # timeline: 2 transition mirrors + 2 evidence mirrors + 1 manual = 5
    assert len(tl) == 5