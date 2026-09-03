"""Phase 7 tests: ATT&CK subset, TI store, multi-alert correlation."""

from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore
from aegis.intel import attack, ti

# -- ATT&CK --

def test_lookup_known_technique():
    t = attack.lookup("T1059.001")
    assert t["name"] == "PowerShell"
    assert "execution" in t["tactics"]


def test_lookup_unknown_returns_none():
    assert attack.lookup("T9999.999") is None


def test_match_keywords_powershell_chain():
    hits = attack.match_keywords("WINWORD spawns powershell -enc base64 blob -> https beacon")
    ids = {h["id"] for h in hits}
    assert "T1059.001" in ids
    assert "T1566.001" in ids
    assert "T1027" in ids
    assert "T1071.001" in ids


def test_match_keywords_ranked():
    # text matching many keywords of one technique ranks it first
    hits = attack.match_keywords("powershell -enc encodedcommand iex invoke-expression")
    assert hits[0]["id"] == "T1059.001"


def test_matrix_loaded_from_data_file():
    from aegis.intel import attack

    assert len(attack.TECHNIQUES) > 100  # full STIX matrix ingested
    assert attack.ATTACK_DATA_VERSION.startswith("stix-")


def test_match_keywords_limit():
    hits = attack.match_keywords("powershell -enc base64 https beacon "
                                 "downloadstring certutil lsass exfil")
    assert len(hits) <= 12


def test_match_keywords_empty():
    assert attack.match_keywords("nothing suspicious here") == []


# -- TI --

def test_lookup_ip_malicious_rich_shape():
    r = ti.lookup("185.220.101.4")
    assert r["known_malicious"] is True
    assert r["ioc_type"] == "ip"
    assert r["confidence"] >= 0.9
    assert r["category"] == "c2"
    assert r["source"] == "local-intel-v2"


def test_lookup_ip_clean():
    r = ti.lookup("8.8.8.8")
    assert r["known_malicious"] is False
    assert r["confidence"] == 0.0


def test_lookup_domain_and_hash():
    d = ti.lookup("Secure-Login-Verify.NET")
    assert d["ioc_type"] == "domain"
    assert d["known_malicious"] is True
    h = ti.lookup("a3f8d2e91c4b7f60d21e8a54c9b03f77d6e5a2c81b94f0d37e6c25a48f19b302")
    assert h["ioc_type"] == "hash"
    assert h["category"] == "payload.dll"


def test_lookup_all():
    results = ti.lookup_all(["185.220.101.4", "8.8.8.8"])
    assert len(results) == 2
    assert [r["known_malicious"] for r in results] == [True, False]


def test_all_incident_ids_interface():
    store = InMemoryStore()
    a = ingest_alert(store, source="s", fields={}, incident_type="powershell")
    b = ingest_alert(store, source="s", fields={}, incident_type="powershell")
    assert set(store.all_incident_ids()) == {a.id, b.id}