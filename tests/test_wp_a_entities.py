"""WP-A tests: Asset/Identity entities, store-based criticality, disable_account."""

import sys

sys.path.insert(0, "scripts")

from aegis.executor.executor import SimulatedExecutor
from aegis.incidents.entities import (
    Asset,
    Identity,
    get_asset_criticality,
    is_account_disabled,
    register_asset,
    register_identity,
    set_account_disabled,
)
from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore
from aegis.policies.engine import Decision, evaluate
from aegis.tools.registry import build_response_tools, build_verify_tools
from aegis.verifier.verifier import SimulatedVerifier


def _store_with_asset(hostname="db-prod-01", criticality="critical"):
    store = InMemoryStore()
    inc = ingest_alert(store, source="t", fields={"host": hostname},
                       incident_type="powershell")
    register_asset(store, inc.id, Asset(hostname=hostname,
                                        criticality=criticality))
    return store, inc.id


# -- entities --

def test_register_and_read_asset():
    store, inc_id = _store_with_asset()
    assert get_asset_criticality(store, inc_id, "DB-PROD-01") == "critical"  # case-insensitive


def test_unknown_host_returns_none_then_fallback():
    store, inc_id = _store_with_asset()
    assert get_asset_criticality(store, inc_id, "no-such-host") is None


def test_identity_disable_state():
    store, inc_id = _store_with_asset("win-vm", "low")
    assert is_account_disabled(store, inc_id, "svc_backup") is False
    set_account_disabled(store, inc_id, "svc_backup", domain="CORP")
    assert is_account_disabled(store, inc_id, "SVC_BACKUP") is True


def test_identity_record_shape():
    store, inc_id = _store_with_asset()
    register_identity(store, inc_id, Identity(username="alice", domain="CORP"))
    rec = store.records(inc_id, "identity")[0]
    assert rec["username"] == "alice" and rec["domain"] == "CORP"
    assert rec["disabled"] is False


# -- policy engine uses Asset records (#9) --

def test_policy_uses_store_criticality_over_map():
    # "win-vm" is hardcoded "low" in the legacy map; store says critical -> DENY
    store, inc_id = _store_with_asset("win-vm", "critical")
    facts = {"host": "win-vm", "confidence": 0.95, "evidence_count": 4}
    r = evaluate("isolate_host", facts, store=store, incident_id=inc_id)
    assert r.decision is Decision.DENY
    assert "asset_criticality!= critical failed" in r.reason


def test_policy_falls_back_to_map_without_records():
    store = InMemoryStore()
    inc = ingest_alert(store, source="t", fields={}, incident_type="powershell")
    facts = {"host": "win-vm", "confidence": 0.95, "evidence_count": 4}
    r = evaluate("isolate_host", facts, store=store, incident_id=inc.id)
    assert r.decision is Decision.ALLOW  # map fallback: win-vm -> low
    assert r.facts["asset_criticality"] == "low"


# -- disable_account end-to-end through registry + verifier --

def test_disable_account_via_registry_verified_by_d2():
    ex = SimulatedExecutor()
    reg = build_response_tools(ex)
    vreg = build_verify_tools(SimulatedVerifier(ex))

    v_before = vreg.call("verify_account_disabled", "D2",
                         username="svc_backup", incident_id="inc-1")
    assert v_before.passed is False

    reg.call("disable_account", "D1", username="svc_backup", incident_id="inc-1")
    v_after = vreg.call("verify_account_disabled", "D2",
                        username="svc_backup", incident_id="inc-1")
    assert v_after.passed is True

    # reasoning agent still blocked from response tools
    import pytest

    with pytest.raises(PermissionError):
        reg.call("disable_account", "A5", username="x", incident_id="inc-1")


def test_disable_account_idempotent():
    ex = SimulatedExecutor()
    r1 = ex.disable_account("svc_backup")
    r2 = ex.disable_account("svc_backup")
    assert ex.account_disabled("svc_backup") is True
    assert r1.status == r2.status == "account_disabled"