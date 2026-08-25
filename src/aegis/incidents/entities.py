"""Asset + Identity entities (debt #9, spec §19 L.1).

Stored as typed records via IncidentStore.add_record (kind "asset"/"identity")
— no new index family. Policy engine reads asset criticality from these
records; the legacy hardcoded map remains bootstrap fallback only.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Asset:
    hostname: str
    criticality: str = "low"  # low | medium | high | critical
    ip: str = ""
    notes: str = ""
    registered_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class Identity:
    username: str
    domain: str = ""
    risk: str = "normal"  # normal | watch | compromised
    disabled: bool = False
    registered_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# -- store helpers (record-kind based; both store impls support this) --

def register_asset(store, incident_id: str, asset: Asset) -> None:
    store.add_record("asset", incident_id, {
        "hostname": asset.hostname.lower(),
        "criticality": asset.criticality,
        "ip": asset.ip,
        "notes": asset.notes,
    })


def register_identity(store, incident_id: str, identity: Identity) -> None:
    store.add_record("identity", incident_id, {
        "username": identity.username.lower(),
        "domain": identity.domain,
        "risk": identity.risk,
        "disabled": identity.disabled,
    })


def get_asset_criticality(store, incident_id: str, host: str) -> str | None:
    """Criticality from Asset records for host; None if unknown."""
    target = host.lower()
    for rec in store.records(incident_id, "asset"):
        if rec.get("hostname") == target:
            return rec.get("criticality", "unknown")
    return None


def is_account_disabled(store, incident_id: str, username: str) -> bool:
    target = username.lower()
    for rec in store.records(incident_id, "identity"):
        if rec.get("username") == target:
            return bool(rec.get("disabled"))
    return False


def set_account_disabled(store, incident_id: str, username: str,
                         domain: str = "") -> None:
    store.add_record("identity", incident_id, {
        "username": username.lower(), "domain": domain,
        "risk": "compromised", "disabled": True,
    })