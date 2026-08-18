"""Alert ingestion (Phase 1): alert -> Incident (NEW)."""

import uuid
from datetime import UTC, datetime

from aegis.incidents.schema import Alert, Incident
from aegis.incidents.store import IncidentStore


def ingest_alert(store: IncidentStore, source: str, fields: dict, incident_type: str) -> Incident:
    alert = Alert(source=source, fields=fields)
    incident = Incident(
        id=f"inc-{uuid.uuid4()}",
        source_alert_id=alert.id,
        type=incident_type,
        severity=fields.get("severity", "unknown"),
        created_at=datetime.now(UTC),
    )
    store.create(incident)
    return incident
