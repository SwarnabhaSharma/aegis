"""Evidence + timeline model (Phase 2).

Evidence = separate records keyed by incident_id (matches incident-steps-* model).
Timeline auto-appends on evidence collect and state transition.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: f"ev-{uuid.uuid4()}")
    incident_id: str
    source: str
    collection_method: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_ref: str = ""
    classification: str = "normal"
    provenance: str = "real"  # §3.4: "real" (telemetry) | "synthetic" (seeded/test)
    confidence: float = 0.5  # §14: per-evidence confidence (source-derived)
    valid_until: datetime | None = None  # §14: expiration; None = indefinite
    contradicts: list[str] = Field(default_factory=list)  # §14: ids this contradicts
    data: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    incident_id: str
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: str
    action: str
    detail: str = ""


def evidence_from_tool_result(incident_id: str, tool: str, events: list,
                              provenance: str = "real") -> list[Evidence]:
    from aegis.privacy import classification_level, detect

    def _raw_ref(e) -> str:
        if not getattr(e, "raw", None):
            return ""
        rid = e.raw.get("winlog", {}).get("record_id", "")
        return str(rid) if rid else ""

    def _privacy(e) -> tuple[str, dict]:
        """§27 privacy-filtering step: classify each evidence record."""
        kinds: set[str] = set()
        for val in (e.command_line, e.file_path, e.user):
            kinds.update(detect(val or ""))
        level = classification_level(sorted(kinds)) if kinds else "normal"
        return level, ({"kinds": sorted(kinds)} if kinds else {})

    out = []
    for e in events:
        level, meta = _privacy(e)
        ev = Evidence(
            incident_id=incident_id,
            source=f"tool:{tool}",
            collection_method=tool,
            raw_ref=_raw_ref(e),
            classification=level,
            provenance=provenance,
            data={
                "host": e.host,
                "event_id": e.event_id,
                "action": e.action,
                "user": e.user,
                "process": e.process_name,
                "pid": e.process_pid,
                "destination_ip": e.destination_ip,
                "file_path": e.file_path,
            },
        )
        if meta:
            ev.data["_privacy"] = meta
        out.append(ev)
    return out
