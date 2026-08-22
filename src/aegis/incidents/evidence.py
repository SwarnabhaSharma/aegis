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
    data: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    incident_id: str
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: str
    action: str
    detail: str = ""


def evidence_from_tool_result(incident_id: str, tool: str, events: list) -> list[Evidence]:
    def _raw_ref(e) -> str:
        if not getattr(e, "raw", None):
            return ""
        rid = e.raw.get("winlog", {}).get("record_id", "")
        return str(rid) if rid else ""

    return [
        Evidence(
            incident_id=incident_id,
            source=f"tool:{tool}",
            collection_method=tool,
            raw_ref=_raw_ref(e),
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
        for e in events
    ]
