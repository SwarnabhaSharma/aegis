"""Incident domain models (Phase 1). Data model per docs/phase-d.md L.1."""

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class IncidentState(enum.StrEnum):
    NEW = "NEW"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    CORRELATING = "CORRELATING"
    ASSESSING = "ASSESSING"
    RESPONSE_PLANNED = "RESPONSE_PLANNED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    ESCALATED = "ESCALATED"
    FAILED = "FAILED"


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: f"alert-{uuid.uuid4()}")
    source: str
    fields: dict[str, Any]
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: str = "unknown"


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: f"inc-{uuid.uuid4()}")
    source_alert_id: str
    type: str
    state: IncidentState = IncidentState.NEW
    severity: str = "unknown"
    confidence: float = 0.0
    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    fields: dict[str, Any] = Field(default_factory=dict)
    # child records land in incident-steps-* (timeline/evidence/etc.), not inline here.
    timeline: list[dict[str, Any]] = Field(default_factory=list)


class Transition(BaseModel):
    incident_id: str
    from_state: IncidentState
    to_state: IncidentState
    actor: str
    reason: str = ""
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
