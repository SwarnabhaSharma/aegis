"""Audit pipeline (debt #4, spec §18). Every important operation -> AuditEvent.

Recorder is sink-agnostic: memory list always populated (tests/CLI), optional
ES sink writes docs to {prefix}-audit. Tamper protection (hash chain) is a
later layer on top of these records.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from elasticsearch import Elasticsearch


@dataclass
class AuditEvent:
    category: str  # pipeline_stage | policy_decision | evidence_validation | tool_call | record
    incident_id: str = ""
    actor: str = ""
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))
    detail: dict[str, Any] = field(default_factory=dict)


class AuditRecorder:
    def __init__(self, es: Elasticsearch | None = None,
                 index: str = "aegis-dev-audit") -> None:
        self.events: list[AuditEvent] = []
        self._es = es
        self._index = index

    def record(self, category: str, incident_id: str = "", actor: str = "",
               **detail) -> AuditEvent:
        ev = AuditEvent(category=category, incident_id=incident_id,
                        actor=actor, detail=detail)
        self.events.append(ev)
        if self._es is not None:
            try:
                self._es.index(index=self._index, document={
                    "category": ev.category,
                    "incident_id": ev.incident_id,
                    "actor": ev.actor,
                    "ts": ev.ts.isoformat(),
                    "detail": ev.detail,
                }, refresh=True)
            except Exception:
                pass  # ponytail: audit write failure must not break the run;
                      # in-memory copy survives; alerting layer lands later
        return ev

    def ensure_index(self) -> None:
        if self._es is None:
            return
        if not self._es.indices.exists(index=self._index):
            self._es.indices.create(index=self._index, mappings={"properties": {
                "category": {"type": "keyword"},
                "incident_id": {"type": "keyword"},
                "actor": {"type": "keyword"},
                "ts": {"type": "date"},
            }})


def version_manifest(model: str, prompt_version: str,
                     policy_versions: list[str],
                     tool_schema_version: str) -> dict:
    """§21 per-incident manifest: behavior traceable to configuration."""
    return {
        "model": model or "unknown",
        "prompt_version": prompt_version,
        "policy_versions": sorted(set(policy_versions)),
        "tool_schema_version": tool_schema_version,
    }