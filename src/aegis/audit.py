"""Audit pipeline (debt #4 + WP-D, spec §18). Every important operation ->
AuditEvent with hash-chain tamper evidence.

Recorder is sink-agnostic: memory list always populated (tests/CLI), optional
ES sink writes docs to {prefix}-audit. Chain: each event carries seq +
prev_hash + sha256 over (prev, payload); verify_chain() detects modification.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from elasticsearch import Elasticsearch


def _event_hash(prev_hash: str, payload: dict) -> str:
    material = json.dumps(
        {"prev": prev_hash, "payload": payload}, sort_keys=True, default=str)
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass
class AuditEvent:
    category: str  # pipeline_stage | policy_decision | evidence_validation | tool_call | ...
    incident_id: str = ""
    actor: str = ""
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))
    detail: dict[str, Any] = field(default_factory=dict)
    seq: int = 0
    prev_hash: str = ""
    hash: str = ""


class AuditRecorder:
    def __init__(self, es: Elasticsearch | None = None,
                 index: str = "aegis-dev-audit") -> None:
        self.events: list[AuditEvent] = []
        self._es = es
        self._index = index

    def _payload(self, ev: AuditEvent) -> dict:
        return {"category": ev.category, "incident_id": ev.incident_id,
                "actor": ev.actor, "ts": ev.ts.isoformat(), "detail": ev.detail}

    def record(self, category: str, incident_id: str = "", actor: str = "",
               **detail) -> AuditEvent:
        prev_hash = self.events[-1].hash if self.events else ""
        ev = AuditEvent(category=category, incident_id=incident_id,
                        actor=actor, detail=detail,
                        seq=len(self.events), prev_hash=prev_hash)
        ev.hash = _event_hash(prev_hash, self._payload(ev))
        self.events.append(ev)
        if self._es is not None:
            try:
                self._es.index(index=self._index, document={
                    **self._payload(ev),
                    "seq": ev.seq, "prev_hash": ev.prev_hash, "hash": ev.hash,
                }, refresh=True)
            except Exception:
                pass  # ponytail: audit write failure must not break the run;
                      # in-memory copy survives; alerting layer lands later
        return ev

    def verify_chain(self) -> bool:
        """Tamper-evidence: recompute the chain; any mismatch -> False."""
        prev = ""
        for ev in self.events:
            expected = _event_hash(prev, self._payload(ev))
            if ev.prev_hash != prev or ev.hash != expected:
                return False
            prev = ev.hash
        return True

    def ensure_index(self) -> None:
        if self._es is None:
            return
        if not self._es.indices.exists(index=self._index):
            self._es.indices.create(index=self._index, mappings={"properties": {
                "category": {"type": "keyword"},
                "incident_id": {"type": "keyword"},
                "actor": {"type": "keyword"},
                "ts": {"type": "date"},
                "seq": {"type": "integer"},
                "prev_hash": {"type": "keyword"},
                "hash": {"type": "keyword"},
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