"""Incident store interface + in-memory fake (Phase 1).

Interface so real ES impl can swap in later (ADR-017) without touching callers.
In-memory fake = dev/tests run with no ES on this machine (user constraint).
"""

import abc
import threading
from datetime import UTC, datetime

from aegis.incidents.evidence import Evidence, TimelineEntry
from aegis.incidents.schema import Incident, Transition


class IncidentStore(abc.ABC):
    @abc.abstractmethod
    def create(self, incident: Incident) -> Incident: ...

    @abc.abstractmethod
    def get(self, incident_id: str) -> Incident | None: ...

    @abc.abstractmethod
    def update_state(self, incident_id: str, new_state, actor: str, reason: str) -> Incident: ...

    @abc.abstractmethod
    def add_transition(self, transition: Transition) -> None: ...

    @abc.abstractmethod
    def transitions(self, incident_id: str) -> list[Transition]: ...

    @abc.abstractmethod
    def add_evidence(self, evidence: Evidence) -> None: ...

    @abc.abstractmethod
    def evidence(self, incident_id: str) -> list[Evidence]: ...

    @abc.abstractmethod
    def add_timeline(self, entry: TimelineEntry) -> None: ...

    @abc.abstractmethod
    def timeline(self, incident_id: str) -> list[TimelineEntry]: ...

    @abc.abstractmethod
    def all_incident_ids(self) -> list[str]: ...

    @abc.abstractmethod
    def add_record(self, kind: str, incident_id: str, doc: dict) -> None:
        """Persist an arbitrary typed step record (toolcall/agentrun/policy/
        decision/verification/manifest) under the incident."""

    @abc.abstractmethod
    def records(self, incident_id: str, kind: str) -> list[dict]: ...


class InMemoryStore(IncidentStore):
    """Thread-safe fake. Single-writer per incident via per-id lock."""

    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._transitions: dict[str, list[Transition]] = {}
        self._evidence: dict[str, list[Evidence]] = {}
        self._timeline: dict[str, list[TimelineEntry]] = {}
        self._records: dict[tuple[str, str], list[dict]] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()

    def create(self, incident: Incident) -> Incident:
        with self._global_lock:
            self._incidents[incident.id] = incident
            self._transitions.setdefault(incident.id, [])
            self._evidence.setdefault(incident.id, [])
            self._timeline.setdefault(incident.id, [])
            self._locks[incident.id] = threading.Lock()
        return incident

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def update_state(self, incident_id: str, new_state, actor: str, reason: str) -> Incident:
        lock = self._locks.get(incident_id)
        if lock is None:
            raise KeyError(incident_id)
        with lock:
            inc = self._incidents[incident_id]
            inc.state = new_state
            inc.version += 1
            inc.updated_at = datetime.now(UTC)
        return inc

    def add_transition(self, transition: Transition) -> None:
        self._transitions.setdefault(transition.incident_id, []).append(transition)
        self.add_timeline(
            TimelineEntry(
                incident_id=transition.incident_id,
                actor=transition.actor,
                action="transition",
                detail=f"{transition.from_state.value} -> {transition.to_state.value}",
            )
        )

    def transitions(self, incident_id: str) -> list[Transition]:
        return list(self._transitions.get(incident_id, []))

    def add_evidence(self, evidence: Evidence) -> None:
        self._evidence.setdefault(evidence.incident_id, []).append(evidence)
        self.add_timeline(
            TimelineEntry(
                incident_id=evidence.incident_id,
                actor="tool",
                action="evidence",
                detail=f"{evidence.collection_method}: {evidence.id}",
            )
        )

    def evidence(self, incident_id: str) -> list[Evidence]:
        return list(self._evidence.get(incident_id, []))

    def add_timeline(self, entry: TimelineEntry) -> None:
        self._timeline.setdefault(entry.incident_id, []).append(entry)

    def timeline(self, incident_id: str) -> list[TimelineEntry]:
        return list(self._timeline.get(incident_id, []))

    def all_incident_ids(self) -> list[str]:
        return list(self._incidents.keys())

    def add_record(self, kind: str, incident_id: str, doc: dict) -> None:
        self._records.setdefault((incident_id, kind), []).append(doc)

    def records(self, incident_id: str, kind: str) -> list[dict]:
        return list(self._records.get((incident_id, kind), []))
