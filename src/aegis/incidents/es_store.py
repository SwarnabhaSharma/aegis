"""Elasticsearch incident store (ADR-017). Same interface as InMemoryStore.

Indices: {prefix}-incidents (one doc per incident, _id=incident.id),
{prefix}-steps (transition/evidence/timeline docs discriminated by 'kind').
Writes use refresh=True — dev scale, keeps reads consistent without ceremony.
update_state uses optimistic concurrency (if_seq_no/if_primary_term);
conflict -> ValueError.
"""

from datetime import UTC, datetime

from elasticsearch import ConflictError, Elasticsearch, NotFoundError

from aegis.incidents.evidence import Evidence, TimelineEntry
from aegis.incidents.schema import Incident, Transition
from aegis.incidents.store import IncidentStore

_INCIDENT_MAPPINGS = {
    "properties": {
        "id": {"type": "keyword"},
        "source_alert_id": {"type": "keyword"},
        "type": {"type": "keyword"},
        "state": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "confidence": {"type": "float"},
        "version": {"type": "integer"},
        "created_at": {"type": "date"},
        "updated_at": {"type": "date"},
    }
}

_STEPS_MAPPINGS = {
    "properties": {
        "kind": {"type": "keyword"},
        "incident_id": {"type": "keyword"},
        "ts": {"type": "date"},
    }
}


class ElasticsearchStore(IncidentStore):
    def __init__(self, es: Elasticsearch, prefix: str = "aegis-dev") -> None:
        self._es = es
        self._incidents_idx = f"{prefix}-incidents"
        self._steps_idx = f"{prefix}-steps"
        for idx, mappings in (
            (self._incidents_idx, _INCIDENT_MAPPINGS),
            (self._steps_idx, _STEPS_MAPPINGS),
        ):
            if not es.indices.exists(index=idx):
                es.indices.create(index=idx, mappings=mappings)

    # -- incidents --

    def create(self, incident: Incident) -> Incident:
        self._es.index(
            index=self._incidents_idx, id=incident.id,
            document=incident.model_dump(mode="json"), refresh=True,
        )
        return incident

    def get(self, incident_id: str) -> Incident | None:
        try:
            hit = self._es.get(index=self._incidents_idx, id=incident_id)
        except NotFoundError:
            return None
        return Incident.model_validate(hit["_source"])

    def _write(self, inc: Incident, if_seq_no: int | None = None,
               if_primary_term: int | None = None) -> None:
        try:
            kwargs: dict = {"refresh": True}
            if if_seq_no is not None:
                kwargs["if_seq_no"] = if_seq_no
                kwargs["if_primary_term"] = if_primary_term
            self._es.index(
                index=self._incidents_idx, id=inc.id,
                document=inc.model_dump(mode="json"), **kwargs,
            )
        except ConflictError as e:
            raise ValueError(f"concurrent update conflict on {inc.id}") from e

    def update_state(self, incident_id: str, new_state, actor: str, reason: str) -> Incident:
        try:
            hit = self._es.get(index=self._incidents_idx, id=incident_id)
        except NotFoundError:
            raise KeyError(incident_id) from None
        inc = Incident.model_validate(hit["_source"])
        inc.state = new_state
        inc.version += 1
        inc.updated_at = datetime.now(UTC)
        self._write(inc, hit["_seq_no"], hit["_primary_term"])
        return inc

    # -- steps (child records) --

    @staticmethod
    def _step_ts(obj) -> str:
        ts = getattr(obj, "ts", None) or getattr(obj, "observed_at", None)
        return ts.isoformat() if ts else datetime.now(UTC).isoformat()

    def _add_step(self, kind: str, obj) -> None:
        self._es.index(
            index=self._steps_idx,
            document={
                "kind": kind,
                "incident_id": obj.incident_id,
                "ts": self._step_ts(obj),
                "doc": obj.model_dump(mode="json"),
            },
            refresh=True,
        )

    def _steps(self, incident_id: str, kind: str, model):
        resp = self._es.search(
            index=self._steps_idx,
            body={
                "query": {"bool": {"must": [
                    {"term": {"incident_id": incident_id}},
                    {"term": {"kind": kind}},
                ]}},
                "sort": [{"ts": {"order": "asc"}}],
                "size": 1000,
            },
        )
        return [model.model_validate(h["_source"]["doc"]) for h in resp["hits"]["hits"]]

    # -- interface: transitions / evidence / timeline --

    def add_transition(self, transition: Transition) -> None:
        self._add_step("transition", transition)
        self.add_timeline(TimelineEntry(
            incident_id=transition.incident_id,
            actor=transition.actor,
            action="transition",
            detail=f"{transition.from_state.value} -> {transition.to_state.value}",
        ))

    def transitions(self, incident_id: str) -> list[Transition]:
        return self._steps(incident_id, "transition", Transition)

    def add_evidence(self, evidence: Evidence) -> None:
        self._add_step("evidence", evidence)
        self.add_timeline(TimelineEntry(
            incident_id=evidence.incident_id,
            actor="tool",
            action="evidence",
            detail=f"{evidence.collection_method}: {evidence.id}",
        ))

    def evidence(self, incident_id: str) -> list[Evidence]:
        return self._steps(incident_id, "evidence", Evidence)

    def add_timeline(self, entry: TimelineEntry) -> None:
        self._add_step("timeline", entry)

    def timeline(self, incident_id: str) -> list[TimelineEntry]:
        return self._steps(incident_id, "timeline", TimelineEntry)