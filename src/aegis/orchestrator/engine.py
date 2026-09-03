"""Orchestrator (Phase 1): drives state transitions through the lifecycle.

Authority: orchestrator + operator may mutate state (Phase C K.2). Agents
cannot. Transition validity enforced by state_machine before store write.
"""

import threading

from aegis.incidents.schema import Incident, Transition
from aegis.incidents.store import IncidentStore
from aegis.orchestrator.state_machine import assert_transition


class Orchestrator:
    def __init__(self, store: IncidentStore) -> None:
        self._store = store
        self._locks: dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()

    def _get_lock(self, incident_id: str) -> threading.Lock:
        with self._locks_lock:
            if incident_id not in self._locks:
                self._locks[incident_id] = threading.Lock()
            return self._locks[incident_id]

    def transition(self, incident_id: str, to_state, actor: str, reason: str = "") -> Incident:
        lock = self._get_lock(incident_id)
        with lock:
            inc = self._store.get(incident_id)
            if inc is None:
                raise KeyError(incident_id)
            from_state = inc.state
            assert_transition(actor, from_state, to_state)
            inc = self._store.update_state(incident_id, to_state, actor, reason)
            self._store.add_transition(
                Transition(
                    incident_id=incident_id,
                    from_state=from_state,
                    to_state=to_state,
                    actor=actor,
                    reason=reason,
                )
            )
            return inc
