"""Simulated verifier (Phase 6, ADR-016). In-memory, generic retry counter."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis.executor.executor import SimulatedExecutor
from aegis.incidents.schema import IncidentState


@dataclass
class Verification:
    id: str = field(default_factory=lambda: f"ver-{uuid.uuid4()}")
    incident_id: str = ""
    action: str = ""
    target: str = ""
    expected: str = ""
    actual: str = ""
    passed: bool = False
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))


class SimulatedVerifier:
    """D2 verifier. Checks simulated backend state; generic retry -> REOPEN/ESCALATED."""

    def __init__(self, executor: SimulatedExecutor, max_retries: int = 2) -> None:
        self._executor = executor
        self._max_retries = max_retries
        self._retries: dict[str, int] = {}
        self._blocked: set[str] = set()
        self._terminated: set[tuple[str, str]] = set()
        self._clean: set[str] = set()
        self._log: list[Verification] = []

    # -- simulated backend mutators (Phase 5 actions would call these) --
    def _block(self, indicator: str) -> None:
        self._blocked.add(indicator)

    def _terminate(self, host: str, pid: str) -> None:
        self._terminated.add((host, pid))

    def _clean_host(self, host: str) -> None:
        self._clean.add(host)

    # -- verify methods (full set, H.2) --
    def verify_host_isolated(self, host: str, incident_id: str) -> Verification:
        actual = "isolated:true" if self._executor.is_isolated(host) else "isolated:false"
        v = Verification(
            incident_id=incident_id, action="verify_host_isolated", target=host,
            expected="isolated:true", actual=actual, passed=actual == "isolated:true",
        )
        self._log.append(v)
        return v

    def verify_process_terminated(self, host: str, pid: str, incident_id: str) -> Verification:
        actual = "terminated:true" if (host, pid) in self._terminated else "terminated:false"
        v = Verification(
            incident_id=incident_id, action="verify_process_terminated", target=f"{host}:{pid}",
            expected="terminated:true", actual=actual, passed=actual == "terminated:true",
        )
        self._log.append(v)
        return v

    def verify_indicator_blocked(self, indicator: str, incident_id: str) -> Verification:
        actual = "blocked:true" if indicator in self._blocked else "blocked:false"
        v = Verification(
            incident_id=indicator, action="verify_indicator_blocked", target=indicator,
            expected="blocked:true", actual=actual, passed=actual == "blocked:true",
        )
        # note: incident_id overloaded above for brevity; fix:
        v.incident_id = incident_id
        self._log.append(v)
        return v

    def verify_persistence_removed(self, host: str, incident_id: str) -> Verification:
        actual = "clean:true" if host in self._clean else "clean:false"
        v = Verification(
            incident_id=incident_id, action="verify_persistence_removed", target=host,
            expected="clean:true", actual=actual, passed=actual == "clean:true",
        )
        self._log.append(v)
        return v

    # -- retry policy: fail -> REOPEN until max_retries then ESCALATED --
    def next_state(self, verification: Verification) -> IncidentState:
        if verification.passed:
            return IncidentState.RESOLVED
        count = self._retries.get(verification.incident_id, 0) + 1
        self._retries[verification.incident_id] = count
        if count >= self._max_retries:
            return IncidentState.ESCALATED
        return IncidentState.REOPENED

    @property
    def log(self) -> list[Verification]:
        return list(self._log)
