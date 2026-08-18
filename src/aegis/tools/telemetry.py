"""Telemetry source abstraction (Phase 2).

Read tools query telemetry through this interface. InMemoryTelemetry = tests/dev
(no VM needed); ElasticsearchTelemetry = live winlogbeat-* on VM (runtime).
"""

import abc
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class TelemetryEvent:
    event_id: str
    channel: str
    action: str
    host: str
    user: str = ""
    process_name: str = ""
    process_pid: str = ""
    process_parent: str = ""
    process_parent_pid: str = ""
    destination_ip: str = ""
    destination_port: str = ""
    file_path: str = ""
    command_line: str = ""
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))
    raw: dict = field(default_factory=dict)


class TelemetrySource(abc.ABC):
    @abc.abstractmethod
    def search_events(self, *, host: str | None = None, event_id: str | None = None,
                      process_name: str | None = None, user: str | None = None,
                      limit: int = 50) -> list[TelemetryEvent]: ...

    @abc.abstractmethod
    def get_process_tree(
        self, host: str, pid: str | None = None, limit: int = 100
    ) -> list[TelemetryEvent]: ...

    @abc.abstractmethod
    def get_network_connections(self, host: str, limit: int = 100) -> list[TelemetryEvent]: ...


class InMemoryTelemetry(TelemetrySource):
    """Fake telemetry for tests. Mirrors winlogbeat schema semantics."""

    def __init__(self, events: list[TelemetryEvent] | None = None) -> None:
        self._events = events or []

    def search_events(self, *, host=None, event_id=None, process_name=None,
                      user=None, limit=50) -> list[TelemetryEvent]:
        out = []
        for e in self._events:
            if host and e.host != host:
                continue
            if event_id and e.event_id != event_id:
                continue
            if process_name and e.process_name != process_name:
                continue
            if user and e.user != user:
                continue
            out.append(e)
        return out[:limit]

    def get_process_tree(
        self, host: str, pid: str | None = None, limit: int = 100
    ) -> list[TelemetryEvent]:
        matches = [e for e in self._events if e.host == host and e.event_id == "1"]
        if pid:
            matches = [e for e in matches if e.process_pid == pid]
        return matches[:limit]

    def get_network_connections(self, host: str, limit: int = 100) -> list[TelemetryEvent]:
        return [e for e in self._events
                if e.host == host and e.event_id == "3"][:limit]
