"""Simulated executor (Phase 5, ADR-013). In-memory, idempotent, no real backend."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class ResponseResult:
    host: str
    isolated: bool
    status: str  # "isolated" | "already_isolated" | "failed"
    message: str = ""


@dataclass
class ResponseAction:
    id: str = field(default_factory=lambda: f"act-{uuid.uuid4()}")
    incident_id: str = ""
    action: str = "isolate_host"
    target: str = ""
    status: str = "pending"
    result: ResponseResult | None = None
    idempotency_key: str = ""
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))


class SimulatedExecutor:
    """In-memory host isolation. Idempotent via idempotency_key."""

    def __init__(self) -> None:
        self._hosts: dict[str, bool] = {}  # host -> isolated
        self._by_key: dict[str, ResponseResult] = {}
        self._actions: list[ResponseAction] = []

    def isolate_host(
        self,
        host: str,
        incident_id: str,
        idempotency_key: str | None = None,
    ) -> ResponseResult:
        key = idempotency_key or f"{incident_id}:isolate_host:{host}"
        if key in self._by_key:
            return self._by_key[key]

        already = self._hosts.get(host, False)
        if already:
            result = ResponseResult(host=host, isolated=True,
                                    status="already_isolated", message="host already isolated")
        else:
            self._hosts[host] = True
            result = ResponseResult(host=host, isolated=True,
                                    status="isolated", message="host isolated (simulated)")

        self._by_key[key] = result
        self._actions.append(ResponseAction(
            incident_id=incident_id, action="isolate_host", target=host,
            status=result.status, result=result, idempotency_key=key,
        ))
        return result

    def is_isolated(self, host: str) -> bool:
        return self._hosts.get(host, False)

    def reset(self, host: str) -> None:
        self._hosts.pop(host, None)

    @property
    def actions(self) -> list[ResponseAction]:
        return list(self._actions)
