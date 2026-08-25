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
    """In-memory response actions. Idempotent via idempotency_key.

    State written here is what D2 verifies against — single source of truth
    (fixes unreachable verifier seams, debt #11).
    """

    def __init__(self) -> None:
        self._hosts: dict[str, bool] = {}  # host -> isolated
        self._by_key: dict[str, ResponseResult] = {}
        self._actions: list[ResponseAction] = []
        self._terminated: set[tuple[str, str]] = set()   # (host, pid)
        self._blocked: set[str] = set()                   # indicators
        self._clean: set[str] = set()                     # persistence-removed hosts
        self._disabled_accounts: set[str] = set()

    def _record(self, incident_id, action, target, key, result):
        self._actions.append(ResponseAction(
            incident_id=incident_id, action=action, target=target,
            status=result.status, result=result, idempotency_key=key,
        ))

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
        self._record(incident_id, "isolate_host", host, key, result)
        return result

    def terminate_process(self, host: str, pid: str) -> ResponseResult:
        """Idempotent: terminating an already-dead pid reports success."""
        self._terminated.add((host, pid))
        result = ResponseResult(host=host, isolated=False,
                                status="terminated",
                                message=f"process {pid} terminated (simulated)")
        self._record("", "terminate_process", f"{host}:{pid}",
                     f"terminate_process:{host}:{pid}", result)
        return result

    def block_indicator(self, indicator: str) -> ResponseResult:
        """Reversible via unblock_indicator rollback."""
        self._blocked.add(indicator)
        result = ResponseResult(host=indicator, isolated=False,
                                status="blocked",
                                message=f"{indicator} blocked (simulated)")
        self._record("", "block_indicator", indicator,
                     f"block_indicator:{indicator}", result)
        return result

    def remove_persistence(self, host: str) -> ResponseResult:
        self._clean.add(host)
        result = ResponseResult(host=host, isolated=False,
                                status="persistence_removed",
                                message=f"persistence removed on {host} (simulated)")
        self._record("", "remove_persistence", host,
                     f"remove_persistence:{host}", result)
        return result

    def disable_account(self, username: str) -> ResponseResult:
        """Idempotent. State read by verify_account_disabled (D2)."""
        self._disabled_accounts.add(username.lower())
        result = ResponseResult(host=username.lower(), isolated=False,
                                status="account_disabled",
                                message=f"account {username} disabled (simulated)")
        self._record("", "disable_account", username,
                     f"disable_account:{username.lower()}", result)
        return result

    # -- state readers (D2 verifies against these) --

    def process_terminated(self, host: str, pid: str) -> bool:
        return (host, pid) in self._terminated

    def indicator_blocked(self, indicator: str) -> bool:
        return indicator in self._blocked

    def persistence_removed(self, host: str) -> bool:
        return host in self._clean

    def account_disabled(self, username: str) -> bool:
        return username.lower() in self._disabled_accounts

    def is_isolated(self, host: str) -> bool:
        return self._hosts.get(host, False)

    def reset(self, host: str) -> None:
        self._hosts.pop(host, None)

    @property
    def actions(self) -> list[ResponseAction]:
        return list(self._actions)
