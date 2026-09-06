"""Approval queue for autonomous operations.

When the loop decides an action needs human approval, the request is queued
here. The loop continues investigating other alerts while waiting.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


class ApprovalStatus(enum.StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


@dataclass
class ApprovalRequest:
    id: str = field(default_factory=lambda: f"apr-{uuid.uuid4().hex[:12]}")
    incident_id: str = ""
    action: str = ""
    reason: str = ""
    decision: str = ""  # ALLOW/APPROVE/DENY from policy engine
    facts: dict = field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None
    resolved_by: str = ""


class ApprovalQueue:
    """In-memory approval queue. Thread-safe via GIL for portfolio use."""

    def __init__(self) -> None:
        self._queue: dict[str, ApprovalRequest] = {}

    def enqueue(self, incident_id: str, action: str, reason: str,
                decision: str = "", facts: dict | None = None) -> ApprovalRequest:
        req = ApprovalRequest(
            incident_id=incident_id, action=action, reason=reason,
            decision=decision, facts=facts or {},
        )
        self._queue[req.id] = req
        return req

    def approve(self, request_id: str, by: str = "operator") -> ApprovalRequest | None:
        return self._resolve(request_id, ApprovalStatus.APPROVED, by)

    def deny(self, request_id: str, by: str = "operator") -> ApprovalRequest | None:
        return self._resolve(request_id, ApprovalStatus.DENIED, by)

    def get(self, request_id: str) -> ApprovalRequest | None:
        return self._queue.get(request_id)

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self._queue.values()
                if r.status == ApprovalStatus.PENDING]

    def all_requests(self) -> list[ApprovalRequest]:
        return list(self._queue.values())

    def stats(self) -> dict:
        all_reqs = list(self._queue.values())
        return {
            "total": len(all_reqs),
            "pending": sum(1 for r in all_reqs if r.status == ApprovalStatus.PENDING),
            "approved": sum(1 for r in all_reqs if r.status == ApprovalStatus.APPROVED),
            "denied": sum(1 for r in all_reqs if r.status == ApprovalStatus.DENIED),
        }

    def _resolve(self, request_id: str, status: ApprovalStatus,
                 by: str) -> ApprovalRequest | None:
        req = self._queue.get(request_id)
        if req is None or req.status != ApprovalStatus.PENDING:
            return None
        req.status = status
        req.resolved_at = datetime.now(UTC)
        req.resolved_by = by
        return req
