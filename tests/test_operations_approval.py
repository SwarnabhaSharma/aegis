"""Tests for operations approval queue."""

from aegis.operations.approval_queue import ApprovalQueue, ApprovalStatus


def test_enqueue_and_get():
    q = ApprovalQueue()
    req = q.enqueue("inc-1", "isolate_host", "high severity")
    assert req.incident_id == "inc-1"
    assert req.status == ApprovalStatus.PENDING
    assert q.get(req.id) is req


def test_approve():
    q = ApprovalQueue()
    req = q.enqueue("inc-1", "isolate_host", "reason")
    result = q.approve(req.id)
    assert result.status == ApprovalStatus.APPROVED
    assert result.resolved_by == "operator"
    assert result.resolved_at is not None


def test_deny():
    q = ApprovalQueue()
    req = q.enqueue("inc-1", "disable_account", "reason")
    result = q.deny(req.id)
    assert result.status == ApprovalStatus.DENIED


def test_cannot_resolve_twice():
    q = ApprovalQueue()
    req = q.enqueue("inc-1", "action", "reason")
    q.approve(req.id)
    result = q.approve(req.id)
    assert result is None


def test_pending_filter():
    q = ApprovalQueue()
    r1 = q.enqueue("inc-1", "a1", "reason")
    r2 = q.enqueue("inc-2", "a2", "reason")
    q.approve(r1.id)
    pending = q.pending()
    assert len(pending) == 1
    assert pending[0].id == r2.id


def test_stats():
    q = ApprovalQueue()
    r1 = q.enqueue("inc-1", "a", "reason")
    q.enqueue("inc-2", "b", "reason")
    q.approve(r1.id)
    stats = q.stats()
    assert stats["total"] == 2
    assert stats["pending"] == 1
    assert stats["approved"] == 1
    assert stats["denied"] == 0


def test_all_requests():
    q = ApprovalQueue()
    q.enqueue("inc-1", "a", "reason")
    q.enqueue("inc-2", "b", "reason")
    assert len(q.all_requests()) == 2


def test_get_nonexistent():
    q = ApprovalQueue()
    assert q.get("no-such-id") is None
