"""Autonomous operations loop.

Polls store for NEW incidents, ranks by priority, feeds highest-priority
incident into investigate(), queues approval requests when policy decides
APPROVE. Continues investigating while approval is pending.

Usage:
    loop = OperationsLoop(store, llm, controls=controls)
    loop.start()          # background thread
    loop.stop()           # graceful shutdown
    loop.status()         # {running, processed, pending, ...}
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis.incidents.schema import IncidentState
from aegis.operations.approval_queue import ApprovalQueue
from aegis.operations.priority import rank_incidents
from aegis.policies.engine import Decision

logger = logging.getLogger(__name__)


@dataclass
class LoopState:
    running: bool = False
    processed: int = 0
    failed: int = 0
    skipped: int = 0
    current_incident: str = ""
    started_at: datetime | None = None
    last_cycle_at: datetime | None = None
    errors: list[str] = field(default_factory=list)


class OperationsLoop:
    """Autonomous poll → prioritize → investigate → approve queue.

    Sequential: one alert at a time. Backpressure: sleep on cycle time.
    """

    def __init__(self, store, llm, controls=None, registry=None,
                 poll_interval: int | None = None, confidence_floor: float = 0.95):
        self.store = store
        self.llm = llm
        self.controls = controls
        self.registry = registry
        self.confidence_floor = confidence_floor
        self.approval_queue = ApprovalQueue()
        self.state = LoopState()

        if poll_interval is not None:
            self._poll_interval = poll_interval
        else:
            self._poll_interval = int(os.getenv("AEGIS_POLL_INTERVAL", "300"))

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self.state.running:
            return
        self.state.running = True
        self.state.started_at = datetime.now(UTC)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="aegis-ops-loop")
        self._thread.start()
        logger.info("Operations loop started (interval=%ds)", self._poll_interval)

    def stop(self) -> None:
        if not self.state.running:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=30)
        self.state.running = False
        logger.info("Operations loop stopped")

    def status(self) -> dict:
        return {
            "running": self.state.running,
            "processed": self.state.processed,
            "failed": self.state.failed,
            "skipped": self.state.skipped,
            "current_incident": self.state.current_incident,
            "started_at": self.state.started_at.isoformat() if self.state.started_at else None,
            "last_cycle_at": (self.state.last_cycle_at.isoformat()
                               if self.state.last_cycle_at else None),
            "pending_approvals": len(self.approval_queue.pending()),
            "poll_interval": self._poll_interval,
            "errors": self.state.errors[-10:],  # last 10
        }

    def run_cycle(self) -> dict:
        """One poll cycle: fetch → rank → investigate top alert. Returns cycle summary."""
        from aegis.slice import investigate

        self.state.last_cycle_at = datetime.now(UTC)

        # Fetch NEW incidents, filter out already-investigating
        candidates = self._fetch_new_incidents()
        if not candidates:
            return {"processed": 0, "skipped": 0, "reason": "no new incidents"}

        ranked = rank_incidents(candidates)
        top = ranked[0]

        # Skip if paused or incident cancelled
        if self.controls and (self.controls.paused
                              or top.id in self.controls.cancelled_incidents):
            self.state.skipped += 1
            return {"processed": 0, "skipped": 1, "reason": "paused or cancelled"}

        self.state.current_incident = top.id
        logger.info("Processing incident %s (severity=%s, host=%s)",
                     top.id[:12], top.severity, top.fields.get("host", "?"))

        try:
            result = investigate(
                self.store, top.id, self.llm,
                registry=self.registry,
                confidence_floor=self.confidence_floor,
                controls=self.controls,
            )

            if not result["ok"]:
                self.state.failed += 1
                err = result.get("errors", ["unknown"])
                self.state.errors.append(f"{top.id}: {err}")
                return {"processed": 0, "failed": 1, "incident": top.id, "errors": err}

            # Queue approval if policy decided APPROVE
            decision = result.get("decision")
            if decision and decision.decision == Decision.APPROVE:
                self.approval_queue.enqueue(
                    incident_id=top.id,
                    action=decision.action,
                    reason=decision.reason,
                    decision=decision.decision.value,
                    facts=decision.facts,
                )
                logger.info("Approval queued for %s: %s", top.id[:12], decision.action)

            self.state.processed += 1
            return {"processed": 1, "incident": top.id,
                    "decision": decision.decision.value if decision else None}

        except Exception as exc:
            self.state.failed += 1
            self.state.errors.append(f"{top.id}: {exc}")
            logger.exception("Investigation failed for %s", top.id[:12])
            return {"processed": 0, "failed": 1, "incident": top.id, "error": str(exc)}

        finally:
            self.state.current_incident = ""

    def _fetch_new_incidents(self) -> list:
        """Get incidents in NEW state from the store."""
        ids = self.store.all_incident_ids()
        new = []
        for iid in ids:
            inc = self.store.get(iid)
            if inc is not None and inc.state == IncidentState.NEW:
                new.append(inc)
        return new

    def _run(self) -> None:
        """Background loop thread."""
        while not self._stop_event.is_set():
            try:
                self.run_cycle()
            except Exception:
                logger.exception("Operations loop cycle failed")
            # Sleep in small increments so stop() is responsive
            interval = self._poll_interval
            if interval <= 0:
                interval = 1  # continuous mode: poll every 1s
            for _ in range(interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)
