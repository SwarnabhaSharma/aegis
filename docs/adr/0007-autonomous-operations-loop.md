# ADR-007 — Autonomous Operations Loop

- **Decision**: Add an autonomous operations loop as the outer layer of Aegis. The loop continuously polls ES for alerts, prioritizes by `severity × age × asset_criticality` (multiplicative scoring), and feeds them into the existing single-alert investigate pipeline. Approval requests are queued; the loop continues investigating other alerts while waiting. Sequential investigation (one alert at a time). Backpressure: slow down when model/ES overloaded.

- **Alternatives**:
  - Request-response only (current state): operator points Aegis at one alert at a time
  - Event-driven: ES watcher triggers pipeline on new alert
  - Batch mode: operator says "process top N" and agents work through them

- **Recommendation**: Poll & prioritize as the core autonomous loop. Batch mode can be built on top.

- **Rationale**: User vision — Aegis should autonomously work through a backlog of 60k alerts, not wait for human direction on which alert to investigate next. The existing single-alert pipeline is the right inner core; the new layer decides *which* alert to work on *when*.

- **Trade-offs**:
  - More complex: new orchestrator module, priority queue, approval queue management
  - Stateful: must track progress across the backlog (which alerts processed, which pending)
  - Resource management: must handle ES polling intervals, backpressure, model budget caps
  - Gains: true autonomous operations, the core value proposition

- **Status**: APPROVED

- **Downstream**:
  - New module: `aegis/operations/loop.py` — autonomous poll + prioritize + feed
  - New module: `aegis/operations/approval_queue.py` — async approval management
  - Existing `investigate()` unchanged — called by the loop for each alert
  - Existing API gains: `GET /operations/status` (loop status), `POST /operations/start|stop`
  - ES index: `aegis-operations-state` for loop progress tracking
  - Console UI extended: operations status panel, approval queue view
  - Executor/Verifier: keep simulated; design for real EDR swap later via clean contract
