# Aegis — Phase D: Data Model, Technology, Roadmap, Vertical Slice

Per doc §31-D. Covers L (data model), M (technology stack), N (roadmap), O (first vertical slice). **Stops for review.**

---

## L. Data Model

### L.1 Entities

| Entity | Fields (key) | Relationships |
|---|---|---|
| Incident | id, source_alert_id, type, severity, confidence, state, created_at, updated_at, version | has alerts, evidence, agents, policies, approvals, verifications, audit |
| Alert | id, source, raw, fields, detected_at, severity | belongs to incident |
| Evidence | id, incident_id, source, collection_method, observed_at, raw_ref, classification, tags, provenance | references raw telemetry doc; linked to agent + tool-call |
| TimelineEvent | id, incident_id, ts, actor, action, detail | part of incident timeline |
| Asset | id, hostname, ip, criticality | referenced by evidence, response actions |
| Identity | id, username, domain, risk | referenced by evidence, response actions |
| Indicator | id, value, type (ip/domain/hash), source, malicious | referenced by evidence, TI |
| AgentRun | id, incident_id, agent (A1-A5), status, started, ended, step_count, tool_call_count, output_refs | per-agent execution record |
| ToolCall | id, agent_run_id, tool, input, output_ref, risk_class, allowed, result | audit of tool usage |
| PolicyDecision | id, incident_id, action, policy_version, facts, decision (ALLOW/APPROVE/DENY), reason | links policy → outcome |
| Approval | id, incident_id, action, requested_by, decided_by (operator), decision, ts, note | human approval record |
| ResponseAction | id, incident_id, action, target, status, result, idempotency_key | executed action |
| Verification | id, incident_id, action, expected, actual, passed, ts | independent verify result |
| AuditEvent | id, ts, incident_id, actor, category, detail, data_requested, data_released, data_withheld | tamper-aware log |

### L.2 ES indices

| Index | Entity | Notes |
|---|---|---|
| `incidents-*` | Incident (doc + metadata) | one doc per incident, state machine drives updates |
| `incident-steps-*` | TimelineEvent, AgentRun, ToolCall, PolicyDecision, Approval, ResponseAction, Verification, Evidence | one doc per step/event; parent=incident_id |
| `audit-*` | AuditEvent | append-only; future tamper-watch (hash chain) |
| `telemetry-*` | raw events (existing SOC pattern) | read-only for evidence |

### L.3 Data flow

```
Alert → Incident(incidents-*) → evidence gathered (telemetry refs)
  → AgentRun+ToolCall (incident-steps-*)
  → PolicyDecision, Approval, ResponseAction, Verification (incident-steps-*)
  → AuditEvent (audit-*)
```

Privacy (ADR-003 deferred): evidence carries `classification` + field metadata now; view-layer enforcement added Phase 8 without re-indexing.

---

## M. Technology Stack

### M.1 Decisions

| Concern | Choice | Alternatives rejected | Why |
|---|---|---|---|
| Backend | FastAPI (Python) | Flask, Go, Node | typed, async, prior proven pattern |
| Store | Elasticsearch (Ubuntu VM **192.168.56.105**, v8.19.20) | SQLite, Postgres, MongoDB | ADR-017 ES-only; telemetry already in ES |
| LLM backend | llama.cpp server, OpenAI-compat | ollama, LM Studio (superseded) | ADR-011 user decision |
| LLM client | `openai` python lib | httpx raw, ollama lib | ADR-019; OpenAI-compat target |
| Agent orchestration | Custom orchestrator | LangGraph, CrewAI | ADR-018; Phase C spec owns flow |
| State machine | in-process, deterministic | event bus, temporal, workflow engine | ADR-008/018; simplicity + authority |
| Policy engine | custom pure function | rule-engine lib, LLM reasoning | ADR-006; determinism + testability |
| Config/secrets | `.env` + pydantic-settings | Vault, docker secrets | local scale, ADR-010 |
| Testing | pytest + ruff | unittest, black+flake8 | A-018 user lock |
| Observability | structlog + stdlib logging | OpenTelemetry stack | local scale; structured logs enough |

### M.2 Trade-offs notes

- **ES-only**: weaker transactions vs relational; fine at portfolio scale; single store keeps ops trivial. Change trigger: multi-user concurrent editing or strong integrity needs → add relational layer.
- **Custom orchestrator**: hand-written routing vs framework scaffolding. Framework rejected: abstraction without security value, and Phase C flow is fully specified/deterministic.
- **`openai` lib**: tracks OpenAI API; LM Studio compatible. Swap cost = adapter in `integrations/llm.py`.

### M.3 Package list (Phase 0)

```
fastapi, uvicorn, elasticsearch, openai, pydantic, pydantic-settings,
python-dotenv, structlog, pytest, ruff
```

No other runtime deps. No RAG deps (ADR-007). YAGNI enforced.

---

## N. Roadmap

Merge of doc §25 phases with prior build order + ADRs. Phases gated (full DoD in `dod.md`).

| Phase | Name | Key deliverable | Builds on |
|---|---|---|---|
| 0 | Foundations | repo, config, logging, module skeleton, pytest+ruff | ADR-010/018 |
| 1 | Core incident engine | lifecycle, ingestion (synthetic), state machine, ES stores | L, ADR-017 |
| 2 | Investigation | tool registry + read tools, evidence model, timeline | H, A-014 |
| 3 | AI reasoning | `integrations/llm.py`, A1-A5 agents, budgets, fallback | M.2, ADR-018/019 |
| 4 | Policy & authorization | policy engine, versioning, approvals, dry-run | J, ADR-006 |
| 5 | Response | simulated executor, response tools, idempotency | H, ADR-013 |
| 6 | Verification | D2 verifier, reopen/escalate, resolve | H, ADR-016 |
| 7 | Correlation & intel | multi-alert correlation, ATT&CK, TI enrichment | A3/A4 |
| 8 | Privacy | view-layer enforcement (deferred per ADR-003) | L.1 field metadata |
| 9 | Evaluation | reproducible corpus + metrics | A-014 |
| 10 | Production polish | console UI, docs, diagrams, threat model, deployment | ADR-014 |

### N.1 Sequencing note

Full platform vision (ADR-002) → phases build breadth, not just one slice. PowerShell slice (ADR-020) is the proof-thread that validates phases 1-6 in sequence; other incident types extend via scenario adapters (E.4).

---

## O. First Vertical Slice — PowerShell Execution

### O.1 Scenario

Malicious PowerShell execution (doc §27): alert → triage → process investigation → network investigation → correlation → threat assessment → policy → host isolation → verification → resolution.

### O.2 Flow through architecture

| Step | State | Actor | Action |
|---|---|---|---|
| 1 | NEW | ingestion | synthetic alert: Office spawns encoded PowerShell |
| 2 | TRIAGING | A1 Triage | classify severe; plan investigation |
| 3 | INVESTIGATING | A2 Investigation | read tools: get_process_tree, get_network_connections, get_file_activity, search_events → evidence |
| 4 | CORRELATING | A3 Correlation | link process→conn→parent-child chain; affected assets |
| 5 | ASSESSING | A4 Threat Analysis | TI lookups on C2 IP/hash; ATT&CK T1059.001 mapping; confidence |
| 6 | RESPONSE_PLANNED | A5 Planner | recommend isolate_host(host) w/ rationale + expected result |
| 7 | AWAITING_APPROVAL | policy engine | isolate_host on critical asset → HUMAN approve (or auto on non-critical, conf≥.9, ≥3 evidence) |
| 8 | AUTHORIZED | operator | approve |
| 9 | EXECUTING | D1 Executor | simulated isolate_host |
| 10 | VERIFYING | D2 Verifier | verify_host_isolated → state check |
| 11 | RESOLVED | orchestrator | passed → resolved; audit replay complete |

### O.3 Policy profile (PowerShell slice)

```yaml
action: isolate_host
conditions:
  confidence: ">= 0.90"
  asset_criticality: "!= critical"   # critical → human approval
  evidence_count: ">= 3"
approval_required: false
```

### O.4 Verify checks

```text
verify_host_isolated(host) → simulated state "isolated:true" (was "false")
```

Failure → REOPEN → re-investigate → second fail → ESCALATED (human-owned).

---

**Gate: Phase D complete. Await review before Phase E (risks + final review → consolidated architecture).**