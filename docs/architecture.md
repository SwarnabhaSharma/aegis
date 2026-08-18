# Aegis — Consolidated Architecture

Approved architecture for Aegis: Autonomous Security Incident Operations Platform.
Greenfield, `D:\Resume\Aegis`. All decisions traceable to ADRs in `docs/adr.md`; assumptions in `docs/assumptions.md`.

---

## 1. What Aegis is

AI-driven security incident platform running full lifecycle `Detect → Triage → Investigate → Correlate → Assess → Plan → Authorize → Respond → Verify → Resolve/Reopen/Escalate`. **AI reasons; deterministic controls govern.** LLM is a reasoning component — it cannot authorize, act, or declare success (ADR-005/016).

## 2. Core principles

1. Minimum necessary data + authority (doc §3.1)
2. AI is reasoning, not security authority (doc §3.2, ADR-005)
3. Deterministic controls own policy/authorization/execution/verification (doc §3.3, ADR-006/016)
4. Evidence integrity — every conclusion linked to evidence (doc §3.4, D-008)
5. Fail-safe — uncertainty → gather → reduce scope → human → escalate → stop (doc §3.5)
6. RAG not core — structured knowledge first (doc §5, ADR-007)
7. Verification required — HTTP 200 ≠ success (doc §16, ADR-009)
8. Secrets hygiene from day one (ADR-010)

## 3. Architecture

**Modular monolith + scenario plugins + multi-agent reasoning** (ADR-015/018).

```
                    ┌─────────────────────────────┐
  Alert source ──►   Ingestion  ──►  Incident store │  (ES: incidents-*)
                    └──────────────┬──────────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │  ORCHESTRATOR (state machine) │  custom, deterministic
                    │  NEW→TRIAGING→INVESTIGATING→  │  (ADR-018)
                    │  CORRELATING→ASSESSING→PLANNED→│
                    │  AUTH→EXECUTING→VERIFYING→     │
                    │  RESOLVED/REOPENED/ESCALATED    │
                    └───┬─────┬─────┬─────┬─────┬──┘
                        │     │     │     │     │
                   ┌────▼┐ ┌─▼──┐ ┌▼───┐ ┌▼────┐ ┌▼─────┐
                   │Tools │ │LLM  │ │Policy│ │Exec │ │Verify │
                   │(read)│ │agents│ │engine│ │(sim)│ │(indep)│
                   └──────┘ └────┘ └─────┘ └─────┘ └──────┘
                        │     │     │     │
                        ▼     ▼     ▼     ▼
                   Scenario adapters (PowerShell first, ADR-020)
                        │     │     │     │
                        ▼     ▼     ▼     ▼
              Evidence ─ Audit ─ Privacy(future) ─ ES store
```

## 4. Agents

**5 LLM reasoning agents + 2 deterministic services** (ADR-015/016).

| Agent | Role | Tools | Writes |
|---|---|---|---|
| A1 Triage | classify, severity, dismiss | none | incident state |
| A2 Investigation | gather evidence, timeline | read tools | evidence |
| A3 Correlation | link events, attack chain | read subset | correlation |
| A4 Threat Analysis | IOC/ATT&CK/confidence | TI lookups | assessment |
| A5 Response Planner | recommend actions | read policy | plan |
| D1 Executor | execute (deterministic) | response tools | action result |
| D2 Verifier | verify (deterministic) | verify tools | verification state |

Rules: store-only handoff (no agent→agent), sequential pipeline, budgets (steps/tool-calls/time), immutable per-agent permissions.

## 5. Tools

Typed contract: schema / risk_class (READ|LOW|MEDIUM|HIGH) / reversible / allowed_agents / timeout / retry / idempotent / rate limit / audit.

- **Read** (A2/A3/A4): search_events, get_process_tree, get_network_connections, get_authentication_events, get_host_details, get_file_activity, lookup_ip/domain/hash, get_policy
- **Response** (D1): isolate_host, disable_account, terminate_process, block_indicator, remove_persistence — simulated executor (ADR-013)
- **Verify** (D2): verify_host_isolated, verify_process_terminated, verify_indicator_blocked, verify_persistence_removed

## 6. Policy engine

Deterministic pure function `(action, facts, policy) → ALLOW | APPROVE | DENY`. Versioned, precedence most-specific, conflict→DENY, dry-run mode, emergency override. Autonomy buckets: fully-auto / policy-authorized / human-approved / forbidden.

## 7. State machine

14 states, explicit transition table with actor authority (Phase C K). Rules: orchestrator/operator mutate only; LLM cannot; timeouts→ESCALATED; idempotent transitions; single-writer per incident; every transition audited.

## 8. Emergency controls

Operator-only, LLM-independent: pause, disable agent/tool, revoke permission, force-approval, disable action, terminate, safe mode, restore. Global/per-agent/per-tool/per-incident.

## 9. Data model

13 entities → ES indices: `incidents-*` (state), `incident-steps-*` (timeline/evidence/agent-runs/tool-calls/policy/approvals/actions/verifications), `audit-*` (audit events). Evidence carries classification + field metadata for later privacy (ADR-003).

## 10. Technology

| Concern | Choice |
|---|---|
| Backend | FastAPI, Python |
| Store | Elasticsearch (Ubuntu VM 192.168.56.105, v8.19.20) — ES-only (ADR-017) |
| LLM backend | llama.cpp server, OpenAI-compat `http://localhost:8080/v1` (ADR-011) |
| LLM client | `openai` python lib (ADR-019) |
| Orchestration | custom in-process state machine (ADR-018) |
| Policy | custom pure function |
| Config/secrets | `.env` + pydantic-settings (ADR-010) |
| Logging | structlog |
| Tests/lint | pytest + ruff (A-018) |

Runtime deps: fastapi, uvicorn, elasticsearch, openai, pydantic, pydantic-settings, python-dotenv, structlog, pytest, ruff. No RAG deps.

## 11. Roadmap

| Phase | Name |
|---|---|
| 0 | Foundations — repo, config, logging, skeleton, pytest+ruff |
| 1 | Core incident engine — lifecycle, synthetic ingestion, state machine, ES stores |
| 2 | Investigation — tool registry, read tools, evidence model, timeline |
| 3 | AI reasoning — llm.py, A1-A5, budgets, fallback |
| 4 | Policy & authorization — engine, versioning, approvals, dry-run |
| 5 | Response — simulated executor, response tools, idempotency |
| 6 | Verification — D2, reopen/escalate, resolve |
| 7 | Correlation & intel — multi-alert, ATT&CK, TI |
| 8 | Privacy — view-layer enforcement (deferred, ADR-003) |
| 9 | Evaluation — corpus + metrics |
| 10 | Production polish — console UI, docs, diagrams, threat model, deployment |

First vertical slice (ADR-020): **PowerShell execution** — alert → triage → process+network investigation → correlation → threat assessment → policy → host isolation → verification → resolved. Proves all 5 agents + D1/D2.

## 12. Security model

Threat model D.1-D.4 in `docs/phase-b.md`: 12 AI-attack scenarios (injection via telemetry, tool abuse, privilege escalation, exfiltration, loops, hallucinated evidence, false remediation, verification manipulation, TI poisoning) each with defense. Fail-safe requirements enforced per phase DoD.

## 13. Deferred / non-goals

Privacy gateway (Phase 8), real VM telemetry (post-Phase 7), multi-role auth (Phase 10), RAG (only if demonstrated need), event bus/microservices (unless scale forces), CI (until pushed).

---

Referenced docs: `assumptions.md`, `adr.md`, `dod.md`, `phase-a.md`, `phase-b.md`, `phase-c.md`, `phase-d.md`, `phase-e.md`.