# Aegis Gap Audit — Living Tracker

- **Source of truth**: `D:\Resume\Aegis — Master Project Architecture Prompt — Polished.md` (§3–§29)
- **Audit date**: 2026-08-22 (post Phase 0–7 + consolidation, commit `c53d00b`)
- **Legend**:
  - `PRESENT` — built, meets spec
  - `PARTIAL` — exists, below spec (notes name the delta)
  - `ABSENT` — required by spec, not built
  - `DEFERRED (ADR-nnn)` — deliberate decision, NOT backlog; only ADR-backed items may use this
- **Update rule**: when an item closes, flip the token, append commit hash. `grep ABSENT docs/gap-audit.md` = true backlog; `grep DEFERRED` = intentional non-goals.

---

## §3 Core Design Principles

| Requirement | Status | Where / Notes |
|---|---|---|
| Minimum necessary data & authority | PARTIAL | Authority minimal (`state_machine.py`, registry); agents see full context dict — no field minimization (blocked on privacy §10) |
| AI authority boundary (3.2) | PRESENT | Agents propose-only; state machine rejects agent actor |
| AI vs deterministic split (3.3) | PRESENT | LLM confined to `agents/reasoning.py`; D1/D2 deterministic |
| Evidence integrity (3.4) | PARTIAL | Degrade-not-fabricate ✅; evidence_ids unvalidated (#6); synthetic-vs-real provenance flag missing on Evidence |
| Fail-safe operation (3.5) | PRESENT | Degrade→ESCALATED, budget→stop, verify-fail→REOPEN→ESCALATED |

## §4 Autonomy model

| Requirement | Status | Where |
|---|---|---|
| Four buckets (auto / policy-authorized / human-approved / forbidden) | PRESENT | `policies/engine.py`, state machine |

## §5 RAG position

| Requirement | Status | Notes |
|---|---|---|
| No RAG unless justified | DEFERRED (ADR-007) | Not needed for current design |

## §6 Lifecycle / §12 State machine

| Requirement | Status | Where |
|---|---|---|
| Full lifecycle + actor authority + fail-safes | PRESENT | `orchestrator/state_machine.py`, `engine.py`; transitions recorded + timeline mirrors |

## §7 Agent architecture

| Agent | Status | Notes |
|---|---|---|
| A1 Triage | PRESENT | agentic-capable |
| A2 Investigation | PRESENT | agentic over real tools |
| A3 Correlation | PRESENT | shared-IOC correlation live since evidence persistence |
| A4 Threat Analysis | PARTIAL | ATT&CK subset = 8 techniques; TI static local store |
| A5 Response Planner | PRESENT | fetches policy itself via registry |
| Response Agent (D1) | DEFERRED (ADR-013) | simulated executor until real backend phase |
| Verification Agent (D2) | PARTIAL | service exists; 3 of 4 verify methods unreachable (no producing action) (#11) |

## §8 Tool architecture

| Item | Status | Notes |
|---|---|---|
| search_events / get_process_tree / get_network_connections | PRESENT | ES + in-memory backends |
| get_file_activity | ABSENT | named in slice flow O.2 |
| get_authentication_events / get_host_details | ABSENT | spec investigation tools |
| lookup_ip / domain / hash | PRESENT | rich TI shape |
| get_threat_intelligence | ABSENT | aggregate intel tool |
| isolate_host | PRESENT | idempotent, simulated backend |
| terminate_process / block_indicator / disable_account / remove_persistence | ABSENT | response set (#11) |
| verify_host_isolated / process_terminated / indicator_blocked / persistence_removed | PRESENT (code) | 3 of 4 can never pass naturally until producers exist (#11) |
| Typed input schema | PRESENT | loose dict types |
| Typed output schema | ABSENT | not declared on Tool |
| Authorization + permitted agents | PRESENT | registry-enforced gate |
| Risk classification | PRESENT | READ/LOW/MEDIUM/HIGH |
| Audit logging per tool call | ABSENT | part of #4/#5 |
| Timeout enforcement | PARTIAL | field exists, never enforced |
| Retry behavior | PARTIAL | field exists, never used |
| Rate limits | ABSENT | |
| Idempotency | PRESENT | executor dedupes by key |

## §9 Security authority model

| Requirement | Status | Notes |
|---|---|---|
| Registry + state machine + policy as controls | PRESENT | executor still called direct in slice tail (#7) |

## §10 Privacy architecture

| Requirement | Status | Notes |
|---|---|---|
| PII detection | ABSENT | |
| Secret/credential detection | ABSENT | |
| Data classification engine | ABSENT | inert tag on Evidence only |
| Redaction / tokenization | ABSENT | |
| Field-level access control | ABSENT | |
| Contextual minimization | ABSENT | agents see full context dict |
| Four representations (raw/filtered/AI-visible/analyst-visible) | ABSENT | |
| Auditable privacy decisions ("why received / why withheld") | ABSENT | audit fields reserved in schema |
| Dimension analysis (field/role/agent/task/incident/asset/context) | ABSENT | |

Whole subsystem DEFERRED to Phase 8 sequencing (ADR-003) but individual capabilities above stay ABSENT until designed/built under T3.

## §11 Agent data/action permissions

| Requirement | Status | Notes |
|---|---|---|
| Static per-agent tool sets | PRESENT | registry allowed_agents |
| Conditional dimensions (state/criticality/confidence/time-based) | ABSENT | unmodeled |

## §13 Policy engine

| Requirement | Status | Notes |
|---|---|---|
| Pure evaluate() ALLOW/APPROVE/DENY | PRESENT | no LLM involvement |
| Versioned decisions | PRESENT | policy_version on every decision |
| Conflict → DENY fail-safe | PRESENT | simplified agree-or-DENY |
| Most-specific precedence | PARTIAL | simplified away (#12) |
| Emergency override | PARTIAL | engine fn exists; no API/control-surface endpoint |
| Dry-run mode | PRESENT | flag on record |
| YAML policy files | ABSENT | Python dicts by choice (lazy pick #3, revisit if ops demand) |

## §14 Evidence-driven AI

| Requirement | Status | Notes |
|---|---|---|
| Provenance/timestamps/source/method/raw-ref/classification | PRESENT | Evidence model |
| Confidence-per-evidence | ABSENT | |
| Relationships / evidence graph | ABSENT | simpler model chosen; justification doc owed |
| Contradictory evidence handling | ABSENT | |
| Evidence expiration | ABSENT | |
| Conclusions linked to existing evidence (D-008 enforcement) | ABSENT | #6 validation |

## §15 Adversarial security

| Threat | Status | Notes |
|---|---|---|
| Prompt injection via telemetry | ABSENT | command lines/filenames flow raw into prompts — T1 priority |
| Indirect prompt injection | ABSENT | same hole |
| Tool abuse | PRESENT | registry authorization |
| Privilege escalation | PRESENT | static permission sets |
| Data exfiltration | PARTIAL | tool scope bounds reads; no minimization layer |
| Malicious threat intelligence | ABSENT | N/A until external TI source exists |
| Agent loops | PRESENT | no agent→agent calls; budgets |
| Excessive tool calls | PRESENT | real budget accounting |
| Hallucinated evidence | ABSENT | #6 validation closes it |
| False remediation | PRESENT | D2 verifies actual state |
| Verification manipulation | PRESENT | verifier separate deterministic service |

## §16 Response safety

| Requirement | Status | Notes |
|---|---|---|
| isolate_host full safety profile | PRESENT | risk/reversibility/idempotency/verify/failure-path |
| Structured ActionSpec (expected result/rollback/timeout/failure→escalation) for all actions | ABSENT | #8 |
| "HTTP 200 ≠ success" | PRESENT | D2 independent verification |

## §17 Human override & emergency controls

| Requirement | Status | Notes |
|---|---|---|
| Operator approve/deny | PRESENT | API endpoint + state machine gate |
| Policy override fn | PARTIAL | exists in engine; no control surface endpoint |
| Pause autonomy | ABSENT | T2 |
| Disable individual agents | ABSENT | T2 |
| Revoke tool permissions at runtime | ABSENT | T2 |
| Require-approval-for-all mode | ABSENT | T2 |
| Terminate active workflow | ABSENT | T2 |
| Safe mode + restore | ABSENT | T2 |

## §18 Observability & audit

| Requirement | Status | Notes |
|---|---|---|
| Transitions + timeline records | PRESENT | incidents-steps index |
| Policy version capture | PRESENT | on every decision |
| audit-* index + AuditEvent entity | ABSENT | #4 |
| Full capture list (model/version, prompt id, data requested/released/withheld, tool requested, authz decision, retries) | ABSENT | #4/#5 |
| AgentRun / ToolCall persisted records | ABSENT | #5 |
| Tamper protection (hash chain) | ABSENT | post-#4 |

## §19 Data model entities

| Entity | Status |
|---|---|
| Incident / Alert / TimelineEvent / Evidence / Transition | PRESENT |
| Asset / Identity / Indicator | ABSENT (#9 asset = hardcoded dict) |
| AgentRun / ToolCall / PolicyDecision-persisted / Approval / ResponseAction-persisted / Verification-persisted | ABSENT (#5) |
| AuditEvent | ABSENT (#4) |

Indices: `incidents-*` ✅ · `incident-steps-*` ✅ partial · `audit-*` ❌ · `telemetry-*` ✅ read-only.

## §20 Evaluation framework

| Requirement | Status | Notes |
|---|---|---|
| Reproducible corpus (TP/FP/ambiguous/injection/multi-stage…) | ABSENT | T4; synthetic generator extensible |
| Metrics (detection/investigation/AI-reliability/security/response/efficiency) | ABSENT | T4 |
| Deterministic-baseline comparison | ABSENT | T4 optional |

## §21 Versioning & reproducibility

| Requirement | Status | Notes |
|---|---|---|
| Policy version per incident decision | PRESENT | |
| Model version recording | ABSENT | T1 manifest |
| Prompt ids/versioning | ABSENT | prompts inline, no ids |
| Tool schema versions | ABSENT | |
| Per-incident version manifest block | ABSENT | T1 |

## §26 DoD discipline

| Requirement | Status | Notes |
|---|---|---|
| Tests incl. error/unauthorized cases per feature | PRESENT | 75 tests |
| Written per-feature DoD before implementation | ABSENT | process change, adopt from T1 onward |
| Audit-event generation asserted in tests | ABSENT | blocked on #4 |

## §27 First vertical slice

| Requirement | Status | Notes |
|---|---|---|
| PowerShell slice end-to-end | PRESENT | CLI + API + tests; real telemetry + real Ornith verified |
| Privacy filtering step in slice flow | ABSENT | gated on §10 (T3) |
| Executor realism | DEFERRED (ADR-013) | simulated until real backend phase |

## §28 UX console

| View | Status |
|---|---|
| All six views (queue/detail/privacy/agent activity/response/audit) | ABSENT — API is the foundation; Phase 10 |

## §29 Portfolio standard

| Requirement | Status | Notes |
|---|---|---|
| Documentation set (ADRs/assumptions/phases) | PRESENT | docs/ |
| README.md | ABSENT | T4 |
| Architecture diagrams | ABSENT | T4 |
| Threat model document | ABSENT | T4 (§15 analysis feeds it) |
| CI pipeline | ABSENT | T4 |
| Packaged demo scenarios + reproducible evaluation | ABSENT | T4 |
| Limitations/trade-offs explained | PARTIAL | scattered in ADRs/docs; consolidate in T4 README |

---

## Build tiers → sections closed

| Tier | Scope | Closes sections | Debt ids retired |
|---|---|---|---|
| T1 Security hardening | telemetry-as-untrusted defense; evidence_ids validation; audit pipeline (#4+#5); version manifest | §15, §14(D-008), §18, §19(partial), §21 | #4, #5, #6 |
| T2 Controls + tools | emergency controls; get_file_activity (+auth/host reads); response tools ↔ verifier seams; ActionSpec struct; executor-via-registry | §17, §8, §16, §9(#7), §7(#11) | #7, #8, #11 |
| T3 Minimal privacy layer | detect→classify→AI-visible allowlist per agent/task→logged decisions | §10(minimal), §27 privacy step | #9 (asset map folds into classification context) |
| T4 Eval + portfolio | corpus + metrics runner; README; diagrams; threat model; CI | §20, §26, §28(foundation), §29 | #12 doc note |

Deferred-by-decision (not backlog): privacy full gateway sequencing (ADR-003), executor realism (ADR-013), RAG (ADR-007).

---

*Update rule: flip token + commit hash per closed row. Keep this file honest — a wrong PRESENT here is a lie an interviewer will find.*
