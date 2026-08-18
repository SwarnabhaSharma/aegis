# Aegis — Architecture Decision Log

Format: ID / decision / alternatives / recommendation / rationale / trade-offs / status / downstream impact

Status: OPEN | APPROVED | REJECTED | SUPERSEDED

---

## ADR-001 — Greenfield project
- **Decision**: Aegis is a separate greenfield repo (`D:\Resume\Aegis`). Zero code reuse from SOC-SOAR or incident-remediation V1.
- **Alternatives**: Fork/expand existing incident-remediation V1; reuse as foundation.
- **Recommendation**: Greenfield.
- **Rationale**: User decision. Clean slate for the larger Aegis vision; prior work informs but does not bind.
- **Trade-offs**: Re-implements some plumbing already proven; gains clean architecture + portfolio independence.
- **Status**: APPROVED
- **Downstream**: All module design fresh; prior V1 module layout is input only.

## ADR-002 — Phased build, full platform vision
- **Decision**: Build the whole platform in phases over many sessions. First vertical slice deferred until core engine + one scenario path exist.
- **Alternatives**: First-vertical-slice-first (doc §27).
- **Recommendation**: Full platform vision (user choice).
- **Rationale**: User decision; portfolio scope ambition.
- **Trade-offs**: Longer to first end-to-end demo; better architecture per phase.
- **Status**: APPROVED
- **Downstream**: Roadmap in `dod.md`; each phase gated.

## ADR-003 — Privacy deferred
- **Decision**: Privacy gateway (doc §10) deferred to a later phase; minimal PII/secret field detection + redaction may appear earlier only if cheap.
- **Alternatives**: Full privacy gateway early; minimal-viable privacy early.
- **Recommendation**: Defer (user choice).
- **Rationale**: User decision; portfolio project priority order.
- **Trade-offs**: Less impressive early privacy story; must still design data model to not block later privacy.
- **Status**: APPROVED
- **Downstream**: Data model keeps field metadata so privacy can be layered; Phase 8 revisit.

## ADR-004 — Live gated architecture sessions
- **Decision**: Plan via doc §31 conversation: Phase A → B → C → D → E, each with a review stop. No consolidated architecture dump in one shot.
- **Alternatives**: One consolidated written architecture doc.
- **Recommendation**: Live gated (user choice).
- **Rationale**: Doc §31 explicit; keeps user input at each decision point.
- **Trade-offs**: Slower to a written doc; better decisions.
- **Status**: APPROVED
- **Downstream**: Session flow; ADR log updated per phase.

## ADR-005 — AI is a reasoning component, not a security authority
- **Decision**: LLM may interpret/correlate/hypothesize/recommend/request. It may not authorize, bypass policy, execute arbitrary commands, or declare success without verification.
- **Alternatives**: Trusted-agent design (LLM with broad access).
- **Recommendation**: Untrusted-reasoning design.
- **Rationale**: Doc §3.2; adversarial reality (prompt injection, hallucination, tool abuse).
- **Trade-offs**: Less "impressive" raw autonomy; correct security posture.
- **Status**: APPROVED (core principle, not yet full detail)
- **Downstream**: Agent model (Phase C), authority model, every tool boundary.

## ADR-006 — Deterministic controls own authority
- **Decision**: Policy engine, authorization, execution, and verification are deterministic. LLM proposes; policy decides.
- **Alternatives**: LLM-in-the-loop policy reasoning.
- **Recommendation**: Deterministic policy.
- **Rationale**: Doc §13, §16; reproducibility, auditability, testability.
- **Trade-offs**: Less flexible policies; far safer.
- **Status**: APPROVED (core principle)
- **Downstream**: policy module, tool gate, executor, verifier.

## ADR-007 — RAG not core
- **Decision**: No RAG in initial architecture. Structured knowledge (YAML/JSON playbooks, ATT&CK mappings, policies, SIEM queries) first. RAG only after demonstrated need (doc §5 criteria).
- **Alternatives**: RAG-first.
- **Recommendation**: No-RAG-first.
- **Rationale**: Doc §5; deterministic > retrieval for most SOC knowledge.
- **Trade-offs**: Must hand-curate structured knowledge.
- **Status**: APPROVED
- **Downstream**: Knowledge layer is structured; revisit at Phase 7/8.

## ADR-008 — Modular monolith, not microservices/event bus initially
- **Decision**: Single deployable Python service with internal modules; no message bus, no service mesh. Re-evaluate only if a concrete requirement forces it.
- **Alternatives**: Event-driven workflow engine; microservices.
- **Recommendation**: Modular monolith.
- **Rationale**: Doc §24; doc §23 bias for simplest architecture satisfying security requirements.
- **Trade-offs**: Less horizontal scale; far simpler ops and audit.
- **Status**: APPROVED (provisional — Phase B architecture alternatives will confirm/challenge)
- **Downstream**: Module layout; concurrency model.

## ADR-009 — Success requires verification
- **Decision**: An action is not complete until an independent verification step confirms the expected result. HTTP 200 is not success.
- **Alternatives**: Trust tool API response.
- **Recommendation**: Independent verification.
- **Rationale**: Doc §16, §26; false-remediation risk.
- **Trade-offs**: Extra step per action; mandatory.
- **Status**: APPROVED (core principle)
- **Downstream**: Response tools paired with verify tools; state machine VERIFY state.

## ADR-010 — Secrets hygiene from day one
- **Decision**: No secrets in repo. `.env` gitignored; `.env.example` committed; keys rotated if ever exposed. No repeat of `elk_stack.txt` pattern.
- **Alternatives**: Continue poor hygiene (rejected).
- **Recommendation**: Secrets via gitignored env.
- **Rationale**: Doc §24; prior security finding from SOC-SOAR review (Priority 1).
- **Trade-offs**: Minimal friction; avoids live-key exposure.
- **Status**: APPROVED
- **Downstream**: Phase 0 scaffolding, config module.

## ADR-011 — LLM backend: llama.cpp server
- **Decision**: Local LLM via llama.cpp server, OpenAI-compatible (`http://localhost:8080/v1` default). Swappable provider interface; one env var to change.
- **Alternatives**: Ollama (rejected); LM Studio (superseded — user switched back to llama.cpp 2026-08-18).
- **Recommendation**: llama.cpp.
- **Rationale**: User decision 2026-08-18. Headless, scriptable, faster on constrained HW (user measures throughput/perplexity), native quant/ternary GGUF control, no GUI overhead. OpenAI-compat keeps `openai` client interface unchanged (ADR-019).
- **Trade-offs**: No GUI eyeballing; slightly more manual config. Negligible — swap cost = `LLM_BASE_URL` + `LLM_PROVIDER`.
- **Status**: APPROVED (supersedes LM Studio choice)
- **Downstream**: `integrations/llm.py`, config (`LLM_BASE_URL`, `LLM_MODEL`).

## ADR-012 — Synthetic telemetry first
- **Decision**: Early phases use a synthetic/corpus-driven event generator into ES. Live Windows VM events deferred.
- **Alternatives**: Live VM events (non-reproducible); both (extra cost).
- **Recommendation**: Synthetic first.
- **Rationale**: Doc §20 reproducible corpus; user locked synthetic-first; deterministic tests.
- **Trade-offs**: Less realism in early demos; VM integration later phase.
- **Status**: APPROVED
- **Downstream**: Phase 1 ingestion, Phase 2 investigation, Phase 9 evaluation corpus.

## ADR-013 — Simulated response executor
- **Decision**: Response tools (isolate/block/kill/disable) execute against a simulated executor (sandbox state), with verifier checking simulated post-state. Real VM backend later.
- **Alternatives**: Real VM target now (dangerous, needs agent, non-repeatable).
- **Recommendation**: Simulated.
- **Rationale**: User locked simulated-first; proves policy→execute→verify architecture safely and repeatably.
- **Trade-offs**: Real-world fidelity deferred; tool contracts designed so backend swap is clean.
- **Status**: APPROVED
- **Downstream**: `tools/executor.py`, `verifier.py`, Phase 5-6.

## ADR-014 — Single operator auth
- **Decision**: No role separation early; single operator. Multi-role (analyst/lead/auditor) at console phase.
- **Alternatives**: RBAC early.
- **Recommendation**: Single operator.
- **Rationale**: User locked single-operator; YAGNI before console exists.
- **Trade-offs**: Approval UX is operator-self-approval early; role gates later.
- **Status**: APPROVED
- **Downstream**: Approval endpoints, Phase 4, Phase 10.

## ADR-015 — Multi-agent reasoning model
- **Decision**: **5 LLM reasoning agents** (Triage, Investigation, Correlation, Threat Analysis, Response Planner) + **2 deterministic services** (Response Executor, Verifier). Handoff via incident store only; no direct agent→agent calls. Per-agent budgets + quotas.
- **Alternatives**: Single reasoning component (E.1, prior recommendation); deterministic-everywhere.
- **Recommendation**: Multi-agent (user requested, overrode E.1).
- **Rationale**: User decision 2026-08-17; multi-agent portfolio narrative. Constrained: LLM agents propose, never act; executor/verifier deterministic per ADR-005/006/009.
- **Trade-offs**: Larger permission surface (E.3 security=3 vs 5); mitigated by deterministic gates at every tool + store-mediated handoff.
- **Status**: APPROVED
- **Downstream**: Agent model Phase C, orchestrator routing, tool permissions, budgets.

## ADR-016 — Deterministic Response + Verification
- **Decision**: Response execution and verification are deterministic services (D1/D2), never LLM agents.
- **Alternatives**: LLM-driven response/verification.
- **Recommendation**: Deterministic.
- **Rationale**: ADR-005/006/009; false-remediation + self-verification risk (D-009/D-010); state-check needs no reasoning.
- **Trade-offs**: None material; only correct option.
- **Status**: APPROVED
- **Downstream**: tools/executor.py, verifier.py, VERIFY state.

## ADR-017 — ES-only storage
- **Decision**: Incident state, audit, evidence all in Elasticsearch (`incidents-*`, `incident-steps-*`, `audit-*`). No SQLite/relational store.
- **Alternatives**: SQLite+ES split; Postgres+ES.
- **Recommendation**: ES-only.
- **Rationale**: User locked ES-only; one store/infra; matches existing telemetry stack; adequate for portfolio scale.
- **Trade-offs**: Weaker transactions than relational; single point of failure. Acceptable for local SOC scale.
- **Status**: APPROVED
- **Downstream**: Phase 1 stores, data model.

## ADR-018 — Custom orchestrator (no agent framework)
- **Decision**: Orchestrator = own in-process state machine + sequential agent pipeline (Phase C design). No LangGraph/CrewAI.
- **Alternatives**: LangGraph; CrewAI; other frameworks.
- **Recommendation**: Custom.
- **Rationale**: User locked custom; Phase C already specifies the flow; frameworks add dependency + abstraction without security value; state machine is deterministic and owned.
- **Trade-offs**: More hand-written routing code; full control + testability.
- **Status**: APPROVED
- **Downstream**: orchestrator module, agent pipeline, budgets.

## ADR-019 — `openai` python client for LLM
- **Decision**: LLM calls via `openai` python lib pointed at LM Studio OpenAI-compat endpoint.
- **Alternatives**: raw httpx; ollama client (rejected, ADR-011).
- **Recommendation**: `openai` lib.
- **Rationale**: User locked; LM Studio is OpenAI-compat; structured-output + retries built in; one dep.
- **Trade-offs**: Library tracks OpenAI API shape; fine for LM Studio.
- **Status**: APPROVED
- **Downstream**: integrations/llm.py, Phase 3.

## ADR-020 — PowerShell execution = first vertical slice
- **Decision**: First scenario = malicious PowerShell execution (doc §27). Proven by all 5 agents + 2 deterministic services.
- **Alternatives**: Password spray; persistence; multi-stage.
- **Recommendation**: PowerShell execution.
- **Rationale**: User locked; richest telemetry path (process spawn → encoded → outbound conn → isolate), exercises every agent + tool class.
- **Trade-offs**: Heaviest slice; best proof of architecture.
- **Status**: APPROVED
- **Downstream**: Phase 1-2 synthetic scenario, Phase 5-6 policy+exec+verify.
