# Aegis — Assumptions Log

Format: ID / assumption / reason / confidence / impact-if-wrong / needs-validation / status

Status: OPEN | VALIDATED | REJECTED | SUPERSEDED

---

| ID | Assumption | Reason | Confidence | Impact if wrong | Needs validation | Status |
|---|---|---|---|---|---|---|
| A-001 | Greenfield project; no code reuse from SOC-SOAR / incident-remediation V1 | User decision | HIGH | Wasted prior planning effort only | none | VALIDATED |
| A-002 | Live gated architecture sessions per doc §31 | User decision | HIGH | Process mismatch | none | VALIDATED |
| A-003 | Full platform vision, not first-vertical-slice-first | User decision | HIGH | Delayed end-to-end demo | none | VALIDATED |
| A-004 | Privacy layer deferred to later phase | User decision | HIGH | Privacy not in early build | none | VALIDATED |
| A-005 | Deployment: AI backend + Ollama on laptop, ES+Kibana on Ubuntu VM **192.168.56.105** (corrected from .104), Windows VM as telemetry/attack source | Prior session verified connectivity | HIGH | Rewiring infra | Re-verify at Phase 1 | VALIDATED |
| A-006 | Elasticsearch remains the backing store | Prior V1 plan; existing validated stack | MEDIUM | Store choice re-derived at Phase D | Phase D | OPEN |
| A-007 | Python as primary runtime | Prior pattern, local LLM ecosystem | MEDIUM | Language re-derived at Phase D | Phase D | OPEN |
| A-008 | Local LLM via **llama.cpp** server (OpenAI-compat `http://localhost:8080/v1`), swappable provider interface, used in ≤2 places (hypothesis summary, recommend-actions) | User decision 2026-08-18 (LM Studio superseded) | MEDIUM | Base URL swap only; interface unchanged | Phase D | VALIDATED |
| A-009 | Single reasoning agent + deterministic executors is safer than 7 agents | Doc §7 bias toward fewer agents; prior V1 rejected multi-agent | MEDIUM | Agent model re-examined at Phase C | Phase C | OPEN |
| A-010 | Modular monolith, no microservices / event bus initially | Doc §24; prior V1 | MEDIUM | Re-evaluated at Phase B (architecture alternatives) | Phase B | OPEN |
| A-011 | AI must never bypass authorization/policy/approval; deterministic controls retain authority | Doc §3 core principle | HIGH | Violation = critical flaw | Every phase | OPEN |
| A-012 | RAG is not core; structured knowledge (YAML/JSON playbooks, ATT&CK, policies) first | Doc §5 | HIGH | RAG never added unless demonstrated need | Phase 7/8 | OPEN |
| A-013 | Response success = independent verification, not HTTP 200 | Doc §16 | HIGH | False closure claims | Phase 6 | OPEN |
| A-014 | Telemetry for early phases is synthetic/corpus-driven for reproducibility; live Windows VM events later | Doc §20 requires reproducible corpus; user locked synthetic-first | MEDIUM | Test harness design | Phase 1-2 | VALIDATED |
| A-016 | Response executor is simulated (sandbox state) for early phases; real VM backend later | User locked simulated-first; greenfield safety | MEDIUM | Executor/verifier contract | Phase 5 | VALIDATED |
| A-017 | Single operator auth (no role separation) for early phases; multi-role at console phase | User locked single-operator; less code | MEDIUM | Approval UX design | Phase 10 | VALIDATED |
| A-018 | Dev tooling: pytest + ruff, no CI until repo pushed | User locked defaults | HIGH | Minor | Phase 0 | VALIDATED |
| A-019 | Incident state + audit live in ES only (incidents-* + incident-steps-* indices), no SQLite/relational store | User locked ES-only | MEDIUM | Store migration | Phase 1 | VALIDATED |
| A-020 | Agent pipeline via custom orchestrator (own state machine), no LangGraph/CrewAI | User locked custom | MEDIUM | Re-scaffold | Phase 3 | VALIDATED |
| A-021 | LLM client via `openai` python lib against LM Studio OpenAI-compat | User locked | HIGH | Client swap only | Phase 3 | VALIDATED |
| A-022 | First vertical slice = PowerShell execution incident type | User locked (doc §27 candidate) | HIGH | Slice choice | Phase 1 | VALIDATED |
| A-015 | UI is API/CLI-first early; full security console late phase | Doc §28; prior V1 REST-approval-first | MEDIUM | UI scope | Phase 9-10 | OPEN |
