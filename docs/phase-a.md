# Aegis — Phase A: Product & Problem Definition

Session 0 deliverable. Per doc §33, covers Problem Definition, Product Definition, Autonomy Model, then stops for review. Architecture (Phase B) NOT started.

---

## A. Problem Definition

### The actual security problem

Modern SOCs produce large volumes of telemetry (SIEM, EDR, Sysmon, auth, firewall, network, TI, endpoints). Analysts are buried in alerts and must: triage, collect evidence, correlate, judge maliciousness, gauge severity/confidence, decide response, execute, verify, and document. Most of this is repetitive, time-bound, and error-prone under pressure.

Two failure modes exist today:
1. **No automation** → alert fatigue, slow containment, inconsistent documentation, missed escalation.
2. **Unrestrained automation** → an untrusted LLM handed shell/DB/infra access, leading to unauthorized actions, hallucinated conclusions, prompt injection, exfiltration, false "success" claims.

The problem Aegis solves: **how to automate the full incident lifecycle — detect→triage→investigate→correlate→assess→plan→authorize→respond→verify→resolve — such that AI adds reasoning value while deterministic controls retain authority over data, policy, authorization, execution, and verification.**

### Target users

| Persona | Role | Need |
|---|---|---|
| SOC analyst (L1/L2) | Triage, investigation, response | Offload repetitive triage/evidence gathering; trustworthy recommendations; clear evidence trails |
| SOC lead / incident commander | Approval, escalation, oversight | Deterministic guardrails; visible audit; emergency controls |
| Detection/infra engineer | Maintains rules, tools, policies | Versioned, testable policies/tools; dry-run |
| Auditor / reviewer | Post-incident review | Complete replay of what AI saw, requested, did, and why |
| Portfolio evaluator (this project) | Assesses engineering depth | Reproducible evaluation, threat model, honest docs |

### Existing SOC workflow (target baseline)

```
Detect → Triage → Investigate → Correlate → Assess → Plan → Approve → Execute → Verify → Document/Close
```

Pain points in that workflow:
- Triage is high-volume, low-judgment, and consumes analyst hours
- Evidence collection is manual and repetitive (same queries per incident type)
- Correlation across sources/timelines is manual
- Response is high-stakes; analysts fear making it worse → slow containment
- Verification is often skipped → false closure
- Documentation is incomplete and non-reproducible

### Where automation genuinely helps (and where it must not be trusted)

**Helps (AI appropriate):**
- Alert triage classification and de-prioritization
- Evidence collection orchestration (approved read tools)
- Timeline construction and event correlation
- Hypothesis generation and investigation planning
- Natural-language reasoning across heterogeneous evidence
- Response recommendation with rationale
- Summarization for analyst review

**Must NOT be trusted to decide (deterministic controls own these):**
- Whether data is exposed or what the agent may see (authorization)
- Whether an action is permitted (policy)
- Whether an action may execute (approval)
- Whether remediation actually worked (verification)
- Final severity/confidence for high-risk outcomes without evidence linkage

### System boundaries

**In scope:** alert ingestion, incident lifecycle, read/investigation tools, correlation, evidence model, policy engine, approval, controlled response tools, verification, audit, evaluation harness, (later) privacy layer.

**Out of scope / explicit non-problems:**
- Building a SIEM (ingest/index raw telemetry at scale) — Aegis reads from the telemetry store
- Full SOAR playbook library — playbooks are structured knowledge, authored incrementally
- General AI assistant / RAG chatbot — RAG is not core (doc §5)
- LLM with unrestricted shell/database/infrastructure access — forbidden by design
- Cloud-scale microservices — modular monolith first (doc §24)
- Replacing human judgment for high-risk or ambiguous decisions

---

## B. Product Definition

### Core capabilities (V1 target)

1. **Incident lifecycle engine** — explicit state machine with valid transitions, authority, timeouts, concurrency, idempotency
2. **Alert ingestion** — accept alerts from detection sources → incident
3. **Investigation** — approved read tools gather evidence; timeline construction
4. **Correlation** — connect events, build attack chains, identify affected assets
5. **Assessment** — evidence-linked severity/confidence (never bare "model thinks so")
6. **Response planning** — AI proposes actions with rationale, risks, expected outcomes
7. **Policy engine** — deterministic, versioned, testable; auto/approve/deny
8. **Controlled execution** — response tools with risk class, idempotency, timeout, rollback
9. **Independent verification** — confirm expected result; reopen/escalate on failure
10. **Audit** — complete replay: data requested/released/withheld, tool requests, auth decisions, policy versions, actions, verification
11. **Emergency controls** — pause/disable agents-tools, require approval, safe mode
12. **Evaluation** — reproducible corpus + metrics

### Non-goals (explicit)

- RAG-first knowledge retrieval (structured knowledge first)
- Multi-agent architecture without demonstrated need
- Broad MITRE coverage in V1 (justified mappings only)
- Cloud-native distribution
- Full privacy gateway (deferred per ADR-003)

### Personas → workflows

| Workflow | Actors | Primary path |
|---|---|---|
| Triage a new incident | Analyst | Alert → triage summary → decide investigate/dismiss |
| Investigate | Analyst | Read tools → evidence → timeline → hypothesis |
| Approve response | Lead | Recommendation → policy decision → approve/deny |
| Emergency stop | Lead | Safe mode / disable agent-tool globally |
| Post-incident review | Auditor | Audit replay of full incident |

### What makes Aegis different

- **vs conventional SIEM/SOAR**: Aegis adds AI reasoning (triage, investigation planning, hypothesis generation, correlation, recommendation) on top of deterministic lifecycle — not just hardcoded playbook branches.
- **vs generic AI SOC assistant**: Aegis is a platform with real authority separation — the LLM cannot act, only propose; deterministic controls execute, and verification is independent. Not a chatbot wrapper.
- **The unifying differentiator**: **every AI conclusion is linked to evidence, and every action is gated by deterministic policy + approval + independent verification.**

---

## C. Autonomy Model

The core question: what may the AI decide, request, and execute without human input?

### Autonomy buckets

| Bucket | Definition | Examples | Control |
|---|---|---|---|
| **1. Fully autonomous** | Low-risk, reversible, explicitly permitted | Read-tool evidence collection, correlation, triage classification, hypothesis generation | AI may execute directly; deterministic allowlist of read tools; audit |
| **2. Policy-authorized** | Meets predefined deterministic conditions | Non-critical host isolation at confidence ≥ threshold, with ≥ N evidence | Policy engine evaluates; auto-approve if conditions met; audit |
| **3. Human-approved** | High-risk, irreversible, sensitive, ambiguous | Critical-asset isolation, account disable, persistence removal, escalation | Policy proposes; human approval required; audit |
| **4. Forbidden** | Never automatic, ever | Privilege escalation, policy bypass, unrestricted data access, arbitrary shell, self-authorization, declaring success without verification | Hard-denied by design; attempted → audit + alert |

### Decision authority by concern

| Concern | Owned by |
|---|---|
| What the model believes/infers | AI (hypotheses, labeled as such) |
| What was actually observed | Evidence store (provenance, source, timestamp) |
| What is permitted | Policy engine (deterministic, versioned) |
| Whether this actor may act | Authorization layer (agent/user/asset/context) |
| Whether the operation happened | Tool execution + independent verification |
| Record of everything | Audit store (tamper-resistant) |

### Uncertainty behavior (fail-safe)

When the system is uncertain — missing telemetry, model/tool/policy failure, contradictory evidence, low confidence — it must:
1. Gather additional evidence (if safe + useful)
2. Reduce scope/privileges
3. Request human approval
4. Safely escalate
5. **Stop**

No security-critical action depends solely on LLM availability, correctness, or confidence. If the LLM is down → deterministic fallback path, no autonomous actions.

### LLM authority boundary (doc §3.2)

**May:** interpret telemetry, form hypotheses, correlate evidence, request approved evidence, recommend actions, request approved tools.
**May NOT:** authorize itself, grant permissions, bypass policy, access unrestricted data, execute arbitrary commands, modify infra directly, declare success without verification, arbitrarily alter security-critical state.

---

## End of Phase A — Current understanding, assumptions, ambiguities

### Current understanding of Aegis

A greenfield, portfolio-scale security operations platform that runs the full incident lifecycle with a strict split: **AI reasons, deterministic controls govern.** The LLM is a reasoning component confined to investigation/triage/correlation/planning; policy, authorization, execution, and verification are deterministic and auditable. Autonomy is tiered (auto → policy → human → forbidden) and fail-safe. Structured knowledge first; RAG only if a demonstrated need appears. Privacy is a later-phase component. Built as a modular monolith in Python against an Elasticsearch store, local LLM via Ollama, phased A→G-style gates.

### Key assumptions (full log in `assumptions.md`)

- A-005/006/007/008: topology, ES store, Python, local LLM — carry from prior sessions, re-validated at Phase D
- A-009: single reasoning agent + deterministic executors safer than 7 agents
- A-010: modular monolith
- A-012: no RAG initially
- A-013: verification required for success
- A-014: synthetic telemetry for early phases (reproducible corpus), live optional

### Important ambiguities (open, need input)

1. **A-014 / telemetry sourcing**: real Windows VM events (live, non-reproducible) vs. synthetic ES corpus (reproducible per doc §20). Affects Phase 1–2 design.
2. **Response tool backend**: since greenfield — do response tools (isolate/block/kill) target the real Windows VM agent, a simulated executor (record-only), or both? Verification needs something to verify against.
3. **Auth model**: single-operator local tool vs. multi-role auth (analyst/lead/auditor) — affects console + approval UX scope.
4. **Corpus volume**: how large a reproducible corpus is acceptable for a portfolio project (doc §20 wants TP/FP/ambiguous/benign/multi-stage/injection/unauthorized/verification-fail).

### Initial architectural implications

- State machine must be explicit + authority-aware, not LLM-driven
- Tools must be typed contracts w/ risk class + idempotency + audit
- Evidence model w/ provenance needed before Phase 3 AI reasoning
- Policy engine deterministic + versioned + testable (dry-run)
- Executor and verifier strictly separated (no self-verification)
- Versioning (model/prompt/policy/tool-schema/rule) from Phase 0
- Secrets hygiene from day one (ADR-010)

### Most important questions for me (input needed before Phase B)

1. Telemetry: synthetic corpus first, live VM later? (recommended: yes)
2. Response actions: simulated executor with verify-for-simulation, or real Windows VM target?
3. Auth/role model: single operator (simplest) vs. multi-role?
4. LLM model tag for Ollama — exact quantized model to pin? (prior sessions left this open)
5. Repo tooling preferences: any constraint on test framework, lint, CI?

**Gate: awaiting review before proceeding to Phase B (threat model + architecture alternatives).**

### Gate decisions (locked 2026-08-17)

| Question | Decision |
|---|---|
| 1. Telemetry | **Synthetic corpus first** (ADR-012); live VM later |
| 2. Response actions | **Simulated executor** + verify-for-simulation (ADR-013); real VM backend later |
| 3. Auth | **Single operator** early; multi-role at console phase (ADR-014) |
| 4. LLM backend | **LM Studio** OpenAI-compat `http://localhost:1234/v1` (ADR-011); ollama rejected |
| 5. Tooling | **pytest + ruff**, no CI until repo pushed (A-018) |
