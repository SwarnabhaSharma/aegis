# Aegis — Definition of Done

Each phase requires all criteria before exiting. A feature is not done because a happy-path demo works (doc §26).

## Global requirements (every phase)

- Expected functionality works
- Relevant error cases handled
- Unauthorized behavior is rejected
- Audit events are generated
- Security controls tested
- Relevant automated tests pass
- Failures produce safe outcomes
- Documentation updated

## Phase gates

### Phase 0 — Foundations (repo, config, governance)
- **Prerequisites**: ADR-001..010 logged; assumptions logged
- **Deliverables**: repo scaffold, `.gitignore`, `.env.example`, config loader, structured logging, module skeleton, test harness (pytest), CI-ready lint
- **Functional acceptance**: app boots with no secrets in repo; config validated; logging works
- **Security acceptance**: no secrets committed; config rejects unknown/malformed keys; no default credentials
- **Tests**: config loader tests, logging smoke test
- **Exit**: green test run, clean `git status`

### Phase 1 — Core incident engine
- **Prerequisites**: Phase 0, architecture Phase B/C approvals (state machine, data model)
- **Deliverables**: incident lifecycle, alert ingestion, explicit state machine, store, valid transitions + authority
- **Functional acceptance**: alert → NEW → TRIAGING → ... → RESOLVED; invalid transitions rejected; timeouts enforced; concurrency safe
- **Security acceptance**: state mutation requires authorized actor; LLM cannot arbitrarily mutate state; audit on every transition
- **Tests**: transition table tests, timeout tests, concurrency/idempotency tests, unauthorized-transition rejection
- **Exit**: synthetic alert end-to-end through full happy path + failure path

### Phase 2 — Investigation (read tools + evidence)
- **Prerequisites**: Phase 1, tool model approved (Phase C)
- **Deliverables**: tool registry, read tools (typed I/O schemas), evidence collection, timeline building, evidence model w/ provenance
- **Functional acceptance**: tools return typed results; evidence linked to source + timestamp; timeline reconstructable
- **Security acceptance**: read-only tools cannot mutate; field-level view respected (per A-003 privacy stance); tool calls audited; prompt injection in telemetry treated as data
- **Tests**: tool schema validation, evidence provenance, injection-string handling
- **Exit**: one investigation workflow completes against synthetic events

### Phase 3 — AI reasoning
- **Prerequisites**: Phase 2, LLM interface + placement approved
- **Deliverables**: swappable LLM provider, hypothesis generation/summarization, evidence-driven conclusions, confidence scoring, deterministic fallback
- **Functional acceptance**: AI output linked to evidence; fallback path when model down; structured JSON with parse fallback
- **Security acceptance**: LLM output treated as untrusted; no tool access beyond read tools; injection attempts logged; no fabricated evidence accepted
- **Tests**: fallback tests, output-schema validation, unsupported-conclusion rejection
- **Exit**: triage + investigation reasoning against corpus w/ no hallucinated evidence

### Phase 4 — Policy & authorization
- **Prerequisites**: Phase 3, policy model approved
- **Deliverables**: deterministic policy engine, policy versioning, approval flow, action risk classification, dry-run mode
- **Functional acceptance**: policy eval is deterministic; approve/deny per policy; human approval gates high-risk; dry-run simulates without executing
- **Security acceptance**: policy cannot be bypassed by LLM; policy decisions audited w/ version; denied actions logged w/ reason
- **Tests**: policy unit tests, precedence/conflict tests, bypass-attempt tests
- **Exit**: action recommendation → policy → (auto|approve|deny) verified against test suite

### Phase 5 — Response execution
- **Prerequisites**: Phase 4
- **Deliverables**: response tools (isolate/disable/terminate/block), executor w/ idempotency + timeout + retry, rollback where possible
- **Functional acceptance**: authorized actions execute; idempotent re-run; timeout → safe failure; rollback path exercised
- **Security acceptance**: only policy-approved actions execute; executor never executes unauthorized request; audit every action
- **Tests**: executor idempotency, timeout, rollback, unauthorized-action rejection
- **Exit**: full authorize→execute loop on one response action

### Phase 6 — Verification & resolution
- **Prerequisites**: Phase 5
- **Deliverables**: independent verification tools, reopen/escalate logic, resolution conditions
- **Functional acceptance**: verify confirms expected result; on failure → REOPEN/ESCALATE; verification result recorded
- **Security acceptance**: verification independent of executor; no self-verification; audit
- **Tests**: verify-true, verify-false→reopen, escalation
- **Exit**: full incident loop (alert→resolve + alert→reopen) end-to-end

### Phase 7 — Correlation & intelligence
- **Prerequisites**: Phase 6
- **Deliverables**: multi-alert correlation, attack-chain linking, ATT&CK mapping, optional TI enrichment
- **Functional acceptance**: correlated incident shows linked events + chain; ATT&CK mapping justified
- **Security acceptance**: external TI treated as untrusted; correlation cannot fabricate links
- **Tests**: correlation cases, chain construction, poisoning input handling
- **Exit**: multi-stage attack scenario correlated correctly

### Phase 8 — Privacy (deferred per ADR-003)
- **Deliverables**: PII/secret detection, redaction, field-level access, AI-visible vs analyst-visible, privacy audit trail
- **Functional/security acceptance**: field requests/releases/withholds auditable; "why withheld" answerable
- **Tests**: redaction, classification, access-control tests

### Phase 9 — Evaluation
- **Prerequisites**: Phase 7 (or after Privacy per schedule)
- **Deliverables**: reproducible test corpus (TP/FP/ambiguous/benign/multi-stage/incomplete/injection/unauthorized/failed-verify/contradictory), metrics harness (precision/recall/FPR, hallucination rate, policy-violation rate, exfiltration attempts, remediation success, verification accuracy)
- **Functional acceptance**: corpus reproducible; metrics computed by script; no fabricated numbers
- **Security acceptance**: adversarial cases (injection, exfil, false-remediation) included
- **Tests**: metric-correctness tests
- **Exit**: full evaluation report on corpus

### Phase 10 — Production polish
- **Prerequisites**: Phase 9
- **Deliverables**: security operations console (incident queue, detail, timeline, evidence, privacy view, agent activity, response, audit replay), docs, architecture diagrams, threat model, deployment guide, setup instructions
- **Functional acceptance**: console views per doc §28; audit replay works
- **Security acceptance**: console auth; audit protected from tampering
- **Tests**: UI smoke tests
- **Exit**: portfolio-ready — docs, diagrams, threat model, reproducible eval, demo scenarios, stated limitations
