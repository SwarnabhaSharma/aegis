# Aegis — Phase E: Risks, Open Questions, Final Review

Per doc §31-E. Covers P (risks/open questions) and Q (architectural review). Precedes the consolidated architecture document.

---

## P. Risks and Open Questions

### P.1 Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R-001 | LLM (LM Studio local, quantized/ternary) unreliable at strict JSON output | HIGH | Agent pipeline failures, malformed conclusions | Structured-output attempt + parse fallback + retry-once + deterministic degrade (fail-safe, no autonomous action) |
| R-002 | Prompt injection via telemetry bypasses reasoning agents | MEDIUM | Wrong investigation/triage | Telemetry always wrapped as data; injection attempts logged; agents never auto-act (ADR-005) |
| R-003 | Multi-agent permission sprawl (5 agents × tools) | MEDIUM | Unauthorized tool use | Immutable per-agent permission table; tool registry allowlist; policy gate; audit every call (D-003/004) |
| R-004 | Synthetic corpus under-represents real telemetry | MEDIUM | Slice works in sim, fails live | Synthetic-first (ADR-012) then live VM pass at later phase; corpus documented as simulation |
| R-005 | ES-only store: weak transactions / consistency | LOW-MEDIUM | Duplicate state transitions | Single-writer per incident; idempotent transitions; version field |
| R-006 | Agent loops / budget exhaustion | LOW | Resource drain, runaway | Step + tool-call + time budgets; hard stop → ESCALATED (D-006/007) |
| R-007 | Scope creep toward "impressive" features (RAG, event bus, complex UI) | MEDIUM | Delays core | ADR-007/008; YAGNI enforced; roadmap gates |
| R-008 | Local LLM offline / wrong model loaded | MEDIUM | No reasoning | Deterministic fallback path; no autonomous actions; operator notified |
| R-009 | Verifier and executor coupled in code | LOW | Self-verification | Separate modules, separate contracts; verifier read-only, deterministic (ADR-016) |

### P.2 Open questions (non-blocking)

| # | Question | When resolved |
|---|---|---|
| OQ-001 | Exact LM Studio model tag to pin | Phase 3 (user's model roster) |
| OQ-002 | Live Windows VM integration timing | Post-Phase 7 (ADR-012 revisit) |
| OQ-003 | Repo push to GitHub + CI activation | When user pushes (A-018) |
| OQ-004 | Multi-role auth (analyst/lead/auditor) details | Phase 10 console (ADR-014) |
| OQ-005 | Privacy enforcement depth | Phase 8 (ADR-003) |

---

## Q. Architectural Review

### Q.1 Core principles verified against design

| Principle (doc) | Status | Evidence |
|---|---|---|
| AI is reasoning, not authority (§3.2) | ✅ | ADR-005; agents propose, deterministic controls decide |
| Deterministic controls own policy/auth/exec/verify (§3.3) | ✅ | ADR-006/016; policy engine, executor, verifier deterministic |
| Minimum data + authority (§3.1) | ✅ | Per-agent tool/perm table; view layer (privacy) reserved |
| Evidence integrity (§3.4) | ✅ | Evidence model w/ provenance; conclusions require evidence_ids (D-008) |
| Fail-safe operation (§3.5) | ✅ | Uncertainty ladder; budgets; timeouts→ESCALATED; LLM-down fallback |
| RAG not core (§5) | ✅ | ADR-007; structured playbooks/policies first |
| Explicit lifecycle (§6) | ✅ | State machine with transition authority (Phase C K) |
| Fewer agents safer (§7) | ⚠️ | 5 reasoning agents (user choice, ADR-015) but handoff via store + budgets contain risk |
| Controlled tools (§8) | ✅ | Tool registry, typed schemas, risk classes, idempotency |
| Privacy first-class (§10) | ⏸️ | Deferred per ADR-003; schema reserved |
| Adversarial security (§15) | ✅ | Threat model D.1-D.4 + 12 scenarios with defenses |
| Success needs verification (§16) | ✅ | ADR-009/016; VERIFY state mandatory |
| Human override (§17) | ✅ | Emergency controls table, operator-only, LLM-independent |
| Auditability (§18) | ✅ | audit-* index; every transition/tool/policy/approval logged |
| Reproducibility (§21) | ✅ | Versioned policies, model/prompt pinning, corpus |
| Simplest architecture (§22/23) | ✅ | Modular monolith + custom orchestrator; ES-only; 9 runtime deps |

### Q.2 Design review verdict

The design satisfies the doc's core requirement: **a coherent, secure, explainable, extensible, auditable autonomous security operations platform** — with the documented exception that multi-agent (ADR-015, user-directed) trades some of the single-agent safety margin, fully mitigated by deterministic gates at every boundary.

### Q.3 What would change this architecture

- Requirement for real concurrent SOC-scale throughput → event-driven orchestration (E.2)
- Strong relational integrity needs → add SQLite/relational layer for state (ADR-017 revision)
- Need for independently deployable investigators → true agent runtime (E.3 revision)
- Privacy becomes a headline feature → pull Phase 8 forward

---

**Consolidated architecture document follows (separate file). Build starts at Phase 0 after review.**