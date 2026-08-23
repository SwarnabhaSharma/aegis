# Aegis Threat Model (spec §15)

AI-assisted SOC automation is itself an attack surface. This document maps
assets, threats, implemented mitigations, and honest residuals. Companion to
[adr.md](adr.md) and [gap-audit.md](gap-audit.md).

## Assets

| Asset | Why it matters |
|---|---|
| Incident state integrity | wrong state = wrong authority for actions |
| Response-action exclusivity | only authorized path may isolate/terminate |
| Evidence fidelity | conclusions must trace to real telemetry |
| Credentials in `.env` / ES | platform and cluster compromise |
| Telemetry confidentiality | PII/secrets inside logs |
| Audit trail completeness | reconstruction + non-repudiation |

## Trust boundaries

1. **Telemetry → LLM**: all event content is attacker-influencable data.
2. **LLM output → system**: model JSON is never trusted as instruction or action.
3. **Tools → world**: registry is the single authorization gate.
4. **Operator → controls**: emergency switches bypass the LLM entirely.

## Threats → mitigations

| # | Threat | Mitigation (status) |
|---|---|---|
| 1 | Prompt injection via telemetry ("IGNORE PREVIOUS INSTRUCTIONS…") | **Built** — untrusted_data wrapping with angle-bracket escaping; system-prompt data-not-instructions rule; heuristic pattern detector → audit (`bb18bd2`) |
| 2 | Indirect injection (TI content, filenames, API responses) | **Partial** — same wrapping covers tool-result paths; corpus measurement pending broader scenarios |
| 3 | Tool abuse — agent calls unauthorized tool | **Built** — registry allowlist per agent; response tools exclusive to D1; revocable at runtime (`81a600f`) |
| 4 | Privilege escalation — agent gains permissions | **Built** — static immutable permission sets; agents cannot request scope change |
| 5 | Data exfiltration — agent reads unrelated sensitive data | **Partial** — read scope bounded by registered tools; privacy redaction masks secrets/PII before AI views (`318f3e1`); task-based minimization not yet built |
| 6 | Malicious external threat intelligence | **Deferred** — TI is a local static store; re-threat-model before adding any live feed |
| 7 | Agent loops (agents calling agents) | **Built** — no agent→agent calls; store-mediated handoff only |
| 8 | Excessive tool calls | **Built** — real per-incident budget + per-agent step budget; exceed → degrade → escalate |
| 9 | Hallucinated evidence — invented evidence_ids | **Built** — post-pipeline validation strips fabricated refs, flags to audit (`bb18bd2`); measured: local 9B fabricates routinely, defense fires every run |
| 10 | False remediation — claims success that didn't happen | **Built** — D2 verifies actual state independently; HTTP-200-style success never trusted |
| 11 | Verification manipulation — agent influences its own verification | **Built** — D2 is a separate deterministic service reading executor state; no LLM involvement |
| 12 | Runaway autonomy | **Built** — emergency controls: pause, safe mode, agent disable, require-approval-all; LLM-independent (`81a600f`) |

## Residual risks (honest)

- **Model misjudgment within valid JSON**: a confidently-wrong-but-parseable
  classification still drives the flow. Mitigated by policy gates on any
  consequential action + human approval path; not eliminable at this layer.
  Measured via eval corpus rather than assumed away.
- **Injection detector is heuristic**: known-pattern list; novel phrasings may
  pass wrapping undefended (wrapping itself remains the primary control).
  Extend patterns from eval findings.
- **Audit tamper-protection absent**: audit records are append-only by
  convention, not cryptographically chained. Planned layer.
- **Simulated backends**: executor state is in-memory; real EDR integration
  re-opens §16 review before production use (ADR-013).
- **Single-operator assumption** (ADR-014): role-based privacy views and
  multi-operator authZ are unbuilt.

## Review cadence

Re-run `scripts/run_eval.py` after any prompt/model/policy change; update this
document when threats move between residual/mitigated columns.
