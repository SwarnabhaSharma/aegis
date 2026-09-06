# AEGIS UI Plan — inspect-before-build reports (approved 2026-09-06)

Transcribed from session review. Reference images give vision; backend stays
source of truth; no fake data to match pictures.

## A. Capability mapping

| UI Concept | Real support | Data/API source | Status | MVP | Decision |
|---|---|---|---|---|---|
| Overview Dashboard | `/dashboard` + `/api/dashboard/stats` counters | store scan + Counter | Partial | Yes | Extend + restyle, no fake 98%/102% |
| Incident Queue | `GET /incidents?state=&severity=`, plain table | store.get | Partial | Yes | Search/sort/page, Title/Asset/Status columns |
| Incident Detail | `/incidents/{id}/console` KV + tables + tabs | timeline/evidence/records | Partial | Yes | Unify + phase stepper + merged replay |
| Investigation Workspace (ad-hoc KQL + AI chat) | agent tools only, no user endpoint | tools registry | Missing | No | Defer; read-only evidence for MVP |
| Agent Activity (global live) | per-incident agentrun/toolcall, no aggregation | store records | Partial | Yes | New `GET /api/agents/activity`, no CoT |
| Response & Approval | policy ALLOW/APPROVE/DENY + approve/deny/override, simulated exec (ADR-013) | policies engine, slice | Partial | Yes | 6-step chain on backend decisions |
| Attack Chain | typed edges + `/graph` + vis-network page | intel/graph.py | Partial | Min | Keep graph; linear kill strip deferred |
| Privacy & Data Access | gateway redact/classify/vault + analyst-view/reveal | privacy gateway, audit | Ready- | Yes | Access-log table from evidence |
| Audit Replay | hash chain + timeline/transitions/records | audit.py, store | Partial | Yes | Merged replay table; animation deferred |
| TI view | TIChain STIX 697 + providers, no page | intel/ | Partial | No | Overview widget only |
| Assets | Asset records + host tool, no page | entities.py | Partial | No | Host string in queue/detail |
| Settings & Integrations | controls + elastic status/poll, no matrix | controls.py, adapter | Partial | No | Keep Controls/Operations; matrix would be fake |
| Global Search | none | — | Missing | No | Queue filter covers MVP |
| Reports | none | — | Missing | No | Defer |

## B. MVP scope

Shell + design tokens → Overview (real counts) → Queue (search/sort/page) →
Detail (stepper + replay) → Agent feed → Response chain → Privacy log →
Audit filters → demo scenario. Deferred: KQL/AI-chat, kill strip, TI/Assets/
Reports/Settings pages, global search, animated replay, fake metrics.

## C. Information architecture

```text
Overview (/dashboard)
Incidents (/ queue, /incidents/{id}/console detail)
Agent Activity (/console/agents)
Response (per-incident tab)
Operations (/console/operations: loop + approvals)
Audit (/console/audit global + per-incident replay)
Privacy (per-incident tab)
Controls (/console/controls; full Settings deferred)
```

No dead top-level pages for backends that do not exist.

## D. Gaps

Required (additive, done in Phases 2-7): `GET /api/overview`,
queue q/sort/page on API + console, `GET /incidents/{id}/replay`,
`GET /api/agents/activity`, record timestamps + data fields (P3a).
Recommended (later): `POST /incidents/{id}/query` over existing tools,
tactic→stage mapping for kill strip.
Deferred: saved queries, AI chat, global search, reports export, real EDR
swap (ADR-013), integration health probes.

## Phase order (as executed)

0 inspect + these reports → 1 shell/tokens → 2 overview → 3 queue →
4 detail/replay → 5 agents → 6 response → 7 privacy/audit → 8 demo.
Post-MVP: P0 XSS, P1 queue dedup, P2 console auth, P3a stamps, P4 docs.
