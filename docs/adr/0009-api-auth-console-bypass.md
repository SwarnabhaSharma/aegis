# ADR-009 — API Key Auth with Console Bypass

- **Decision**: API key authentication via middleware. Console UI pages (HTML) bypass auth. API endpoints require key when `AEGIS_API_KEY` is set.

- **Alternatives**:
  - No auth (local dev only)
  - OAuth2/JWT for all endpoints
  - Session-based auth for console, API key for API

- **Recommendation**: API key middleware with explicit console bypass paths.

- **Rationale**: Security model from spec §17:
  - API key protects programmatic access (curl, scripts, integrations)
  - Console UI is for human operators on localhost — auth would block the UX
  - Dev mode (`aegis_env == "dev"` + empty key) disables auth entirely
  - Prod mode requires a key — fail closed

- **Trade-offs**:
  - Console pages are unauthenticated when accessed locally (acceptable for portfolio)
  - API key is static (no rotation) — acceptable for single-user deployment
  - Gains: simple, correct security posture, no session management

- **Status**: APPROVED

- **Downstream**:
  - Middleware: `api.py` correlation + auth middleware
  - Bypass paths: `/`, `/console/*`, `/incidents/*/console*`, `/docs`, `/health`, `/ready`
  - Env: `AEGIS_API_KEY` (empty = disabled in dev)
