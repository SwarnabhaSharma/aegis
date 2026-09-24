# ADR-023 — Console UI Architecture

- **Decision**: Use Jinja2 server-rendered templates with custom dark CSS for the console UI. No frontend framework, no build step, no npm.

- **Alternatives**:
  - React/Vue SPA with WebSocket updates
  - HTMX for dynamic updates without full page reloads
  - Static HTML with vanilla JavaScript

- **Recommendation**: Jinja2 server-rendered. Simplest path, zero build step, works immediately.

- **Rationale**: Portfolio piece. The UI needs to demonstrate the platform works, not showcase frontend skills. Server-rendered templates:
  - No build step — `uvicorn` is the only command
  - No npm/node dependency — Python-only project
  - Dark CSS theme already consistent across 10 templates
  - Auto-refresh via vanilla JS polling (operations page)

- **Trade-offs**:
  - Full page reloads on navigation (acceptable for portfolio)
  - No real-time WebSocket updates (solved via JS polling on operations page)
  - Less interactive than SPA (solved via form submissions with redirects)
  - Gains: simple, maintainable, zero frontend tooling

- **Status**: APPROVED

- **Downstream**:
  - Templates: `templates/*.html` (10 templates)
  - CSS: `static/console.css` (dark theme, stats grid, severity bars)
  - JS: inline `<script>` for auto-refresh on operations page
  - Auth: console pages skip API key auth (see ADR-024)
