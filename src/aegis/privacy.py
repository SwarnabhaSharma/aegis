"""Minimal privacy layer (debt #10/T3, spec §10). Detection -> classification
-> redaction before AI-visible views; decisions logged via audit.

V1 scope (ponytail): regex detectors + uniform text redaction for agent views
+ dict-field allowlist. Full gateway (tokenization, role-based views, four
representations) stays deferred per ADR-003 sequencing.
"""

import re

# ponytail: curated patterns, extend when eval corpus shows misses
_PATTERNS: dict[str, str] = {
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "credential": r"(?i)\b(password|passwd|pwd|api[_-]?key|apikey|secret|token"
                  r"|authorization)\s*[:=]\s*\S{4,}",
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
}

_COMPILED = {k: re.compile(v) for k, v in _PATTERNS.items()}

# kind -> classification level (higher wins)
_LEVELS = {"credential": "secret", "aws_access_key": "secret", "jwt": "secret",
           "private_key": "secret", "ssn": "secret", "email": "pii"}
_ORDER = ["normal", "pii", "secret"]


def detect(text: str) -> list[str]:
    """Kinds of sensitive data found in text."""
    if not text:
        return []
    return [kind for kind, rx in _COMPILED.items() if rx.search(text)]


def redact(text: str) -> tuple[str, list[str]]:
    """Mask detected spans as [REDACTED:<kind>]. Returns (masked, kinds)."""
    if not text:
        return text, []
    kinds: list[str] = []
    masked = str(text)
    for kind, rx in _COMPILED.items():
        if rx.search(masked):
            kinds.append(kind)
            masked = rx.sub(f"[REDACTED:{kind}]", masked)
    return masked, sorted(set(kinds))


def classification_level(kinds: list[str]) -> str:
    level = "normal"
    for k in kinds:
        lvl = _LEVELS.get(k, "pii")
        if _ORDER.index(lvl) > _ORDER.index(level):
            level = lvl
    return level


# §10 AI-visible view: dict outputs filtered to allowlisted keys per tool.
# Analyst-facing reads keep full dicts; only the LLM observation path filters.
AI_VISIBLE_FIELDS: dict[str, set[str]] = {
    "get_host_details": {"host", "seen", "event_count", "first_seen",
                         "last_seen", "channels"},  # users withheld from AI
}


def ai_visible(tool: str, obs):
    """Filter a tool result for AI visibility (dicts only; lists/str pass)."""
    allowed = AI_VISIBLE_FIELDS.get(tool)
    if allowed is None or not isinstance(obs, dict):
        return obs
    return {k: v for k, v in obs.items() if k in allowed}


def withheld_keys(tool: str, obs) -> list[str]:
    allowed = AI_VISIBLE_FIELDS.get(tool)
    if allowed is None or not isinstance(obs, dict):
        return []
    return sorted(k for k in obs if k not in allowed)


# -- §10 task-based minimization + RoleViews (WP-F) --

# per-agent task profiles: which telemetry event_ids each agent needs.
# Everything else is withheld from that agent's view (minimization).
TASK_PROFILES: dict[str, set[str] | None] = {
    "A1": set(),            # alert metadata only; no raw telemetry
    "A2": None,             # investigation: full telemetry
    "A3": None,             # correlation: full telemetry
    "A4": {"3", "11", "4624", "4625"},  # threat: IOC-bearing events
    "A5": set(),            # planner: policy/evidence summaries only
}


def task_view(agent_id: str, events: list) -> list:
    """Withhold events outside the agent's task profile."""
    profile = TASK_PROFILES.get(agent_id)
    if profile is None:
        return list(events)
    return [e for e in events if getattr(e, "event_id", "") in profile]


class RoleView:
    """§10 role-scoped views over an observation. AI view = allowlist +
    redaction; analyst view = full fidelity."""

    def __init__(self, tool: str, obs):
        self.tool = tool
        self.raw = obs

    def ai(self) -> str:
        from aegis.agents.reasoning import _fmt_observation

        return _fmt_observation(self.ai_visible(), tool=self.tool)

    def ai_visible(self):
        return ai_visible(self.tool, self.raw)

    def withheld(self) -> list[str]:
        return withheld_keys(self.tool, self.raw)

    def analyst(self):
        return self.raw


# -- reversible tokenization vault (WP-F, §10) --

import secrets as _secrets  # noqa: E402


class TokenVault:
    """Per-incident reversible tokenization.

    tokenize(): replaces each detected sensitive span with a unique
    [TOK:<n>:<rand>] token and stores the ORIGINAL span. reveal(): analyst-only
    restoration. Vault stays local to the incident — never serialized into
    prompts, never persisted to ES.
    """

    def __init__(self) -> None:
        self._map: dict[str, str] = {}   # token -> original span
        self._counter = 0

    def _next_token(self) -> str:
        self._counter += 1
        return f"[TOK:{self._counter}:{_secrets.token_hex(2)}]"

    def tokenize(self, text: str) -> tuple[str, list[str]]:
        if not text:
            return text, []
        kinds: list[str] = []
        issued: list[str] = []
        out = str(text)
        for kind, rx in _COMPILED.items():
            def _sub(m, kind=kind):
                token = self._next_token()
                self._map[token] = m.group(0)
                kinds.append(kind)
                issued.append(token)
                return token
            out = rx.sub(_sub, out)
        return out, issued

    def reveal(self, text: str) -> str:
        out = str(text)
        for token, original in self._map.items():
            out = out.replace(token, original)
        return out

    def tokens(self) -> list[str]:
        return list(self._map.keys())