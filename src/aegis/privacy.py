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