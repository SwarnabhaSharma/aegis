"""§10 Privacy gateway — single filtering boundary between store and consumers.

Every observation passes through Gateway.filter() which returns a RoleView
with three representations:
  .ai()       — agent prompt (field-filtered + text-redacted)
  .analyst()  — human view (tokenized PII, reversible)
  .withheld() — what was filtered (for audit)
"""

from aegis.privacy import (
    TASK_PROFILES,
    RoleView,
    TokenVault,
    redact,
    task_view,
    withheld_keys,
)


class Gateway:
    """Central privacy filter. One instance per incident."""

    def __init__(self) -> None:
        self.vault = TokenVault()

    def filter(self, agent_id: str, tool: str, obs) -> RoleView:
        """Wrap observation in a RoleView with per-agent filtering applied."""
        filtered = obs
        # task-based minimization: strip events outside agent's profile
        if isinstance(obs, list) and agent_id in TASK_PROFILES:
            filtered = task_view(agent_id, obs)
        return RoleView(tool, filtered)

    def filter_text(self, agent_id: str, text: str) -> str:
        """Redact text for AI view."""
        masked, _ = redact(text)
        return masked

    def analyst_view(self, text: str) -> str:
        """Tokenize PII for analyst view (reversible via vault)."""
        tokenized, _ = self.vault.tokenize(text)
        return tokenized

    def reveal(self, text: str) -> str:
        """De-tokenize analyst view back to original."""
        return self.vault.reveal(text)

    def withheld_report(self, agent_id: str, tool: str, obs) -> dict:
        """Audit report: what was withheld from this agent for this observation."""
        report = {"agent": agent_id, "tool": tool, "withheld_keys": [],
                  "task_filtered": False}
        if isinstance(obs, dict):
            report["withheld_keys"] = withheld_keys(tool, obs)
        profile = TASK_PROFILES.get(agent_id)
        if profile is not None and isinstance(obs, list):
            original_count = len(obs)
            filtered = task_view(agent_id, obs)
            report["task_filtered"] = True
            report["events_withheld"] = original_count - len(filtered)
        return report


# module-level singleton — one gateway per process
_gateway: Gateway | None = None


def get_gateway() -> Gateway:
    global _gateway
    if _gateway is None:
        _gateway = Gateway()
    return _gateway
