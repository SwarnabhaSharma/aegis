"""Emergency controls (debt #17, spec §17). LLM-independent operator switches.

Global state seeded from env, mutable at runtime (API /controls). Enforcement
points: pipeline entry (pause/safe-mode/disabled agents), registry calls
(revoked tools), policy application (require-approval-for-all).
"""

import os
from dataclasses import dataclass, field


@dataclass
class ControlState:
    paused: bool = False
    disabled_agents: set[str] = field(default_factory=set)
    revoked_tools: set[str] = field(default_factory=set)
    require_approval_all: bool = False
    safe_mode: bool = False

    @classmethod
    def from_env(cls) -> "ControlState":
        cs = cls(
            paused=os.getenv("AEGIS_PAUSED") == "1",
            safe_mode=os.getenv("AEGIS_SAFE_MODE") == "1",
            require_approval_all=os.getenv("AEGIS_REQUIRE_APPROVAL") == "1",
        )
        if agents := os.getenv("AEGIS_DISABLE_AGENTS", ""):
            cs.disabled_agents |= {a.strip() for a in agents.split(",") if a.strip()}
        if tools := os.getenv("AEGIS_REVOKED_TOOLS", ""):
            cs.revoked_tools |= {t.strip() for t in tools.split(",") if t.strip()}
        if cs.safe_mode:
            cs.paused = True
            cs.require_approval_all = True
        return cs

    # -- mutators (operator surface) --

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False

    def disable_agent(self, agent_id: str) -> None:
        self.disabled_agents.add(agent_id)

    def enable_agent(self, agent_id: str) -> None:
        self.disabled_agents.discard(agent_id)

    def revoke_tool(self, tool: str) -> None:
        self.revoked_tools.add(tool)

    def restore_tool(self, tool: str) -> None:
        self.revoked_tools.discard(tool)

    def enter_safe_mode(self) -> None:
        self.safe_mode = True
        self.paused = True
        self.require_approval_all = True

    def restore_normal(self) -> None:
        self.safe_mode = False
        self.paused = False
        self.require_approval_all = False

    def autonomy_blocked(self) -> bool:
        return self.paused or self.safe_mode