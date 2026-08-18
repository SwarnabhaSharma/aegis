"""Policy engine (Phase 4). Deterministic pure function per ADR-006.

evaluate(action, facts, ...) -> ALLOW | APPROVE | DENY. No LLM involved.
Versioned decisions, precedence (conflict -> DENY fail-safe), emergency
override, dry-run mode.
"""

import operator
from dataclasses import dataclass
from enum import Enum
from typing import Any

from aegis.policies.store import Policy, get_policy_for

# ponytail: hardcoded asset map; swap for Asset store when a consumer exists.
ASSET_CRITICALITY: dict[str, str] = {"win-vm": "low", "critical-box": "critical"}

_OPS = {
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
    "==": operator.eq,
    "!=": operator.ne,
}


class Decision(Enum):
    ALLOW = "ALLOW"
    APPROVE = "APPROVE"
    DENY = "DENY"


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    decision: Decision
    policy_version: str
    reason: str
    facts: dict[str, Any]
    dry_run: bool = False
    overridden: bool = False


def evaluate(
    action: str,
    facts: dict[str, Any],
    incident_type: str = "powershell",
    dry_run: bool = False,
    override: Decision | None = None,
    policies: list[Policy] | None = None,
) -> PolicyDecision:
    """Evaluate an action against matching policies. Pure; never executes."""
    if override is not None:
        if override not in (Decision.ALLOW, Decision.DENY):
            raise ValueError("override must be Decision.ALLOW or Decision.DENY")
        return PolicyDecision(action, override, "override", "operator override",
                              facts, dry_run=dry_run, overridden=True)

    matches = [p for p in (policies or get_policy_for(incident_type)) if p.action == action]
    if not matches:
        return PolicyDecision(action, Decision.DENY, "-", "no policy for action",
                              facts, dry_run=dry_run)

    results = [_eval_one(p, facts) for p in matches]
    decisions = {r.decision for r in results}
    if len(decisions) > 1:
        versions = ";".join(p.version for p in matches)
        return PolicyDecision(action, Decision.DENY, versions,
                              "conflicting policies -> fail-safe DENY", facts,
                              dry_run=dry_run)
    r = results[0]
    return PolicyDecision(action, r.decision, r.policy_version, r.reason,
                          r.facts, dry_run=dry_run)


def _eval_one(policy: Policy, facts: dict[str, Any]) -> PolicyDecision:
    resolved = dict(facts)
    host = facts.get("host")
    if host:
        resolved["asset_criticality"] = ASSET_CRITICALITY.get(host, "unknown")

    failures: list[str] = []
    for key, cond in policy.conditions.items():
        value = resolved.get(key)
        op, _, rhs = cond.partition(" ")
        rhs = rhs.strip()
        if not _satisfied(value, op, rhs):
            failures.append(f"{key}{cond} failed (value={value!r})")

    if failures:
        return PolicyDecision(policy.action, Decision.DENY, policy.version,
                              "; ".join(failures), resolved)
    decision = Decision.APPROVE if policy.approval_required else Decision.ALLOW
    return PolicyDecision(policy.action, decision, policy.version,
                          "all conditions met", resolved)


def _coerce(left: Any, right: str) -> tuple[Any, Any]:
    try:
        return float(left), float(right)
    except (TypeError, ValueError):
        return left, right


def _satisfied(value: Any, op: str, rhs: str) -> bool:
    if op == "present":
        return value not in (None, "", [], {})
    if op not in _OPS:
        raise ValueError(f"unsupported condition op: {op!r}")
    left, right = _coerce(value, rhs)
    return _OPS[op](left, right)