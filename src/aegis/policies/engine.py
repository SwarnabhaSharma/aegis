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


def _version_key(version: str):
    try:
        return tuple(int(x) for x in version.split("."))
    except ValueError:
        return (0,)


def evaluate(
    action: str,
    facts: dict[str, Any],
    incident_type: str = "powershell",
    dry_run: bool = False,
    override: Decision | None = None,
    policies: list[Policy] | None = None,
    store=None,
    incident_id: str = "",
) -> PolicyDecision:
    """Evaluate an action against matching policies. Pure; never executes.

    Precedence (§13 J.2): most-specific policy wins — specificity = number of
    conditions, tie broken by higher version. Equal-specificity policies that
    both pass but disagree -> fail-safe DENY.
    """
    if override is not None:
        if override not in (Decision.ALLOW, Decision.DENY):
            raise ValueError("override must be Decision.ALLOW or Decision.DENY")
        return PolicyDecision(action, override, "override", "operator override",
                              facts, dry_run=dry_run, overridden=True)

    matches = [p for p in (policies or get_policy_for(incident_type)) if p.action == action]
    if not matches:
        return PolicyDecision(action, Decision.DENY, "-", "no policy for action",
                              facts, dry_run=dry_run)

    # most-specific first: more conditions bind tighter; version breaks ties
    matches.sort(key=lambda p: (-len(p.conditions),
                                tuple(-x for x in _version_key(p.version))))

    results = [_eval_one(p, facts, store=store, incident_id=incident_id)
               for p in matches]

    # highest-specificity tier decides; identical-version disagreement -> DENY
    top_spec = len(matches[0].conditions)
    tier_pairs = [(r, p) for r, p in zip(results, matches, strict=True)
                  if len(p.conditions) == top_spec]
    top_version = max(_version_key(p.version) for _, p in tier_pairs)
    latest = [r for r, p in tier_pairs
              if _version_key(p.version) == top_version]
    decisions = {r.decision for r in latest}
    if len(decisions) > 1:
        versions = ";".join(sorted({p.version for _, p in tier_pairs}))
        return PolicyDecision(action, Decision.DENY, versions,
                              "conflicting policies at top specificity -> fail-safe DENY",
                              facts, dry_run=dry_run)
    winner = latest[0]
    if winner.decision is Decision.DENY:
        # lower-specificity policies may still satisfy where the strictest failed
        for r, _p in zip(results[1:], matches[1:], strict=True):
            if r.decision is not Decision.DENY:
                return PolicyDecision(action, r.decision, r.policy_version,
                                      f"{r.reason} (generalized fallback)",
                                      r.facts, dry_run=dry_run)
        return PolicyDecision(action, Decision.DENY, winner.policy_version,
                              winner.reason, facts, dry_run=dry_run)
    return PolicyDecision(action, winner.decision, winner.policy_version,
                          winner.reason, winner.facts, dry_run=dry_run)


def _eval_one(policy: Policy, facts: dict[str, Any],
              store=None, incident_id: str = "") -> PolicyDecision:
    resolved = dict(facts)
    host = facts.get("host")
    if host:
        # criticality: Asset records first (#9), hardcoded map as fallback
        criticality = None
        if store is not None and incident_id:
            from aegis.incidents.entities import get_asset_criticality

            criticality = get_asset_criticality(store, incident_id, host)
        if criticality is None:
            criticality = ASSET_CRITICALITY.get(host, "unknown")
        resolved["asset_criticality"] = criticality

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