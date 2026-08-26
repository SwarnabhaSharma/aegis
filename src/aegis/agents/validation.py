"""Evidence validation (debt #6, spec 3.4/§15 hallucinated-evidence defense).

Agent outputs claiming evidence_ids must reference records that exist in the
incident store. Fabricated refs are stripped (never trusted), flagged in the
result, and reported for audit.
"""

from datetime import UTC, datetime

from aegis.agents.reasoning import AGENTS
from aegis.intel import attack as attack_store


def validate_evidence(store, incident_id: str,
                      results: dict) -> dict:
    """Strip fabricated/expired evidence_ids from each agent result.

    Returns report: {agent: {"fabricated": [...], "stripped": bool}}.
    Mutates results in place (AgentResult.data).
    """
    now = None
    known = {}
    for ev in store.evidence(incident_id):
        if ev.valid_until is not None:
            now = now or datetime.now(UTC)
            if ev.valid_until < now:
                continue  # expired -> treated as absent (§14)
        known[ev.id] = ev
    report: dict = {}
    for agent_id in AGENTS:
        r = results.get(agent_id)
        if r is None or not getattr(r, "data", None):
            continue
        claimed = r.data.get("evidence_ids")
        if not isinstance(claimed, list):
            continue
        fabricated = [str(x) for x in claimed if str(x) not in known]
        if not fabricated:
            continue
        r.data["evidence_ids"] = [x for x in claimed if str(x) in known]
        r.data["fabricated_evidence_ids"] = fabricated
        report[agent_id] = {"fabricated": fabricated, "stripped": True}
    return report


def validate_attack_mapping(store, incident_id: str, results: dict) -> dict:
    """§15 ATT&CK hallucination defense (strict mode).

    For each agent's attack_techniques: unknown technique ids and mappings
    citing no valid evidence_id are stripped + flagged.
    """
    now = None
    known_ev: set[str] = set()
    for ev in store.evidence(incident_id):
        if ev.valid_until is not None:
            now = now or datetime.now(UTC)
            if ev.valid_until < now:
                continue
        known_ev.add(ev.id)

    report: dict = {}
    for agent_id in AGENTS:
        r = results.get(agent_id)
        if r is None or not getattr(r, "data", None):
            continue
        claimed = r.data.get("attack_techniques")
        if not isinstance(claimed, list):
            continue
        kept, stripped = [], []
        for entry in claimed:
            if not isinstance(entry, dict):
                stripped.append({"entry": entry, "reason": "malformed"})
                continue
            tid = str(entry.get("id", "")).upper()
            if attack_store.lookup(tid) is None:
                stripped.append({"id": tid, "reason": "unknown technique"})
                continue
            cited = [str(x) for x in entry.get("evidence_ids", [])
                     if str(x) in known_ev]
            if not cited:
                stripped.append({"id": tid,
                                 "reason": "no valid evidence_ids cited"})
                continue
            kept.append({**entry, "id": tid, "evidence_ids": cited})
        r.data["attack_techniques"] = kept
        if stripped:
            r.data["stripped_attack_techniques"] = stripped
            report[agent_id] = {"stripped_count": len(stripped),
                                "kept_count": len(kept)}
    return report