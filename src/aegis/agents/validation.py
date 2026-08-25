"""Evidence validation (debt #6, spec 3.4/§15 hallucinated-evidence defense).

Agent outputs claiming evidence_ids must reference records that exist in the
incident store. Fabricated refs are stripped (never trusted), flagged in the
result, and reported for audit.
"""

from datetime import UTC, datetime

from aegis.agents.reasoning import AGENTS


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