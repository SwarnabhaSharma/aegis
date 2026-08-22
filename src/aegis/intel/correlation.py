"""Multi-alert correlation (Phase 7). Shared-IOC linking across incidents.

Scans evidence of all incidents for indicators shared with the current one.
"""

_INDICATOR_KEYS = ("destination_ip", "host", "file_path")


def _indicators(evidence: list) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for ev in evidence:
        data = ev.data or {}
        for key in _INDICATOR_KEYS:
            value = data.get(key)
            if value:
                out.add((key, str(value)))
    return out


def find_related(store, current_incident_id: str) -> list[dict]:
    """Incidents sharing at least one indicator with the current one.

    ponytail: full evidence scan per incident; swap for an ES term query on
    steps.doc.data.* when incident count makes O(n) scans measurable.
    """
    mine = _indicators(store.evidence(current_incident_id))
    if not mine:
        return []
    related = []
    for inc_id in store.all_incident_ids():
        if inc_id == current_incident_id:
            continue
        shared = mine & _indicators(store.evidence(inc_id))
        if shared:
            related.append({
                "incident_id": inc_id,
                "shared": sorted(f"{k}={v}" for k, v in shared),
            })
    return sorted(related, key=lambda r: r["incident_id"])