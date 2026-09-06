"""Evidence collection pipeline — fetch events, build records, detect contradictions, seed graph.

Extracted from slice.py investigate() to isolate the ~50-line evidence
concern from the orchestration flow.
"""

from __future__ import annotations


def collect_evidence(store, inc_id: str, host: str, registry=None,
                     events=None, seed=None, audit=None):
    """Fetch telemetry, create evidence records, build graph edges.

    Returns (evidence_records, evidence_events, edges, shared_edges, prov).
    """
    from aegis.incidents.evidence import evidence_from_tool_result

    prov = "real"
    if events is not None:
        evidence_events = list(events)
    elif registry is not None:
        proc_tree = registry.call("get_process_tree", "A2", host=host)
        net = registry.call("get_network_connections", "A2", host=host)
        evidence_events = list(proc_tree) + list(net)
    else:
        from aegis.slice import _synthetic_events

        evidence_events = _synthetic_events(host)
        prov = "synthetic"

    evidence_records = evidence_from_tool_result(
        inc_id, "read_tools", evidence_events, provenance=prov,
    )
    _detect_contradictions(evidence_records)
    for ev in evidence_records:
        store.add_evidence(ev)

    from aegis.intel.graph import build_incident_edges, cross_incident_ioc_edges
    from aegis.intel.graph import persist_edges as persist_graph_edges

    edges = build_incident_edges(evidence_records, inc_id)
    shared_edges = cross_incident_ioc_edges(store, inc_id)
    persist_graph_edges(store, inc_id, edges + shared_edges)

    if audit is not None:
        if edges or shared_edges:
            audit.record("graph_built", inc_id, actor="graph_builder",
                         incident_edges=len(edges),
                         cross_incident_edges=len(shared_edges))

    return evidence_records, evidence_events, edges, shared_edges, prov


def _detect_contradictions(evidence_records: list) -> None:
    """§14: populate contradicts field when two records conflict on same entity."""
    by_entity: dict[tuple, list] = {}
    for ev in evidence_records:
        data = ev.data
        host = data.get("host", "")
        entity_key = None
        if data.get("process"):
            entity_key = ("process", host, data["process"])
        elif data.get("file_path"):
            entity_key = ("file", host, data["file_path"])
        if entity_key:
            by_entity.setdefault(entity_key, []).append(ev)

    for _entity_key, evs in by_entity.items():
        if len(evs) < 2:
            continue
        actions = {}
        for ev in evs:
            action = ev.data.get("action", "")
            actions.setdefault(action, []).append(ev)
        if len(actions) > 1:
            all_evs = [ev for group in actions.values() for ev in group]
            ids = [ev.id for ev in all_evs]
            for ev in all_evs:
                ev.contradicts = [i for i in ids if i != ev.id]
