"""Evidence graph (WP-C, spec §14). Full graph model — user decision.

Nodes: evidence records ("ev:<id>"), hosts ("asset:<host>"),
identities ("identity:<user>"), indicators ("ioc:<value>").
Edges: typed, persisted as record:edge docs in incident-steps-*.

ADR-021 justification (user decision): full graph chosen over adjacency for
multi-hop/cross-incident reasoning headroom; ES-doc storage keeps the ES-only
constraint (ADR-017). Adjacency upgrade path unnecessary — this IS the graph.
"""

from datetime import UTC, datetime

REL_PROCESS_SPAWNED = "PROCESS_SPAWNED"
REL_CONNECTED_TO = "CONNECTED_TO"
REL_WROTE_FILE = "WROTE_FILE"
REL_AUTH_AS = "AUTHENTICATED_AS"
REL_BELONGS_HOST = "BELONGS_TO_HOST"
REL_SHARED_IOC = "SHARED_INDICATOR"

AUTH_EVENT_IDS = {"4624", "4625", "4634", "4647", "4672"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _edge(src_type, src_id, rel, dst_type, dst_id, incident_id, confidence=0.9):
    return {
        "incident_id": incident_id,
        "src_type": src_type, "src_id": src_id,
        "relationship": rel,
        "dst_type": dst_type, "dst_id": dst_id,
        "confidence": confidence,
    }


def _anchor_process(evidence: list) -> dict:
    """pid+host -> process-create evidence (the chain anchor per pid)."""
    anchors: dict[tuple[str, str], object] = {}
    for ev in evidence:
        d = ev.data or {}
        if str(d.get("event_id")) == "1" and d.get("pid"):
            anchors[(str(d.get("host")), str(d.get("pid")))] = ev
    return anchors


def build_incident_edges(evidence: list, incident_id: str) -> list[dict]:
    """Typed edges derived from freshly collected evidence records."""
    edges: list[dict] = []
    anchors = _anchor_process(evidence)

    for ev in evidence:
        d = ev.data or {}
        eid = f"ev:{ev.id}"
        host = str(d.get("host") or "")
        if host:
            edges.append(_edge("evidence", eid, REL_BELONGS_HOST,
                               "asset", f"asset:{host}", incident_id))

        pid = str(d.get("pid") or "")
        anchor = anchors.get((host, pid)) if pid else None
        if anchor is not None and anchor.id != ev.id:
            aid = f"ev:{anchor.id}"
            if str(d.get("event_id")) == "3":
                edges.append(_edge("evidence", aid, REL_CONNECTED_TO,
                                   "evidence", eid, incident_id))
            elif str(d.get("event_id")) == "11":
                edges.append(_edge("evidence", aid, REL_WROTE_FILE,
                                   "evidence", eid, incident_id))
        elif str(d.get("event_id")) in AUTH_EVENT_IDS and d.get("user"):
            # auth events without a process anchor still link to the identity
            edges.append(_edge("evidence", eid, REL_AUTH_AS,
                               "identity", f"identity:{d['user']}", incident_id,
                               confidence=0.8))

        if d.get("destination_ip"):
            edges.append(_edge("evidence", eid, REL_CONNECTED_TO,
                               "indicator", f"ioc:{d['destination_ip']}",
                               incident_id, confidence=0.85))

    return edges


def persist_edges(store, incident_id: str, edges: list[dict]) -> int:
    for e in edges:
        doc = dict(e)
        doc["ts"] = _now()
        store.add_record("edge", incident_id, doc)
    return len(edges)


def load_graph(store, incident_id: str) -> tuple[list[dict], list[dict]]:
    """(nodes, edges) for one incident. Nodes from evidence + entity records
    + every endpoint referenced by an edge."""
    evidence = [f"ev:{ev.id}" for ev in store.evidence(incident_id)]
    nodes = [{"id": n, "type": "evidence"} for n in evidence]
    for rec in store.records(incident_id, "asset"):
        nodes.append({"id": f"asset:{rec['hostname']}", "type": "asset",
                      "label": rec["hostname"]})
    for rec in store.records(incident_id, "identity"):
        nodes.append({"id": f"identity:{rec['username']}", "type": "identity",
                      "label": rec["username"]})
    edges = store.records(incident_id, "edge")

    have = {n["id"] for n in nodes}
    for e in edges:
        for side in ("src", "dst"):
            nid, ntype = e[f"{side}_id"], e[f"{side}_type"]
            if nid not in have:
                nodes.append({"id": nid, "type": ntype})
                have.add(nid)
    return nodes, edges


def traverse(edges: list[dict], start_id: str, max_hops: int = 3) -> list[dict]:
    """BFS over undirected view of edges; returns reachable edge list."""
    adj: dict[str, list[int]] = {}
    for i, e in enumerate(edges):
        adj.setdefault(e["src_id"], []).append(i)
        adj.setdefault(e["dst_id"], []).append(i)
    seen_nodes = {start_id}
    out: list[dict] = []
    frontier = [(start_id, 0)]
    while frontier:
        node, depth = frontier.pop()
        if depth >= max_hops:
            continue
        for ei in adj.get(node, []):
            e = edges[ei]
            if e in out:
                continue
            out.append(e)
            nxt = e["dst_id"] if e["src_id"] == node else e["src_id"]
            if nxt not in seen_nodes:
                seen_nodes.add(nxt)
                frontier.append((nxt, depth + 1))
    return out


def serialize_edges(edges: list[dict]) -> str:
    lines = []
    for e in edges:
        conf = f" ({e.get('confidence', 0.9):.2f})" if e.get("confidence") else ""
        lines.append(f"{e['src_id']} -[{e['relationship']}]-> {e['dst_id']}{conf}")
    return "\n".join(lines) or "(empty graph)"


def cross_incident_ioc_edges(store, current_incident_id: str) -> list[dict]:
    """SHARED_INDICATOR edges between this incident's IOC nodes and other
    incidents' matching indicator values. Supersedes find_related scan."""
    def indicators(inc_id: str) -> set[str]:
        vals = set()
        for ev in store.evidence(inc_id):
            d = ev.data or {}
            for k in ("destination_ip", "file_path"):
                v = d.get(k)
                if v:
                    vals.add(f"ioc:{k}:{v}")
            if d.get("host"):
                vals.add(f"ioc:host:{d['host']}")
        return vals

    mine = indicators(current_incident_id)
    if not mine:
        return []
    edges: list[dict] = []
    for other in store.all_incident_ids():
        if other == current_incident_id:
            continue
        shared = sorted(mine & indicators(other))
        for val in shared:
            edges.append({
                "incident_id": current_incident_id,
                "src_id": val, "src_type": "indicator",
                "dst_id": f"incident:{other}", "dst_type": "incident",
                "relationship": REL_SHARED_IOC,
                "confidence": 0.9, "ts": _now(),
            })
    return edges