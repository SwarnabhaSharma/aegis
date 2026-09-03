"""Create Aegis Kibana dashboards using Lens visualizations (Kibana 8.19+).

Usage:
    python scripts/create_kibana_dashboards.py [--kibana-url http://localhost:5601]
"""

import argparse
import json
import sys
import time
import uuid

sys.path.insert(0, "src")

import httpx
from httpx import BasicAuth

KIBANA_URL = "http://localhost:5601"
KIBANA_AUTH = None


def _col_id():
    return str(uuid.uuid4())[:8]


def _api(method, url, body=None, auth=None, retries=3):
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    kwargs = {"headers": headers, "timeout": 60, "auth": auth}
    if body is not None:
        kwargs["json"] = body
    for attempt in range(retries):
        try:
            resp = httpx.request(method, url, **kwargs)
            if resp.status_code < 400:
                return resp.json() if resp.content else {}
            if resp.status_code == 404:
                return {}
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return resp.json() if resp.content else {}
        except httpx.TimeoutException:
            if attempt < retries - 1:
                time.sleep(2)
                continue
            raise
    return {}


# -- Lens column builders --

def _count_col(col_id):
    return {
        "label": "Count",
        "dataType": "number",
        "operationType": "count",
        "isBucketed": False,
        "sourceField": "___records___",
        "params": {"emptyAsNull": True},
    }


def _terms_col(col_id, field, size=10, label=None):
    return {
        "label": label or f"Top values of {field}",
        "dataType": "string",
        "operationType": "terms",
        "sourceField": field,
        "isBucketed": True,
        "params": {
            "size": size,
            "orderBy": {"type": "column", "columnId": col_id},
            "orderDirection": "desc",
            "otherBucket": True,
            "missingBucket": False,
            "parentFormat": {"id": "terms"},
        },
    }


def _date_hist_col(field, count_col_id):
    return {
        "label": "Count of records over @timestamp",
        "dataType": "date",
        "operationType": "date_histogram",
        "sourceField": field,
        "isBucketed": True,
        "params": {
            "interval": "auto",
            "includeEmptyRows": True,
            "dropPartials": False,
        },
    }


# -- Panel builders --

def _lens_panel(panel_index, x, y, w, h, title, viz_type, state, refs):
    return {
        "version": "8.15.0",
        "type": "lens",
        "panelIndex": panel_index,
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_index},
        "embeddableConfig": {
            "enhancements": {"dynamicActions": {"events": []}},
            "syncColors": False,
            "syncCursor": True,
            "syncTooltips": False,
            "filters": [],
            "query": {"query": "", "language": "kuery"},
            "attributes": {
                "title": title,
                "visualizationType": viz_type,
                "type": "lens",
                "references": refs,
                "state": state,
            },
        },
    }


def _xy_layer(layer_id, x_col, y_cols, split_col=None, series_type="bar_stacked"):
    layer = {
        "layerId": layer_id,
        "seriesType": series_type,
        "xAccessor": x_col,
        "accessors": y_cols,
        "layerType": "data",
    }
    if split_col:
        layer["splitAccessor"] = split_col
    return layer


def _dt_layer(layer_id, columns):
    return {
        "layerId": layer_id,
        "columns": columns,
        "layerType": "data",
    }


def _lens_state(visualization, layers, datasource_cols):
    layer_id = "layer0"
    return {
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            **visualization,
        },
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": datasource_cols,
                        "columnOrder": list(datasource_cols.keys()),
                        "incompleteColumns": {},
                    }
                }
            }
        },
    }


def _data_view_ref(layer_id, data_view_id):
    return {
        "type": "index-pattern",
        "id": data_view_id,
        "name": f"indexpattern-datasource-layer-{layer_id}",
    }


# -- Visualization definitions --

def _incidents_table(dv_id):
    layer_id = "layer0"
    x = _col_id()
    state_col = _col_id()
    sev_col = _col_id()
    type_col = _col_id()
    cnt = _col_id()

    cols = {
        x: _terms_col(cnt, "id", 20, "Incident ID"),
        state_col: _terms_col(cnt, "state", 10, "State"),
        sev_col: _terms_col(cnt, "severity", 10, "Severity"),
        type_col: _terms_col(cnt, "type", 10, "Type"),
        cnt: _count_col(cnt),
    }

    viz_state = {
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "preferredSeriesType": "bar_stacked",
            "layers": [_xy_layer(layer_id, x, [cnt], series_type="bar_stacked")],
        },
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": cols,
                        "columnOrder": list(cols.keys()),
                        "incompleteColumns": {},
                    }
                }
            }
        },
    }

    return viz_state, [_data_view_ref(layer_id, dv_id)], "lnsXY", "Aegis Incidents"


def _severity_pie(dv_id):
    layer_id = "layer0"
    sev = _col_id()
    cnt = _col_id()

    cols = {
        sev: _terms_col(cnt, "severity", 10, "Severity"),
        cnt: _count_col(cnt),
    }

    viz_state = {
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "preferredSeriesType": "bar_stacked",
            "layers": [_xy_layer(layer_id, sev, [cnt], series_type="bar_stacked")],
        },
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": cols,
                        "columnOrder": list(cols.keys()),
                        "incompleteColumns": {},
                    }
                }
            }
        },
    }

    return viz_state, [_data_view_ref(layer_id, dv_id)], "lnsXY", "Severity Distribution"


def _states_bar(dv_id):
    layer_id = "layer0"
    state_f = _col_id()
    cnt = _col_id()

    cols = {
        state_f: _terms_col(cnt, "state", 20, "State"),
        cnt: _count_col(cnt),
    }

    viz_state = {
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "preferredSeriesType": "bar_stacked",
            "layers": [_xy_layer(layer_id, state_f, [cnt], series_type="bar_stacked")],
        },
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": cols,
                        "columnOrder": list(cols.keys()),
                        "incompleteColumns": {},
                    }
                }
            }
        },
    }

    return viz_state, [_data_view_ref(layer_id, dv_id)], "lnsXY", "Incident States"


def _evidence_by_kind(dv_id):
    layer_id = "layer0"
    kind = _col_id()
    cnt = _col_id()

    cols = {
        kind: _terms_col(cnt, "kind", 20, "Evidence Kind"),
        cnt: _count_col(cnt),
    }

    viz_state = {
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "preferredSeriesType": "bar_horizontal",
            "layers": [_xy_layer(layer_id, kind, [cnt], series_type="bar_horizontal")],
        },
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": cols,
                        "columnOrder": list(cols.keys()),
                        "incompleteColumns": {},
                    }
                }
            }
        },
    }

    return viz_state, [_data_view_ref(layer_id, dv_id)], "lnsXY", "Evidence by Kind"


def _attack_table(dv_id):
    layer_id = "layer0"
    kind = _col_id()
    cnt = _col_id()

    cols = {
        kind: _terms_col(cnt, "kind", 20, "ATT&CK Technique"),
        cnt: _count_col(cnt),
    }

    viz_state = {
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "preferredSeriesType": "bar_stacked",
            "layers": [_xy_layer(layer_id, kind, [cnt])],
        },
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": cols,
                        "columnOrder": list(cols.keys()),
                        "incompleteColumns": {},
                    }
                }
            }
        },
    }

    return viz_state, [_data_view_ref(layer_id, dv_id)], "lnsXY", "ATT&CK Techniques"


def _timeline(dv_id):
    layer_id = "layer0"
    ts = _col_id()
    cnt = _col_id()

    cols = {
        ts: _date_hist_col("ts", cnt),
        cnt: _count_col(cnt),
    }

    viz_state = {
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "preferredSeriesType": "area_stacked",
            "layers": [_xy_layer(layer_id, ts, [cnt], series_type="area_stacked")],
        },
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": cols,
                        "columnOrder": list(cols.keys()),
                        "incompleteColumns": {},
                    }
                }
            }
        },
    }

    return viz_state, [_data_view_ref(layer_id, dv_id)], "lnsXY", "Event Timeline"


def _audit_table(dv_id):
    layer_id = "layer0"
    cat = _col_id()
    actor = _col_id()
    cnt = _col_id()

    cols = {
        cat: _terms_col(cnt, "category", 20, "Category"),
        actor: _terms_col(cnt, "actor", 20, "Actor"),
        cnt: _count_col(cnt),
    }

    viz_state = {
        "visualization": {
            "legend": {"isVisible": True, "position": "right"},
            "preferredSeriesType": "bar_stacked",
            "layers": [_xy_layer(layer_id, cat, [cnt])],
        },
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columns": cols,
                        "columnOrder": list(cols.keys()),
                        "incompleteColumns": {},
                    }
                }
            }
        },
    }

    return viz_state, [_data_view_ref(layer_id, dv_id)], "lnsXY", "Audit Trail"


# -- Dashboard --

VIZ_DEFS = [
    ("incidents", _incidents_table),
    ("incidents", _severity_pie),
    ("incidents", _states_bar),
    ("steps", _evidence_by_kind),
    ("steps", _attack_table),
    ("steps", _timeline),
    ("audit", _audit_table),
]


def build_dashboard_panels(views):
    panels = []
    references = []

    for i, (view_key, viz_fn) in enumerate(VIZ_DEFS):
        dv_id = views[view_key]
        viz_state, viz_refs, viz_type, title = viz_fn(dv_id)

        row = i // 2
        col = i % 2
        panel_index = str(i)

        panel = _lens_panel(
            panel_index, col * 24, row * 15, 24, 15,
            title, viz_type, viz_state, viz_refs,
        )
        panels.append(panel)

        for ref in viz_refs:
            references.append({
                **ref,
                "name": f"{panel_index}:{ref['name']}",
            })

    return panels, references


def main():
    parser = argparse.ArgumentParser(description="Create Aegis Kibana dashboards")
    parser.add_argument("--kibana-url", default=KIBANA_URL)
    parser.add_argument("--kibana-user", default=None)
    parser.add_argument("--kibana-pass", default=None)
    args = parser.parse_args()

    global KIBANA_AUTH
    if args.kibana_user and args.kibana_pass:
        KIBANA_AUTH = BasicAuth(args.kibana_user, args.kibana_pass)

    kibana_url = args.kibana_url
    base = f"{kibana_url}"

    print(f"Kibana: {kibana_url}")

    # Check Kibana
    try:
        resp = httpx.get(f"{base}/api/status", timeout=60, auth=KIBANA_AUTH)
        status = resp.json().get("status", {}).get("overall", {}).get("level")
        print(f"Status: {status}")
    except Exception as e:
        print(f"Cannot reach Kibana: {e}")
        sys.exit(1)

    # Delete old broken objects
    print("\n--- Cleaning up old objects ---")
    for vid in [
        "aegis-viz-incidents", "aegis-viz-severity", "aegis-viz-states",
        "aegis-viz-evidence-host", "aegis-viz-attack", "aegis-viz-timeline",
        "aegis-viz-audit", "aegis-dashboard",
    ]:
        for otype in ["visualization", "dashboard"]:
            _api("DELETE", f"{base}/api/saved_objects/{otype}/{vid}", auth=KIBANA_AUTH)

    # Delete old data views and recreate
    print("\n--- Data Views ---")
    views = {
        "incidents": "aegis-incidents",
        "steps": "aegis-steps",
        "audit": "aegis-audit",
        "alerts": "aegis-alerts",
    }
    patterns = {
        "incidents": "aegis-dev-incidents",
        "steps": "aegis-dev-steps",
        "audit": "aegis-dev-audit",
        "alerts": "aegis-dev-alerts",
    }
    time_fields = {
        "incidents": "created_at",
        "steps": "ts",
        "audit": "ts",
        "alerts": "@timestamp",
    }
    for name, vid in views.items():
        _api("DELETE", f"{base}/api/data_views/data_view/{vid}", auth=KIBANA_AUTH)
        result = _api("POST", f"{base}/api/data_views/data_view", {
            "data_view": {
                "id": vid, "title": patterns[name],
                "timeFieldName": time_fields[name], "name": patterns[name],
            },
        }, auth=KIBANA_AUTH)
        ok = bool(result.get("data_view"))
        print(f"  {'OK' if ok else 'WARN'} {vid} -> {patterns[name]} (time: {time_fields[name]})")

    # Build dashboard with inline Lens panels
    print("\n--- Building dashboard with Lens panels ---")
    panels, references = build_dashboard_panels(views)
    print(f"  Built {len(panels)} Lens panels")

    # Create dashboard
    result = _api("POST", f"{base}/api/saved_objects/dashboard/aegis-dashboard", {
        "attributes": {
            "title": "Aegis SOC Overview",
            "description": "Aegis — incidents, evidence, ATT&CK, audit",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({
                "useMargins": True, "syncColors": False,
                "syncCursor": True, "syncTooltips": False,
                "hidePanelTitles": False,
            }),
            "timeRestore": True, "timeTo": "now", "timeFrom": "now-24h",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                }),
            },
        },
        "references": references,
    }, auth=KIBANA_AUTH)

    ok = bool(result.get("id"))
    print(f"  {'OK' if ok else 'WARN'} dashboard: aegis-dashboard")
    if not ok:
        print(f"  Error: {result}")

    print(f"\nDone. Open {kibana_url}/app/dashboards#/view/aegis-dashboard")


if __name__ == "__main__":
    main()
