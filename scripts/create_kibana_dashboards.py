"""Create Aegis Kibana dashboards programmatically via the saved objects API.

Creates data views, visualizations, and a dashboard linking them all.
Run after ES has some Aegis incident data (via demo_elastic.py or manual pipeline).

Usage:
    python scripts/create_kibana_dashboards.py [--kibana-url http://localhost:5601]
"""

import argparse
import json
import sys

sys.path.insert(0, "src")

import httpx

KIBANA_URL = "http://localhost:5601"

# -- helpers to build short agg definitions without 150-char lines --

def _terms_agg(agg_id, field, size=20, schema="bucket"):
    return {
        "id": agg_id, "enabled": True, "type": "terms",
        "params": {
            "field": field, "size": size,
            "order": "desc", "orderBy": "1",
        },
        "schema": schema,
    }


def _count_agg(agg_id="1", schema="metric"):
    return {"id": agg_id, "enabled": True, "type": "count", "params": {}, "schema": schema}


def _date_histogram_agg(agg_id, field, schema="segment"):
    return {
        "id": agg_id, "enabled": True, "type": "date_histogram",
        "params": {
            "field": field, "interval": "auto",
            "min_doc_count": 1, "extended_bounds": {},
        },
        "schema": schema,
    }


def _axis(show_filter=True):
    return {"show": True, "filter": show_filter, "truncate": 100}


def _cat_axis(pos="bottom"):
    return {
        "id": "CategoryAxis-1", "type": "category",
        "position": pos, "show": True, "labels": _axis(),
    }


def _val_axis(name="LeftAxis-1", pos="left"):
    return {
        "id": "ValueAxis-1", "name": name, "type": "value",
        "position": pos, "show": True, "labels": _axis(False),
    }


# -- Kibana API helpers --

def _post(kibana_url, path, body):
    resp = httpx.post(
        f"{kibana_url}{path}",
        headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
        json=body, timeout=30,
    )
    return resp.json()


def _delete(kibana_url, path):
    httpx.delete(f"{kibana_url}{path}", headers={"kbn-xsrf": "true"}, timeout=10)


def create_data_view(kibana_url, view_id, title):
    _delete(kibana_url, f"/api/data_views/data_view/{view_id}")
    result = _post(kibana_url, "/api/data_views/data_view", {
        "data_view": {"id": view_id, "title": title, "timeFieldName": "@timestamp", "name": title},
    })
    ok = bool(result.get("data_view"))
    print(f"  {'OK' if ok else 'WARN'} data view: {view_id} -> {title}")
    return view_id


def _create_viz(kibana_url, viz_id, title, data_view_id, vis_type, agg_state):
    _delete(kibana_url, f"/api/saved_objects/visualization/{viz_id}")
    result = _post(kibana_url, f"/api/saved_objects/visualization/{viz_id}", {
        "attributes": {
            "title": title,
            "visState": json.dumps(agg_state),
            "uiStateJSON": "{}",
            "description": agg_state.get("description", ""),
        },
        "references": [{
            "type": "index-pattern",
            "id": data_view_id,
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
        }],
    })
    ok = bool(result.get("id"))
    print(f"  {'OK' if ok else 'WARN'} viz: {viz_id}")
    return viz_id


# -- data views --

def create_all_data_views(kibana_url):
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
    for name, vid in views.items():
        create_data_view(kibana_url, vid, patterns[name])
    return views


# -- visualizations --

def create_all_visualizations(kibana_url, views):
    ids = []

    # 1. Incident table
    ids.append(_create_viz(
        kibana_url, "aegis-viz-incidents", "Aegis Incidents",
        views["incidents"], "table", {
            "title": "Aegis Incidents", "type": "table",
            "params": {"perPage": 25, "showPartialRows": False,
                       "showMetricsAtAllLevels": False,
                       "showTotal": True, "totalFunc": "count"},
            "aggs": [
                _count_agg(),
                _terms_agg("2", "id", 50),
                _terms_agg("3", "state"),
                _terms_agg("4", "severity", 10),
                _terms_agg("5", "type"),
            ],
        },
    ))

    # 2. Severity pie
    ids.append(_create_viz(
        kibana_url, "aegis-viz-severity", "Severity Distribution",
        views["incidents"], "pie", {
            "title": "Severity Distribution", "type": "pie",
            "params": {
                "type": "pie", "addTooltip": True, "addLegend": True,
                "legendPosition": "right", "isDonut": True,
                "labels": {"show": True, "values": True,
                           "last_level": True, "truncate": 100},
            },
            "aggs": [_count_agg(), _terms_agg("2", "severity", 10, "segment")],
        },
    ))

    # 3. States bar
    ids.append(_create_viz(
        kibana_url, "aegis-viz-states", "Incident States",
        views["incidents"], "histogram", {
            "title": "Incident States", "type": "histogram",
            "params": {
                "type": "histogram", "grid": {"categoryLines": False},
                "categoryAxes": [_cat_axis()],
                "valueAxes": [_val_axis()],
                "addTooltip": True, "addLegend": True,
                "legendPosition": "right",
            },
            "aggs": [_count_agg(), _terms_agg("2", "state", 20, "segment")],
        },
    ))

    # 4. Steps by kind
    ids.append(_create_viz(
        kibana_url, "aegis-viz-evidence-host", "Evidence by Host",
        views["steps"], "horizontal_bar", {
            "title": "Evidence by Host", "type": "horizontal_bar",
            "params": {
                "type": "horizontal_bar",
                "grid": {"categoryLines": False},
                "categoryAxes": [_cat_axis("left")],
                "valueAxes": [_val_axis("BottomAxis-1", "bottom")],
                "addTooltip": True, "addLegend": True,
                "legendPosition": "right",
            },
            "aggs": [_count_agg(), _terms_agg("2", "kind", 20, "segment")],
        },
    ))

    # 5. ATT&CK table
    ids.append(_create_viz(
        kibana_url, "aegis-viz-attack", "ATT&CK Techniques",
        views["steps"], "table", {
            "title": "ATT&CK Techniques", "type": "table",
            "params": {"perPage": 20, "showPartialRows": False,
                       "showMetricsAtAllLevels": False,
                       "showTotal": True, "totalFunc": "count"},
            "aggs": [_count_agg(), _terms_agg("2", "kind", 10)],
        },
    ))

    # 6. Timeline area
    ids.append(_create_viz(
        kibana_url, "aegis-viz-timeline", "Event Timeline",
        views["steps"], "area", {
            "title": "Event Timeline", "type": "area",
            "params": {
                "type": "area", "grid": {"categoryLines": False},
                "categoryAxes": [_cat_axis()],
                "valueAxes": [_val_axis()],
                "addTooltip": True, "addLegend": True,
                "legendPosition": "right", "mode": "stacked",
                "times": [], "addTimeMarker": False,
            },
            "aggs": [
                _count_agg(),
                _date_histogram_agg("2", "ts"),
                _terms_agg("3", "kind", 10, "group"),
            ],
        },
    ))

    # 7. Audit trail
    ids.append(_create_viz(
        kibana_url, "aegis-viz-audit", "Audit Trail",
        views["audit"], "table", {
            "title": "Audit Trail", "type": "table",
            "params": {"perPage": 50, "showPartialRows": False,
                       "showMetricsAtAllLevels": False,
                       "showTotal": True, "totalFunc": "count"},
            "aggs": [
                _count_agg(),
                _terms_agg("2", "category"),
                _terms_agg("3", "actor"),
            ],
        },
    ))

    return ids


# -- dashboard --

def create_dashboard(kibana_url, viz_ids):
    dash_id = "aegis-dashboard"
    _delete(kibana_url, f"/api/saved_objects/dashboard/{dash_id}")

    panels, references = [], []
    for i, vid in enumerate(viz_ids):
        row, col = i // 2, i % 2
        panels.append({
            "version": "8.15.0", "type": "visualization",
            "gridData": {"x": col * 24, "y": row * 15,
                         "w": 24, "h": 15, "i": str(i)},
            "panelIndex": str(i), "embeddableConfig": {},
        })
        references.append({"type": "visualization", "id": vid, "name": f"panel_{i}"})

    result = _post(kibana_url, f"/api/saved_objects/dashboard/{dash_id}", {
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
        },
        "references": references,
    })
    ok = bool(result.get("id"))
    print(f"  {'OK' if ok else 'WARN'} dashboard: {dash_id}")
    return dash_id


# -- main --

def main():
    parser = argparse.ArgumentParser(description="Create Aegis Kibana dashboards")
    parser.add_argument("--kibana-url", default=KIBANA_URL)
    args = parser.parse_args()

    kibana_url = args.kibana_url
    print(f"Kibana: {kibana_url}")

    try:
        resp = httpx.get(f"{kibana_url}/api/status", timeout=5)
        status = resp.json().get("status", {}).get("overall", {}).get("level")
        print(f"Status: {status}")
    except Exception as e:
        print(f"Cannot reach Kibana: {e}")
        sys.exit(1)

    print("\n--- Data Views ---")
    views = create_all_data_views(kibana_url)

    print("\n--- Visualizations ---")
    viz_ids = create_all_visualizations(kibana_url, views)

    print("\n--- Dashboard ---")
    create_dashboard(kibana_url, viz_ids)

    print(f"\nDone. Open {kibana_url}/app/dashboards#/view/aegis-dashboard")


if __name__ == "__main__":
    main()
