"""Import Kibana saved objects (index patterns + dashboards) via API.

Usage:
    python scripts/setup_kibana.py [--kibana-url http://localhost:5601]

Requires Kibana running and accessible. Reads NDJSON files from kibana/dashboards/.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, "src")

import httpx


def import_saved_objects(kibana_url: str, ndjson_path: Path) -> bool:
    """Import a single NDJSON file into Kibana."""
    data = ndjson_path.read_bytes()
    resp = httpx.post(
        f"{kibana_url}/api/saved_objects/_import",
        files={"file": (ndjson_path.name, data, "application/ndjson")},
        headers={"kbn-xsrf": "true"},
        timeout=30,
    )
    result = resp.json()
    if result.get("success"):
        print(f"  Imported {ndjson_path.name}: {result.get('successCount', '?')} objects")
        return True
    else:
        print(f"  FAILED {ndjson_path.name}: {result.get('errors', [])}")
        return False


def create_index_pattern(kibana_url: str, index_pattern_id: str, title: str) -> bool:
    """Create a Kibana data view (index pattern) if it doesn't exist."""
    # Check if exists
    resp = httpx.get(
        f"{kibana_url}/api/data_views/data_view/{index_pattern_id}",
        headers={"kbn-xsrf": "true"},
        timeout=10,
    )
    if resp.status_code == 200:
        print(f"  Index pattern '{index_pattern_id}' already exists")
        return True

    # Create
    resp = httpx.post(
        f"{kibana_url}/api/data_views/data_view",
        headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
        json={
            "data_view": {
                "id": index_pattern_id,
                "title": title,
                "timeFieldName": "@timestamp",
            }
        },
        timeout=10,
    )
    if resp.status_code in (200, 409):
        print(f"  Created index pattern '{index_pattern_id}' → {title}")
        return True
    print(f"  FAILED to create index pattern: {resp.text[:200]}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Setup Kibana dashboards for Aegis")
    parser.add_argument("--kibana-url", default="http://localhost:5601")
    args = parser.parse_args()

    kibana_url = args.kibana_url
    print(f"Kibana URL: {kibana_url}")

    # Check Kibana
    try:
        resp = httpx.get(f"{kibana_url}/api/status", timeout=5)
        status = resp.json().get("status", {}).get("overall", {}).get("level", "unknown")
        print(f"Kibana status: {status}")
    except Exception as e:
        print(f"Cannot reach Kibana at {kibana_url}: {e}")
        sys.exit(1)

    # Create index patterns
    print("\n--- Index Patterns ---")
    patterns = [
        ("aegis-incidents", "aegis-dev-incidents"),
        ("aegis-steps", "aegis-dev-steps"),
        ("aegis-audit", "aegis-dev-audit"),
        ("aegis-alerts", "aegis-dev-alerts"),
    ]
    for pid, title in patterns:
        create_index_pattern(kibana_url, pid, title)

    # Import dashboards
    dashboard_dir = Path(__file__).resolve().parents[1] / "kibana" / "dashboards"
    if dashboard_dir.exists():
        print("\n--- Dashboards ---")
        ndjson_files = sorted(dashboard_dir.glob("*.ndjson"))
        if not ndjson_files:
            print("  No .ndjson files found in kibana/dashboards/")
        else:
            success = 0
            for f in ndjson_files:
                if import_saved_objects(kibana_url, f):
                    success += 1
            print(f"\n  {success}/{len(ndjson_files)} dashboard files imported")
    else:
        print(f"\n  Dashboard directory not found: {dashboard_dir}")
        print("  Build dashboards in Kibana UI, export NDJSON, save to kibana/dashboards/")

    print("\nDone. Open Kibana → Dashboards → Aegis.")


if __name__ == "__main__":
    main()
