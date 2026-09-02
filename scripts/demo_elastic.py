"""End-to-end demo: synthetic alerts → Aegis pipeline → ES → Kibana.

Usage:
    python scripts/demo_elastic.py
    (requires ES running at configured host, AEGIS_STORE=es)
"""

import sys
import time

sys.path.insert(0, "src")

from elasticsearch import Elasticsearch

from aegis.config import get_settings
from aegis.integrations.elastic_adapter import ElasticAlertPoller, generate_synthetic_alerts


def main():
    settings = get_settings()
    es = Elasticsearch(
        settings.es_host,
        basic_auth=(settings.es_user, settings.es_password),
        verify_certs=settings.es_verify_certs,
        request_timeout=30,
    )

    # Check ES
    try:
        info = es.info()
        print(f"ES connected: {info['version']['number']}")
    except Exception as e:
        print(f"Cannot reach ES at {settings.es_host}: {e}")
        sys.exit(1)

    alert_index = settings.es_alert_index
    print(f"Alert index: {alert_index}")

    # Step 1: Generate synthetic alerts
    print("\n--- Step 1: Generating synthetic alerts ---")
    written = generate_synthetic_alerts(es=es, index=alert_index, count=3)
    print(f"Generated {written} synthetic alerts")

    # Step 2: Poll once
    print("\n--- Step 2: Polling for new alerts ---")
    from aegis.incidents.store import InMemoryStore
    store = InMemoryStore()
    poller = ElasticAlertPoller(es=es, alert_index=alert_index, store=store)
    incidents = poller.poll_once()
    print(f"Ingested {len(incidents)} incidents:")
    for inc in incidents:
        print(f"  {inc.id} | {inc.type} | {inc.severity} | {inc.state.value}")

    # Step 3: Run investigation on each
    print("\n--- Step 3: Running investigations ---")
    import aegis.slice as sl
    from aegis.integrations.llm import LLMClient

    llm = LLMClient(settings.llm_base_url, settings.llm_model)
    for inc in incidents:
        print(f"\nInvestigating {inc.id}...")
        res = sl.investigate(store, inc.id, llm)
        if res["ok"]:
            print(f"  State: {res['incident'].state.value}")
            print(f"  Policy: {res['decision'].decision.value} ({res['decision'].reason})")
            print(f"  Evidence: {len(res.get('results', {}))} agent results")
        else:
            print(f"  Failed: {res.get('errors')}")

    # Step 4: Summary
    print("\n--- Step 4: Summary ---")
    for inc_id in store.all_incident_ids():
        inc = store.get(inc_id)
        ev = store.evidence(inc_id)
        print(f"  {inc.id}: {inc.state.value} | {len(ev)} evidence | {inc.severity}")

    print(f"\nDone. Open Kibana at http://localhost:5601 to view dashboards.")
    print(f"Or view the console at http://localhost:8000/")


if __name__ == "__main__":
    main()
