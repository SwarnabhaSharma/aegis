"""Integration tests against live ES on VM. Opt-in: AEGIS_INTEGRATION=1.

Validates ES telemetry source + mapping against real winlogbeat-* index.
Run when VM up + .env has creds:
    $env:AEGIS_INTEGRATION="1"; python -m pytest tests/integration -v
"""

import os

import pytest

es = pytest.importorskip("elasticsearch")
from aegis.config import get_settings  # noqa: E402
from aegis.tools.es_telemetry import ElasticsearchTelemetry  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("AEGIS_INTEGRATION") != "1",
    reason="live-ES integration; set AEGIS_INTEGRATION=1",
)


@pytest.fixture(scope="module")
def telemetry():
    s = get_settings()
    client = es.Elasticsearch(
        s.es_host, basic_auth=(s.es_user, s.es_password),
        verify_certs=s.es_verify_certs, request_timeout=60,
    )
    yield ElasticsearchTelemetry(client)
    client.close()


def test_es_connectivity(telemetry):
    results = telemetry.search_events(limit=1)
    assert len(results) >= 1


def test_search_by_event_id(telemetry):
    results = telemetry.search_events(event_id="1", limit=10)
    for e in results:
        assert e.event_id == "1"


def test_search_by_host(telemetry):
    # host from schema: DESKTOP-BJCACOL
    results = telemetry.search_events(host="DESKTOP-BJCACOL", limit=10)
    assert len(results) >= 1
    for e in results:
        assert e.host == "desktop-bjcacol"


def test_process_tree(telemetry):
    results = telemetry.get_process_tree(host="DESKTOP-BJCACOL", limit=10)
    for e in results:
        assert e.event_id == "1"


def test_network_connections(telemetry):
    results = telemetry.get_network_connections(host="DESKTOP-BJCACOL", limit=10)
    for e in results:
        assert e.event_id == "3"