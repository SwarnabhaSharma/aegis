"""Shared infrastructure wiring — single source for store, ES client, telemetry.

Both api.py and slice.py import from here. Change store construction once,
not in lockstep across two files.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from elasticsearch import Elasticsearch

from aegis.config import get_settings

_es_singleton: Elasticsearch | None = None


def make_store():
    """Store per AEGIS_STORE env. Returns (store, es|None)."""
    if os.getenv("AEGIS_STORE") == "es":
        from elasticsearch import Elasticsearch

        from aegis.incidents.es_store import ElasticsearchStore

        s = get_settings()
        es = Elasticsearch(
            s.es_host, basic_auth=(s.es_user, s.es_password),
            verify_certs=s.es_verify_certs, request_timeout=60,
        )
        return ElasticsearchStore(es), es
    from aegis.incidents.store import InMemoryStore

    return InMemoryStore(), None


def get_es_client() -> Elasticsearch:
    """Shared ES client singleton."""
    global _es_singleton
    if _es_singleton is None:
        from elasticsearch import Elasticsearch

        s = get_settings()
        _es_singleton = Elasticsearch(
            s.es_host, basic_auth=(s.es_user, s.es_password),
            verify_certs=s.es_verify_certs, request_timeout=60,
        )
    return _es_singleton


def live_telemetry():
    """ES client + ElasticsearchTelemetry for live winlogbeat data."""
    from aegis.tools.es_telemetry import ElasticsearchTelemetry

    es = get_es_client()
    return es, ElasticsearchTelemetry(es)


def build_registry(controls=None):
    """Production read-tool registry backed by live winlogbeat telemetry."""
    from aegis.tools.registry import build_read_tools

    es, tel = live_telemetry()
    return es, build_read_tools(tel, controls=controls)
