"""Tests for the Elastic Security alert adapter."""

from unittest.mock import MagicMock

from aegis.integrations.elastic_adapter import (
    ElasticAlertPoller,
    _map_severity,
    generate_synthetic_alerts,
    normalize_elastic_alert,
)


class TestNormalizeElasticAlert:
    def test_full_ecs_document(self):
        doc = {
            "rule": {"name": "Suspicious Process", "id": "rule-1", "severity": 80},
            "host": {"name": "DC01"},
            "user": {"name": "Administrator"},
            "process": {"name": "mimikatz.exe", "pid": 4212, "command_line": "mimikatz.exe"},
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "10.0.0.2"},
            "file": {"path": "C:\\temp\\mimikatz.exe"},
            "@timestamp": "2026-01-01T00:00:00Z",
        }
        result = normalize_elastic_alert(doc)
        assert result["host"] == "DC01"
        assert result["user"] == "Administrator"
        assert result["process"] == "mimikatz.exe"
        assert result["pid"] == 4212
        assert result["source_ip"] == "10.0.0.1"
        assert result["destination_ip"] == "10.0.0.2"
        assert result["file_path"] == "C:\\temp\\mimikatz.exe"
        assert result["severity"] == "high"
        assert result["type"] == "Suspicious Process"

    def test_minimal_document(self):
        doc = {}
        result = normalize_elastic_alert(doc)
        assert result["host"] == "unknown"
        assert result["user"] == "unknown"
        assert result["process"] == "unknown"
        assert result["severity"] == "medium"  # default
        assert result["type"] == "elastic-alert"


class TestMapSeverity:
    def test_numeric_high(self):
        assert _map_severity(80) == "high"
        assert _map_severity(100) == "high"

    def test_numeric_medium(self):
        assert _map_severity(50) == "medium"
        assert _map_severity(40) == "medium"

    def test_numeric_low(self):
        assert _map_severity(10) == "low"
        assert _map_severity(0) == "low"

    def test_keyword_mapping(self):
        assert _map_severity("critical") == "high"
        assert _map_severity("high") == "high"
        assert _map_severity("medium") == "medium"
        assert _map_severity("low") == "low"

    def test_unknown_keyword(self):
        assert _map_severity("info") == "medium"
        assert _map_severity(None) == "medium"


class TestElasticAlertPoller:
    def test_poll_once_marks_ingested(self):
        es = MagicMock()
        es.search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "alert-1",
                        "_source": {
                            "rule.name": "Test Alert",
                            "rule.severity": 50,
                            "host.name": "HOST01",
                            "@timestamp": "2026-01-01T00:00:00Z",
                        },
                    }
                ]
            }
        }
        store = MagicMock()
        poller = ElasticAlertPoller(es=es, alert_index="test-alerts", store=store)

        incidents = poller.poll_once()

        assert len(incidents) == 1
        store.create.assert_called_once()
        es.update.assert_called_once()
        update_call = es.update.call_args
        assert update_call[1]["body"]["doc"]["aegis_ingested"] is True

    def test_poll_once_empty(self):
        es = MagicMock()
        es.search.return_value = {"hits": {"hits": []}}
        store = MagicMock()
        poller = ElasticAlertPoller(es=es, alert_index="test-alerts", store=store)

        incidents = poller.poll_once()

        assert len(incidents) == 0
        store.create.assert_not_called()

    def test_poll_once_es_error(self):
        es = MagicMock()
        es.search.side_effect = Exception("ES unreachable")
        store = MagicMock()
        poller = ElasticAlertPoller(es=es, alert_index="test-alerts", store=store)

        incidents = poller.poll_once()

        assert len(incidents) == 0


class TestGenerateSyntheticAlerts:
    def test_generates_alerts(self):
        es = MagicMock()
        es.indices.exists.return_value = True
        count = generate_synthetic_alerts(es=es, index="test-alerts", count=3)
        assert count == 3
        assert es.index.call_count == 3

    def test_creates_index_if_missing(self):
        es = MagicMock()
        es.indices.exists.return_value = False
        count = generate_synthetic_alerts(es=es, index="test-alerts", count=2)
        assert count == 2
        es.indices.create.assert_called_once()

    def test_respects_count_limit(self):
        es = MagicMock()
        es.indices.exists.return_value = True
        count = generate_synthetic_alerts(es=es, index="test-alerts", count=100)
        assert count == 5  # max synthetic alerts
