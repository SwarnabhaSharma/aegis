"""Elasticsearch telemetry source (live winlogbeat-* on VM). Read-only."""

from datetime import UTC, datetime

from elasticsearch import Elasticsearch

from aegis.tools.telemetry import TelemetryEvent, TelemetrySource


class ElasticsearchTelemetry(TelemetrySource):
    def __init__(self, es: Elasticsearch, index: str = ".ds-winlogbeat-9.3.2-*") -> None:
        self._es = es
        self._index = index

    def _search(self, query: dict, limit: int) -> list[TelemetryEvent]:
        body = {"query": query, "size": limit, "sort": [{"@timestamp": {"order": "desc"}}]}
        resp = self._es.search(index=self._index, body=body)
        return [self._to_event(hit) for hit in resp["hits"]["hits"]]

    @staticmethod
    def _parse_ts(value: str) -> datetime:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            # already has offset (+00:00) or is local naive
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return datetime.now(UTC)

    @staticmethod
    def _to_event(hit) -> TelemetryEvent:
        src = hit["_source"]
        win = src.get("winlog", {})
        proc = src.get("process", {})
        dest = src.get("destination", {})
        return TelemetryEvent(
            event_id=str(win.get("event_id", "")),
            channel=win.get("channel", ""),
            action=src.get("event", {}).get("action", ""),
            host=src.get("host", {}).get("name", ""),
            user=src.get("user", {}).get("name", ""),
            process_name=proc.get("name", ""),
            process_pid=str(proc.get("pid", "")),
            process_parent=proc.get("parent", {}).get("name", ""),
            process_parent_pid=str(proc.get("parent", {}).get("pid", "")),
            destination_ip=dest.get("ip", ""),
            destination_port=str(dest.get("port", "")),
            file_path=src.get("file", {}).get("path", ""),
            command_line=proc.get("command_line", "") or src.get("process", {}).get("args", ""),
            ts=ElasticsearchTelemetry._parse_ts(src.get("@timestamp", "")),
            raw=src,
        )

    def search_events(self, *, host=None, event_id=None, process_name=None,
                      user=None, limit=50) -> list[TelemetryEvent]:
        must = []
        if host:
            must.append({"match": {"host.name": host.lower()}})
        if event_id:
            must.append({"term": {"winlog.event_id": event_id}})
        if process_name:
            must.append({"match": {"process.name": process_name}})
        if user:
            must.append({"match": {"user.name": user}})
        return self._search({"bool": {"must": must}}, limit)

    def get_process_tree(
        self, host: str, pid: str | None = None, limit: int = 100
    ) -> list[TelemetryEvent]:
        must = [{"match": {"host.name": host.lower()}}, {"term": {"winlog.event_id": "1"}}]
        if pid:
            must.append({"term": {"process.pid": pid}})
        return self._search({"bool": {"must": must}}, limit)

    def get_network_connections(self, host: str, limit: int = 100) -> list[TelemetryEvent]:
        return self._search(
            {"bool": {"must": [
                {"match": {"host.name": host.lower()}},
                {"term": {"winlog.event_id": "3"}},
            ]}},
            limit,
        )
