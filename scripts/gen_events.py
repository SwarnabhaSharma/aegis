"""Synthetic telemetry generator (ADR-012). Writes realistic Sysmon-mirroring
events into ES `telemetry-*` so read tools have data with no VM/agent needed.

Schema mirrors real winlogbeat fields (host.name, winlog.event_id, event.action,
process.name/pid, destination.ip/port, file.path) for drop-in compatibility.

Usage:
    python scripts/gen_events.py [--count N] [--host NAME] [--scenario powershell]
"""

import argparse
import json
from datetime import UTC, datetime

from elasticsearch import Elasticsearch

from aegis.config import get_settings

INDEX = "telemetry-synthetic-2026.08"


def _event(ts, host, event_id, action, process, pid, **extra):
    process_extra = {}
    if "process_parent" in extra:
        process_extra["parent"] = extra.pop("process_parent")
    if "command_line" in extra:
        process_extra["command_line"] = extra.pop("command_line")
    base = {
        "@timestamp": ts.isoformat(),
        "host": {"name": host},
        "winlog": {"event_id": event_id, "channel": "Microsoft-Windows-Sysmon/Operational"},
        "event": {"action": action, "code": event_id, "module": "sysmon"},
        "process": {"name": process, "pid": str(pid), **process_extra},
        "agent": {"name": host, "type": "synthetic"},
    }
    base.update(extra)
    return json.dumps(base, default=str)


def gen_powershell_attack(host: str, n: int = 5) -> list[str]:
    """PowerShell execution slice: office -> encoded PS -> C2 -> file write."""
    docs = []
    now = datetime.now(UTC)
    for i in range(n):
        pid = 1000 + i
        docs.append(_event(
            now, host, "1", "ProcessCreate", "powershell.exe", str(pid),
            file={"path": "C:\\Users\\test\\evil.ps1"},
            process_parent={"name": "WINWORD.EXE", "pid": "500"},
            command_line="powershell -enc SQBFAFA7AFIA",
        ))
        docs.append(_event(
            now, host, "3", "NetworkConnect", "powershell.exe", str(pid),
            destination={"ip": "185.220.101.4", "port": "443"},
        ))
        docs.append(_event(
            now, host, "11", "FileCreate", "powershell.exe", str(pid),
            file={"path": "C:\\ProgramData\\payload.dll"},
        ))
    return docs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--host", default="win-vm")
    ap.add_argument("--scenario", choices=["powershell"], default="powershell")
    args = ap.parse_args()

    s = get_settings()
    es = Elasticsearch(s.es_host, basic_auth=(s.es_user, s.es_password),
                       verify_certs=s.es_verify_certs, request_timeout=30)
    docs = gen_powershell_attack(args.host, args.count)
    actions: list = []
    for d in docs:
        actions.append({"index": {"_index": INDEX}})
        actions.append(json.loads(d))
    resp = es.bulk(operations=actions)
    print(
        f"indexed {len(docs)} synthetic events into {INDEX} "
        f"(host={args.host}, errors={resp.get('errors')})"
    )


if __name__ == "__main__":
    main()