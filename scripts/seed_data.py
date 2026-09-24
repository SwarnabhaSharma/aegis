"""Seed test data for screenshots."""
import json
import urllib.request

BASE = "http://127.0.0.1:8099"

for sev in ["critical", "high", "medium", "low"]:
    data = json.dumps({
        "source": "synthetic",
        "fields": {
            "severity": sev,
            "host": "win-vm",
            "process": "powershell.exe",
            "command_line": "powershell -enc SQBFAFA7AFIA",
        },
        "incident_type": "powershell",
    }).encode()
    req = urllib.request.Request(
        f"{BASE}/incidents", data=data,
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read())
    print(f"Created: {result['id'][:12]} ({sev})")

print("Seed complete.")
