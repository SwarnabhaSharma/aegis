"""Embedded ATT&CK subset (Phase 7). Curated techniques for Aegis scenarios.

Static dict, zero deps, offline-deterministic (user decision). Swap for STIX
bundle when evaluation phase needs the full matrix.
"""

TECHNIQUES: dict[str, dict] = {
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "keywords": ["phish", "winword", "excel", "outlook", "macro"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "keywords": ["powershell", "-enc", "encodedcommand", "iex", "invoke-expression"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "keywords": ["base64", "obfusc", "encoded"],
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "keywords": ["https", ":443", "beacon", "c2", "post http"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["downloadstring", "downloadfile", "invoke-webrequest", "certutil"],
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "keywords": ["lsass", "mimikatz", "sekurlsa", "procdump lsass"],
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "tactic": "Persistence",
        "keywords": ["currentversion\\run", "run key", "reg add"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "keywords": ["exfil", "upload -method", "convertto-json | post"],
    },
}


def lookup(technique_id: str) -> dict | None:
    tech = TECHNIQUES.get(technique_id.upper())
    if tech is None:
        return None
    return {"id": technique_id.upper(), **tech}


def match_keywords(text: str) -> list[dict]:
    """Map free text (command lines, summaries) to candidate techniques."""
    low = text.lower()
    hits = []
    for tid, tech in TECHNIQUES.items():
        if any(kw in low for kw in tech["keywords"]):
            hits.append({"id": tid, "name": tech["name"], "tactic": tech["tactic"]})
    return hits