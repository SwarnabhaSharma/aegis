"""ATT&CK technique store (spec §14/§21). Full matrix from committed data
file (scripts/update_attack_data.py -> data/attack-techniques.json), falling
back to an embedded subset when the file is absent (offline resilience).

Runtime is offline-deterministic: no network, version recorded in manifests.
"""

import json
from pathlib import Path

_DATA_FILE = Path(__file__).resolve().parents[3] / "data" / "attack-techniques.json"
ATTACK_DATA_VERSION = "embedded-1"


def _load_matrix() -> dict[str, dict]:
    global ATTACK_DATA_VERSION
    if _DATA_FILE.exists():
        try:
            payload = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
            ATTACK_DATA_VERSION = f"stix-{payload.get('generated_at', '')[:10]}"
            return {t["id"]: t for t in payload["techniques"]}
        except (json.JSONDecodeError, KeyError):
            pass  # corrupted file -> embedded fallback below
    # ponytail: minimal offline fallback; ship data file for full coverage
    return {
        "T1566.001": {"name": "Spearphishing Attachment",
                      "tactics": ["initial-access"],
                      "keywords": ["phish", "winword", "excel", "outlook", "macro"]},
        "T1059.001": {"name": "PowerShell", "tactics": ["execution"],
                      "keywords": ["powershell", "-enc", "encodedcommand",
                                   "iex", "invoke-expression"]},
        "T1027": {"name": "Obfuscated Files or Information",
                  "tactics": ["defense-evasion"],
                  "keywords": ["base64", "obfusc", "encoded"]},
        "T1071.001": {"name": "Web Protocols", "tactics": ["command-and-control"],
                      "keywords": ["https", ":443", "beacon", "c2"]},
        "T1105": {"name": "Ingress Tool Transfer", "tactics": ["command-and-control"],
                  "keywords": ["downloadstring", "downloadfile", "invoke-webrequest", "certutil"]},
        "T1003.001": {"name": "LSASS Memory", "tactics": ["credential-access"],
                      "keywords": ["lsass", "mimikatz", "sekurlsa", "procdump lsass"]},
        "T1547.001": {"name": "Registry Run Keys", "tactics": ["persistence"],
                      "keywords": ["currentversion\\run", "run key", "reg add"]},
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"],
                  "keywords": ["exfil", "upload -method"]},
    }


TECHNIQUES: dict[str, dict] = _load_matrix()

# handcrafted command-line aliases for high-value techniques (strong signal;
# full-matrix descriptions miss short markers like "-enc")
LEGACY_ALIASES: dict[str, list[str]] = {
    "T1566.001": ["phish", "winword", "excel", "outlook", "macro"],
    "T1059.001": ["powershell", "-enc", "encodedcommand", "iex",
                  "invoke-expression"],
    "T1027": ["base64", "obfusc"],
    "T1071.001": ["beacon", ":443"],
    "T1105": ["downloadstring", "downloadfile", "invoke-webrequest", "certutil"],
    "T1003.001": ["lsass", "mimikatz", "sekurlsa", "procdump lsass"],
    "T1547.001": ["currentversion\\run", "run key"],
    "T1041": ["exfil"],
}


def lookup(technique_id: str) -> dict | None:
    tech = TECHNIQUES.get(technique_id.upper())
    if tech is None:
        return None
    return {"id": technique_id.upper(), **tech}


def match_keywords(text: str, limit: int = 12) -> list[dict]:
    """Ranked candidates. Scoring: name-keyword hit = 3, description keyword
    hit = 1, curated alias hit = 5 (short CLI markers the matrix misses)."""
    low = text.lower()
    scored: list[tuple[int, dict]] = []
    for tid, tech in TECHNIQUES.items():
        score = 0
        if any(kw in low for kw in tech.get("kw_name", [])):
            score += 3
        score += sum(1 for kw in tech.get("kw_desc", []) if kw in low)
        score += 5 * sum(1 for kw in LEGACY_ALIASES.get(tid, []) if kw in low)
        if score >= 2:
            scored.append((score, {
                "id": tid, "name": tech["name"],
                "tactics": tech.get("tactics", []),
                "score": score,
            }))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
    return [t for _, t in scored[:limit]]