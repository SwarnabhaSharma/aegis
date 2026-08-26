"""Download + normalize MITRE ATT&CK enterprise matrix into a committed data file.

Build-time only; runtime never touches the network. Output:
    data/attack-techniques.json
    {version, source, generated_at, technique_count,
     techniques: [{id, name, tactics, description, keywords}]}

Usage: python scripts/update_attack_data.py
"""

import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

STIX_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
            "enterprise-attack/enterprise-attack.json")
OUT = Path(__file__).resolve().parent.parent / "data" / "attack-techniques.json"

_STOP = set("""a an and the of for to in on with via from by at as is are be
using used use that this it its into over new more than can could may might
which who whom what when where how why not no nor but or if then else so than
too very s t just don should now their they them there these those about
against between through during before after above below out off up down
""".split())

_WORD = re.compile(r"[a-zA-Z]{3,}")


def _keywords(name: str, description: str) -> dict[str, list[str]]:
    """Split match tokens: name words (strong signal) vs description words
    (weak signal). Runtime weights them 3:1."""
    name_tokens = sorted({w.lower() for w in _WORD.findall(name)} - _STOP)
    freq: dict[str, int] = {}
    for w in (w.lower() for w in _WORD.findall(description)):
        freq[w] = freq.get(w, 0) + 1
    strong_desc = sorted(w for w, c in freq.items()
                         if c >= 2 or len(w) >= 9)[:14]
    return {"name": name_tokens, "desc": [w for w in strong_desc
                                          if w not in name_tokens]}


def _technique_id(att_obj: dict) -> str | None:
    for ref in att_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _tactics(att_obj: dict) -> list[str]:
    return [p["phase_name"] for p in att_obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"]


def main() -> None:
    import httpx

    print(f"downloading {STIX_URL} ...")
    resp = httpx.get(STIX_URL, timeout=120, follow_redirects=True)
    resp.raise_for_status()
    bundle = resp.json()

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _technique_id(obj)
        if not tid:
            continue
        name = obj.get("name", "").strip()
        description = obj.get("description", "") or ""
        kw = _keywords(name, description)
        techniques.append({
            "id": tid,
            "name": name,
            "tactics": _tactics(obj),
            "description": description[:600],
            "kw_name": kw["name"],
            "kw_desc": kw["desc"],
        })

    techniques.sort(key=lambda t: t["id"])
    payload = {
        "version": "1",
        "source": STIX_URL,
        "generated_at": datetime.now(UTC).isoformat(),
        "technique_count": len(techniques),
        "techniques": techniques,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print(f"wrote {OUT} ({len(techniques)} techniques)")


if __name__ == "__main__":
    sys.exit(main())
