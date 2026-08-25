"""Threat-intelligence provider framework (WP-G, spec §15/§8).

TIProvider protocol + pluggable registry. Adding provider #N = one class
+ one env entry. Guards baked in:
- private/internal IOC ranges never leave the machine (§10)
- per-provider TTL cache + rate-limit bucket (free-tier safe)
- response text treated as untrusted downstream (§15)
- any provider failure degrades silently to the local static store

Fan-out defaults by IOC type (user-approved):
    ip     -> abuseipdb -> otx -> virustotal
    hash   -> virustotal -> otx
    domain -> otx -> virustotal
    cve    -> nvd (separate lookup_cve tool, not part of IOC chain)
"""

import ipaddress
import time
from dataclasses import dataclass

import httpx

from aegis.intel import ti as local_store
from aegis.privacy import redact


@dataclass
class TIResult:
    value: str
    ioc_type: str
    known_malicious: bool
    confidence: float
    category: str
    source: str
    raw_ref: str = ""  # provider-specific id/link; text kept out of prompts


def is_private_ioc(value: str) -> bool:
    """True for internal/private IOCs that must NOT be queried externally."""
    v = value.strip().lower()
    try:
        if local_store.classify(v) == "ip":
            addr = ipaddress.ip_address(v)
            return not addr.is_global
    except ValueError:
        return True
    return False


class _RateBucket:
    def __init__(self, calls_per_minute: int) -> None:
        self._min_interval = 60.0 / max(calls_per_minute, 1)
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last = time.monotonic()


class Provider:
    """Base: name, key, cache, rate bucket, guarded HTTP GET."""
    name = "base"
    base_url = ""
    calls_per_minute = 30

    def __init__(self, api_key: str) -> None:
        self.key = api_key
        self.enabled = bool(api_key)
        self._cache: dict[str, tuple[float, TIResult]] = {}
        self._ttl = 3600
        self._bucket = _RateBucket(self.calls_per_minute)

    def cached(self, value: str) -> TIResult | None:
        hit = self._cache.get(value)
        if hit and (time.monotonic() - hit[0]) < self._ttl:
            return hit[1]
        return None

    def store_cache(self, value: str, result: TIResult) -> None:
        self._cache[value] = (time.monotonic(), result)

    def headers(self) -> dict:
        raise NotImplementedError

    def parse(self, payload, value: str, ioc_type: str) -> TIResult:
        raise NotImplementedError

    def endpoint(self, value: str, ioc_type: str) -> str:
        raise NotImplementedError

    def lookup(self, value: str, ioc_type: str) -> TIResult:
        """Guarded remote lookup; caller handles fallback to local."""
        if not self.enabled:
            raise RuntimeError(f"{self.name}: no API key")
        self._bucket.wait()
        url = self.endpoint(value.strip().lower(), ioc_type)
        resp = httpx.get(url, headers=self.headers(), timeout=15)
        resp.raise_for_status()
        return self.parse(resp.json(), value.strip().lower(), ioc_type)


# -- concrete providers --

class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2/check"
    calls_per_minute = 20  # free tier ~1k/day
    supports = {"ip"}

    def headers(self) -> dict:
        return {"Key": self.key, "Accept": "application/json"}

    def endpoint(self, value: str, ioc_type: str) -> str:
        from urllib.parse import urlencode

        return f"{self.base_url}?{urlencode({'maxAgeInDays': 90, 'ipAddress': value})}"

    def parse(self, payload, value: str, ioc_type: str) -> TIResult:
        d = payload.get("data", {})
        score = int(d.get("abuseConfidenceScore", 0))
        return TIResult(
            value=value, ioc_type="ip",
            known_malicious=score >= 50,
            confidence=round(score / 100, 2),
            category=str(d.get("usageType", "") or ("abuse" if score >= 50 else "clean")),
            source=self.name,
        )


class VirusTotalProvider(Provider):
    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"
    calls_per_minute = 4  # free tier hard limit
    supports = {"hash"}

    def headers(self) -> dict:
        return {"x-apikey": self.key}

    def endpoint(self, value: str, ioc_type: str) -> str:
        return f"{self.base_url}/files/{value}"

    def parse(self, payload, value: str, ioc_type: str) -> TIResult:
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        engines = sum(int(v) for v in stats.values() if isinstance(v, int)) or 1
        conf = min(malicious / engines * 1.5, 0.99)
        return TIResult(
            value=value, ioc_type="hash",
            known_malicious=malicious > 0,
            confidence=round(conf, 2),
            category=(attrs.get("popular_threat_classification", {})
                      .get("suggested_threat_label", "malware" if malicious else "clean")),
            source=self.name,
        )


class OTXProvider(Provider):
    name = "otx"
    base_url = "https://otx.alienvault.com/api/v1/indicators"
    calls_per_minute = 30
    supports = {"domain", "ip", "hash"}

    def headers(self) -> dict:
        return {"X-OTX-API-KEY": self.key}

    def endpoint(self, value: str, ioc_type: str) -> str:
        section = {"domain": "domain", "ip": "IPv4", "hash": "file"}.get(ioc_type, "IPv4")
        return f"{self.base_url}/{section}/{value}/general"

    def parse(self, payload, value: str, ioc_type: str) -> TIResult:
        pulses = payload.get("pulse_info", {}).get("pulses", [])
        count = len(pulses)
        tags = sorted({t.lower() for p in pulses[:5] for t in p.get("tags", [])})
        malicious = count > 0
        conf = min(0.5 + count * 0.1, 0.95) if malicious else 0.0
        return TIResult(
            value=value, ioc_type=ioc_type,
            known_malicious=malicious,
            confidence=conf,
            category=tags[0] if tags else ("pulsed" if malicious else "clean"),
            source=self.name,
        )


PROVIDER_CLASSES = {
    "abuseipdb": AbuseIPDBProvider,
    "virustotal": VirusTotalProvider,
    "otx": OTXProvider,
}

FANOUT_DEFAULTS = {
    "ip": ["abuseipdb", "otx", "virustotal"],
    "hash": ["virustotal", "otx"],
    "domain": ["otx", "virustotal"],
}


def _redact_for_audit(text: str) -> str:
    masked, _ = redact(text)
    return masked