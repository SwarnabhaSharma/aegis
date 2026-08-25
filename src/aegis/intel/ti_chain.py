"""TI chain (WP-G): fan-out across providers by IOC type, merge results,
degrade to local store. NVD handled separately (lookup_cve tool)."""

import httpx

from aegis.intel import ti as local_store
from aegis.intel.ti_providers import (
    FANOUT_DEFAULTS,
    PROVIDER_CLASSES,
    Provider,
    TIResult,
    is_private_ioc,
)


class TIChain:
    """Ordered provider fan-out per IOC type; local store is always last."""

    def __init__(self, providers: list[Provider]) -> None:
        self.providers = {p.name: p for p in providers}

    def lookup(self, value: str) -> dict:
        v = value.strip().lower()
        ioc_type = local_store.classify(v)

        if is_private_ioc(v):
            return TIResult(value=v, ioc_type=ioc_type, known_malicious=False,
                            confidence=0.0, category="internal-suppressed",
                            source="guard").__dict__

        order = [p for p in FANOUT_DEFAULTS.get(ioc_type, [])
                 if p in self.providers and self.providers[p].enabled]
        results: list[TIResult] = []
        errors: list[str] = []

        for name in order:
            provider = self.providers[name]
            try:
                hit = provider.cached(v)
                result = hit or provider.lookup(v, ioc_type)
                if hit is None:
                    provider.store_cache(v, result)
                results.append(result)
                if result.known_malicious:
                    break  # first confirmed malicious wins; stop spending quota
            except Exception as e:  # network/4xx/5xx -> degrade silently
                errors.append(f"{name}: {type(e).__name__}")

        if results:
            best = max(results, key=lambda r: r.confidence)
            merged = best.__dict__.copy()
            merged["provenance"] = [r.source for r in results]
            if errors:
                merged["provider_errors"] = errors
            return merged

        # local static store fallback (existing behaviour)
        base = local_store.lookup(v)
        if errors:
            base["provider_errors"] = errors
        return base


def build_chain(settings) -> tuple[TIChain, list[str]]:
    """Build chain from settings.ti_providers; returns (chain, live_names)."""
    names = [n.strip().lower() for n in settings.ti_providers.split(",") if n.strip()]
    providers: list[Provider] = []
    for name in names:
        cls = PROVIDER_CLASSES.get(name)
        if cls is None:
            continue
        key = {"abuseipdb": settings.abuseipdb_api_key,
               "virustotal": settings.vt_api_key,
               "otx": settings.otx_api_key}.get(name, "")
        providers.append(cls(key))
    return TIChain(providers), [p.name for p in providers if p.enabled]


# -- NVD (vulnerability metadata; separate from IOC reputation) --

def nvd_lookup_cve(cve_id: str, api_key: str, timeout: int = 15) -> dict:
    """CVE metadata from NVD API 2.0. Raises on HTTP/network failure."""
    cve_id = cve_id.strip().upper()
    resp = httpx.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id},
        headers={"apiKey": api_key} if api_key else {},
        timeout=timeout,
    )
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return {"cve": cve_id, "found": False, "source": "nvd"}
    item = vulns[0]["cve"]
    metrics = item.get("metrics", {})
    cvss = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = metrics[key][0].get("cvssData", {})
            break
    return {
        "cve": cve_id,
        "found": True,
        "cvss_score": cvss.get("baseScore"),
        "severity": cvss.get("baseSeverity", ""),
        "description": next((d["value"] for d in item.get("descriptions", [])
                             if d.get("lang") == "en"), ""),
        "published": item.get("published", ""),
        "source": "nvd",
    }