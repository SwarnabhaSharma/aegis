"""CLI shim for the slice orchestration core (aegis.slice)."""

import argparse
import sys

sys.path.insert(0, "src")

from aegis.slice import run_full_slice as run_slice  # noqa: E402  (re-export)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=None)
    ap.add_argument("--llm", choices=["real", "fake"], default="real")
    ap.add_argument("--telemetry", choices=["synthetic", "real"], default="synthetic")
    ap.add_argument("--confidence", type=float, default=0.95)
    ap.add_argument("--evidence-count", type=int, default=4)  # compat, unused
    args = ap.parse_args()
    host = args.host or ("swarnabhasharma" if args.telemetry == "real" else "win-vm")

    res = run_slice(host=host, llm_mode=args.llm, confidence=args.confidence,
                    evidence_count=args.evidence_count,
                    telemetry_mode=args.telemetry)

    if res.get("incident") is None:
        for err in res.get("errors", []):
            print(f"blocked: {err}")
        sys.exit(1)
    for err in res.get("errors", []):
        print(f"degraded: {err}")
    print(f"final state: {res['incident'].state.value}")
    print(f"trace: {' -> '.join(res['trace'])}")
    print(f"evidence persisted: {res.get('evidence_count', 0)}")
    for r in res.get("related", []):
        if "shared" in r:  # legacy scan format
            print(f"related: {r['incident_id']} shares {', '.join(r['shared'])}")
        else:  # graph edge format (WP-C)
            print(f"related: {r['src_id']} -> {r['dst_id']} "
                  f"[{r.get('relationship', 'SHARED_INDICATOR')}]")
    if "decision" in res:
        d = res["decision"]
        print(f"policy: {d.decision.value} ({d.reason})")
    for v in res.get("verifications", []):
        print(f"verify {v.action} {v.target}: {v.actual} passed={v.passed}")
