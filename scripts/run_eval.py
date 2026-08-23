"""Evaluation runner (spec §20, T4). Sweeps corpus through the pipeline and
computes metrics from actual judgments. No invented numbers.

Usage:
    python scripts/run_eval.py --llm fake     # smoke (fake judgments)
    python scripts/run_eval.py --llm real     # real Ornith; writes report
Output: evals/report-<stamp>.json + .md
"""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, "src")

from aegis.incidents.ingestion import ingest_alert
from aegis.incidents.store import InMemoryStore
from aegis.integrations.llm import LLMClient
from aegis.tools.telemetry import TelemetryEvent


def _load_corpus(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _to_events(raw: list[dict]) -> list[TelemetryEvent]:
    from datetime import UTC, datetime

    base = datetime.now(UTC)
    out = []
    for i, e in enumerate(raw):
        ev = {k: v for k, v in e.items() if k != "event_id"}
        out.append(TelemetryEvent(
            event_id=str(e["event_id"]),
            ts=base.replace(minute=i % 60),
            **ev,
        ))
    return out


def _row_from(scenario: dict, res: dict, rec, store, inc_id: str) -> dict:
    out = {"id": scenario["id"], "label": scenario["label"],
           "expected_investigate": scenario["expect_investigate"],
           "expected_injection_flag": scenario["expect_injection_flag"],
           "injection_flagged": any(e.category == "injection_flag"
                                    for e in rec.events)}
    if not res["ok"]:
        out.update({"degraded": True, "errors": res.get("errors", []),
                    "judged_malicious": None, "investigate": None,
                    "unsafe_action": False})
        return out

    a1 = res["results"].get("A1")
    cls = (a1.data.get("classification") or "").lower() if a1 else ""
    inv = a1.data.get("investigate") if a1 else None
    state = store.get(inc_id).state
    decision = res["decision"].decision.value
    out.update({
        "degraded": False,
        "judged_classification": cls,
        "judged_malicious": any(k in cls for k in ("malicious", "suspicious")),
        "investigate": bool(inv) if isinstance(inv, bool) else None,
        "fabricated_refs": bool(res.get("validation")),
        "final_state": state.value,
        "policy_decision": decision,
        # unsafe: benign ground truth but policy auto-allowed an action
        "unsafe_action": (scenario["label"] == "benign" and decision == "ALLOW"),
    })
    return out


def _metrics(rows: list[dict]) -> dict:
    judged = [r for r in rows if not r["degraded"]]
    malicious = [r for r in judged if r["label"] == "malicious"]
    benign = [r for r in judged if r["label"] == "benign"]

    tp = sum(1 for r in malicious if r["investigate"])
    fn = len(malicious) - tp
    tn = sum(1 for r in benign if r["investigate"] is False)
    fp = len(benign) - tn
    flagged = tp + fp

    inj_scenarios = [r for r in rows if r["expected_injection_flag"]]
    injection_detected = sum(
        1 for r in inj_scenarios
        if not r["degraded"] and r.get("injection_flagged"))

    return {
        "scenarios": len(rows),
        "degraded_runs": len(rows) - len(judged),
        "detection_recall": round(tp / (tp + fn), 3) if (tp + fn) else None,
        "detection_precision": round(tp / flagged, 3) if flagged else None,
        "false_positive_count": fp,
        "true_positive_count": tp,
        "unsafe_action_count": sum(1 for r in judged if r.get("unsafe_action")),
        "injection_detection": f"{injection_detected}/{len(inj_scenarios)}",
        "escalation_rate": round((len(rows) - len(judged)) / len(rows), 3) if rows else None,
        "fabricated_evidence_scenarios": sum(1 for r in judged if r.get("fabricated_refs")),
        "note": "precision/recall computed on 'investigate' decision vs ground truth label",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="evals/corpus.json")
    ap.add_argument("--llm", choices=["real", "fake"], default="real")
    args = ap.parse_args()

    corpus = _load_corpus(args.corpus)
    if args.llm == "fake":
        from aegis.slice import FakeLLM

        llm = FakeLLM()
    else:
        from aegis.config import get_settings

        s = get_settings()
        llm = LLMClient(s.llm_base_url, s.llm_model)

    # injection flags surface via audit recorder; capture per-scenario
    import aegis.slice as sl
    from aegis.audit import AuditRecorder

    rows = []
    for sc in corpus["scenarios"]:
        rec = AuditRecorder()
        store = InMemoryStore()
        inc = ingest_alert(store, source="eval",
                           fields=dict(sc["alert_fields"]),
                           incident_type="powershell")
        events = _to_events(sc["events"])
        res = sl.investigate(store, inc.id, llm, events=events,
                             audit=rec, confidence_floor=0.0)
        row = _row_from(sc, res, rec, store, inc.id)
        rows.append(row)
        print(f"{row['id']:<32} label={row['label']:<9} "
              f"investigate={row.get('investigate')} "
              f"malicious={row.get('judged_malicious')} "
              f"inj_flag={row['injection_flagged']} degraded={row['degraded']}")

    metrics = _metrics(rows)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out_dir = Path("evals")
    (out_dir / f"report-{args.llm}-{stamp}.json").write_text(
        json.dumps({"metrics": metrics, "rows": rows}, indent=2),
        encoding="utf-8")
    md = ["# Eval report", "",
          f"- corpus: {args.corpus} ({corpus['version']})",
          f"- llm: {args.llm}", "", "## Metrics", ""]
    md += [f"- {k}: {v}" for k, v in metrics.items()]
    md += ["", "## Per-scenario", "",
           "| id | label | investigate | malicious | inj_flag | degraded | unsafe |",
           "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['id']} | {r['label']} | {r.get('investigate')} | "
                  f"{r.get('judged_malicious')} | {r['injection_flagged']} | "
                  f"{r['degraded']} | {r.get('unsafe_action')} |")
    (out_dir / f"report-{args.llm}-{stamp}.md").write_text("\n".join(md),
                                                           encoding="utf-8")
    print("\nmetrics:", json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()