#!/usr/bin/env python3
"""Run the triage agent over the labelled dataset with several OpenRouter models and score them.

    OPENROUTER_API_KEY=... INDEXER_PASSWORD=... python3 run_eval.py --model deepseek/deepseek-v4.1-flash \
        --model qwen/qwen3.8-27b [--limit 5]

Scoring (per model):
  recall       malicious alerts called true_positive or needs_escalation (the alert reaches a human)
  strict TP    malicious alerts called true_positive
  specificity  benign alerts called benign
  FP rate      benign alerts called true_positive
  technique    malicious alerts with the right ATT&CK ID (v19 or legacy; parent technique counts)
Writes results/<run>/results.jsonl (one line per alert per model) and results/<run>/summary.md.
"""
import argparse
import asyncio
import datetime as dt
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from agent import openrouter_client, triage  # noqa: E402


def technique_ok(item: dict, predicted: str | None) -> bool:
    if not predicted:
        return False
    # Exact sub-technique or its parent counts (v19 or legacy ID); a sibling sub-technique doesn't
    truth = {t for t in (item["technique"], item.get("legacy")) if t}
    truth |= {t.split(".")[0] for t in truth}
    return predicted.strip().upper() in truth


def score(rows: list[dict]) -> dict:
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    pct = lambda n, d: round(100 * n / d, 1) if d else None  # noqa: E731
    return {
        "alerts": len(rows),
        "recall_pct": pct(sum(r["verdict"] in ("true_positive", "needs_escalation") for r in mal), len(mal)),
        "strict_tp_pct": pct(sum(r["verdict"] == "true_positive" for r in mal), len(mal)),
        "specificity_pct": pct(sum(r["verdict"] == "benign" for r in ben), len(ben)),
        "fp_rate_pct": pct(sum(r["verdict"] == "true_positive" for r in ben), len(ben)),
        "technique_pct": pct(sum(r["technique_ok"] for r in mal), len(mal)),
        "avg_tool_calls": round(statistics.mean(r["tool_calls"] for r in rows), 1) if rows else None,
        "median_latency_s": round(statistics.median(r["latency_s"] for r in rows), 1) if rows else None,
        "cost_usd": round(sum(r["cost_usd"] for r in rows), 4),
        "cost_per_alert_usd": round(sum(r["cost_usd"] for r in rows) / len(rows), 5) if rows else None,
        "invalid_responses": sum(bool(r.get("error")) for r in rows),
    }


async def run_model(model: str, items: list[dict], out, concurrency: int) -> list[dict]:
    client = openrouter_client()
    sem = asyncio.Semaphore(concurrency)
    rows = []

    async def one(item):
        async with sem:
            try:
                report = await triage(item["alert"], model, client)
            except Exception as exc:  # a provider error on one alert shouldn't sink the whole run
                report = {"verdict": "error", "attack_technique": None, "confidence": 0, "summary": str(exc)[:300],
                          "tool_calls": [], "latency_s": 0, "cost_usd": 0.0, "error": "exception"}
        row = {"model": model, "id": item["id"], "label": item["label"], "technique": item["technique"],
               "legacy": item.get("legacy"), "rule": item["alert"]["rule"]["id"], "source": item["source"],
               "verdict": report["verdict"], "predicted_technique": report.get("attack_technique"),
               "technique_ok": item["label"] == "malicious" and technique_ok(item, report.get("attack_technique")),
               "confidence": report.get("confidence"), "summary": report.get("summary"),
               "tool_calls": len(report.get("tool_calls", [])), "latency_s": report.get("latency_s", 0),
               "cost_usd": report.get("cost_usd", 0.0), "error": report.get("error")}
        out.write(json.dumps(row) + "\n")
        out.flush()
        print(f"  [{model}] {item['label']:9s} rule {row['rule']:>6} -> {row['verdict']:16s} "
              f"{row['predicted_technique'] or '-':10s} {row['latency_s']}s", flush=True)
        rows.append(row)

    await asyncio.gather(*(one(i) for i in items))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", action="append", required=True)
    parser.add_argument("--dataset", default=str(HERE / "dataset.jsonl"))
    parser.add_argument("--limit", type=int, help="only the first N alerts (smoke test)")
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--run", default=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M"))
    args = parser.parse_args()

    items = [json.loads(line) for line in Path(args.dataset).read_text().splitlines() if line.strip()]
    if args.limit:
        items = items[: args.limit]
    out_dir = HERE / "results" / args.run
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {}
    with (out_dir / "results.jsonl").open("a") as out:
        for model in args.model:
            print(f"== {model} ({len(items)} alerts)", flush=True)
            summary[model] = score(asyncio.run(run_model(model, items, out, args.concurrency)))

    labels = {lbl: sum(i["label"] == lbl for i in items) for lbl in ("malicious", "benign")}
    lines = [f"# Triage eval {args.run}", "",
             f"{labels['malicious']} malicious and {labels['benign']} benign alerts from the lab "
             "(see triage/eval/README.md for how they were labelled).", "",
             "| Model | Recall | Strict TP | Specificity | FP rate | Technique | Tool calls | Median latency | $/alert | Total $ | Invalid |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for model, s in summary.items():
        lines.append(f"| `{model}` | {s['recall_pct']}% | {s['strict_tp_pct']}% | {s['specificity_pct']}% | "
                     f"{s['fp_rate_pct']}% | {s['technique_pct']}% | {s['avg_tool_calls']} | {s['median_latency_s']}s | "
                     f"{s['cost_per_alert_usd']} | {s['cost_usd']} | {s['invalid_responses']} |")
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
