#!/usr/bin/env python3
"""Build the labelled triage eval set from what the lab already knows to be true.

malicious  alerts of a test's expected rules inside that test's window in a validation run
           (validation/results/<label>.json), labelled with the test's ATT&CK technique
benign     level >= 8 alerts inside the benign-activity window (lab/windows/benign-activity.ps1):
           routine admin activity that trips the same rules

    INDEXER_PASSWORD=... python3 build_dataset.py --validation ../../validation/results/validation.json \
        --validation ../../validation/results/validation-run2.json --benign-window benign-window.json
"""
import argparse
import json
import os
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # installer's self-signed cert
HERE = Path(__file__).resolve().parent
SKIP_GROUPS = {"lab_harness", "purplelab_triage"}


def search(args, filters: list[dict], size: int = 200) -> list[dict]:
    body = {"size": size, "sort": [{"timestamp": "asc"}], "query": {"bool": {"filter": filters}}}
    resp = requests.post(f"{args.indexer}/wazuh-alerts-*/_search", json=body,
                         auth=(args.user, os.environ["INDEXER_PASSWORD"].strip("\r\n")), verify=False, timeout=30)
    resp.raise_for_status()
    return [h["_source"] for h in resp.json()["hits"]["hits"]]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--validation", action="append", required=True, help="validation results JSON (repeatable)")
    parser.add_argument("--benign-window", required=True, help='JSON {"start": iso, "end": iso}')
    parser.add_argument("--agent", default="win11-ep")
    parser.add_argument("--indexer", default="https://127.0.0.1:9200")
    parser.add_argument("--user", default=os.environ.get("INDEXER_USER", "admin"))
    parser.add_argument("--out", default=str(HERE / "dataset.jsonl"))
    args = parser.parse_args()

    items: dict[str, dict] = {}
    for path in args.validation:
        run = json.loads(Path(path).read_text())
        for test in run["results"]:
            alerts = search(args, [
                {"term": {"agent.name": args.agent}},
                {"terms": {"rule.id": [str(r) for r in test.get("expect") or []]}},
                {"range": {"timestamp": {"gte": test["window"][0], "lte": test["window"][1]}}},
            ])
            for a in alerts:
                items[a["id"]] = {"id": a["id"], "label": "malicious", "technique": test["technique"],
                                  "legacy": test.get("legacy"), "source": f"{run['label']} {test['technique']} #{test['test']}",
                                  "alert": a}

    window = json.loads(Path(args.benign_window).read_text())
    for a in search(args, [
        {"term": {"agent.name": args.agent}},
        {"range": {"rule.level": {"gte": 8}}},
        {"range": {"timestamp": {"gte": window["start"], "lte": window["end"]}}},
    ], size=500):
        if SKIP_GROUPS & set(a["rule"].get("groups", [])):
            continue
        items[a["id"]] = {"id": a["id"], "label": "benign", "technique": None, "legacy": None,
                          "source": "benign-activity", "alert": a}

    with open(args.out, "w") as f:
        for item in items.values():
            f.write(json.dumps(item) + "\n")
    by_label: dict[str, list[str]] = {}
    for item in items.values():
        by_label.setdefault(item["label"], []).append(item["alert"]["rule"]["id"])
    for label, rules in sorted(by_label.items()):
        print(f"{label}: {len(rules)} alerts, rules {sorted(set(rules))}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
