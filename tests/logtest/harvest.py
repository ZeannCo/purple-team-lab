#!/usr/bin/env python3
"""Pull the raw Windows event (data.win) behind recent alerts, to use as logtest fixtures.

The alert's data.win object is exactly the eventchannel input wazuh-logtest expects, so
fixtures are real telemetry from the lab's atomic runs rather than hand-written samples.

    INDEXER_PASSWORD=... python3 harvest.py 100140 92302 62123 > harvested.json
"""
import argparse
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # installer's self-signed cert


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("rule_ids", nargs="+")
    parser.add_argument("--indexer", default="https://127.0.0.1:9200")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--per-rule", type=int, default=5)
    parser.add_argument("--agent", default="win11-ep")
    args = parser.parse_args()

    password = os.environ.get("INDEXER_PASSWORD", "").strip("\r\n")
    out = {}
    for rule_id in args.rule_ids:
        body = {"size": args.per_rule, "sort": [{"timestamp": "desc"}],
                "_source": ["timestamp", "rule.id", "rule.description", "data.win"],
                "query": {"bool": {"filter": [{"term": {"rule.id": rule_id}},
                                              {"term": {"agent.name": args.agent}}]}}}
        resp = requests.post(f"{args.indexer}/wazuh-alerts-*/_search", json=body,
                             auth=(args.user, password), verify=False, timeout=30)
        resp.raise_for_status()
        out[rule_id] = [h["_source"] for h in resp.json()["hits"]["hits"]]
        print(f"{rule_id}: {len(out[rule_id])} events", file=sys.stderr)
    json.dump(out, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
