#!/usr/bin/env python3
"""Run the Atomic Red Team tests in tests.yml against win11-ep and record what Wazuh detected.

For each test: run it over WinRM, wait for the endpoint's alerts to be indexed, record
every rule that fired, then clean the test up. A test with `expect` rule IDs PASSes only
if all of them fired; without `expect` it is classified by what the built-in ruleset did:
  detected  an alert tagged with the test's ATT&CK technique (v19 or legacy ID) fired
  alerted   alerts fired, but none tagged with the technique
  missed    nothing fired

Secrets come from the environment: WIN_PASSWORD (endpoint labadmin) and
INDEXER_PASSWORD (Wazuh indexer admin). Run on wazuh01:

    python3 run_validation.py --label baseline [--only T1105] [--settle 60]
"""
import argparse
import datetime as dt
import functools
import http.server
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

import requests
import urllib3
import yaml

from lab_winrm import run as winrm_run

# The indexer uses the self-signed certificate the Wazuh installer generated
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HERE = Path(__file__).resolve().parent
ATOMIC_MODULE = r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
# Manager-side housekeeping, plus the lab's own tuned harness activity (detections/wazuh/9900-*)
NOISE_GROUPS = {"ossec", "sca", "syscheck", "rootcheck", "vulnerability-detector", "wazuh", "lab_harness"}
PAYLOAD_NAME = "atomic-payload.txt"


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(ts: dt.datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ps_quote(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def invoke_atomic(args, test: dict, cleanup: bool = False) -> str:
    input_args = test.get("input_args") or {}
    input_ps = ""
    if input_args:
        pairs = "; ".join(f"{ps_quote(k)} = {ps_quote(v)}" for k, v in input_args.items())
        input_ps = f" -InputArgs @{{ {pairs} }}"
    script = (
        f"Import-Module '{ATOMIC_MODULE}' -Force\n"
        f"Invoke-AtomicTest {test['technique']} -TestGuids {test['guid']}{input_ps}"
        f"{' -Cleanup' if cleanup else ''} -Confirm:$false 6>&1 2>&1 | Out-String -Width 200"
    )
    result = winrm_run(args.endpoint, args.win_user, os.environ["WIN_PASSWORD"], script)
    return (result.std_out + result.std_err).decode("utf-8", "replace").strip()


def fetch_alerts(args, start: dt.datetime, end: dt.datetime) -> list[dict]:
    body = {
        "size": 500,
        "sort": [{"timestamp": "asc"}],
        "_source": ["timestamp", "rule.id", "rule.level", "rule.description", "rule.mitre.id",
                    "rule.groups", "data.win.system.eventID", "data.win.system.channel"],
        "query": {"bool": {"filter": [
            {"term": {"agent.name": args.agent}},
            {"range": {"timestamp": {"gte": iso(start), "lte": iso(end)}}},
        ]}},
    }
    resp = requests.post(f"{args.indexer}/wazuh-alerts-*/_search", json=body,
                         auth=(args.indexer_user, os.environ["INDEXER_PASSWORD"]),
                         verify=False, timeout=30)
    resp.raise_for_status()
    alerts = [hit["_source"] for hit in resp.json()["hits"]["hits"]]
    return [a for a in alerts if not NOISE_GROUPS & set(a["rule"].get("groups", []))]


def summarize_rules(alerts: list[dict]) -> list[dict]:
    rules: dict[str, dict] = {}
    for alert in alerts:
        rule = alert["rule"]
        entry = rules.setdefault(rule["id"], {
            "id": rule["id"], "level": rule["level"], "description": rule["description"],
            "mitre": rule.get("mitre", {}).get("id", []), "count": 0})
        entry["count"] += 1
    return sorted(rules.values(), key=lambda r: (-r["level"], r["id"]))


def technique_ids(test: dict) -> set[str]:
    ids = {test["technique"]}
    if test.get("legacy"):
        ids.add(test["legacy"])
    # A rule tagged with the parent technique also counts (T1059 for T1059.001)
    ids |= {i.split(".")[0] for i in list(ids)}
    return ids


def classify(test: dict, rules: list[dict]) -> str:
    expected = {str(r) for r in test.get("expect", [])}
    if expected:
        return "PASS" if expected <= {r["id"] for r in rules} else "FAIL"
    if any(technique_ids(test) & set(r["mitre"]) for r in rules):
        return "detected"
    return "alerted" if rules else "missed"


def control_run(args, test: dict) -> set[str]:
    """Drives the same WinRM + Invoke-AtomicTest path without executing anything
    (-ShowDetailsBrief), so whatever fires is caused by the harness, not by an atomic."""
    start = utc_now() - dt.timedelta(seconds=2)
    script = (f"Import-Module '{ATOMIC_MODULE}' -Force\n"
              f"Invoke-AtomicTest {test['technique']} -TestGuids {test['guid']} -ShowDetailsBrief | Out-Null")
    winrm_run(args.endpoint, args.win_user, os.environ["WIN_PASSWORD"], script)
    time.sleep(args.settle)
    return {r["id"] for r in summarize_rules(fetch_alerts(args, start, utc_now()))}


def run_test(args, test: dict, harness: set[str]) -> dict:
    expected = {str(r) for r in test.get("expect", [])}
    start = utc_now() - dt.timedelta(seconds=2)
    output = invoke_atomic(args, test)

    # Wait for the agent -> analysisd -> indexer pipeline; stop early once expectations are met
    deadline = time.monotonic() + args.settle
    rules: list[dict] = []
    while True:
        time.sleep(10)
        rules = summarize_rules(fetch_alerts(args, start, utc_now()))
        if expected and expected <= {r["id"] for r in rules}:
            break
        if time.monotonic() >= deadline:
            break
    end = utc_now()

    # Rules the control run showed the harness causes don't count, unless a test expects them
    own = [r for r in rules if r["id"] not in harness or r["id"] in expected]
    cleanup = "" if args.skip_cleanup else invoke_atomic(args, test, cleanup=True)
    return {
        **{k: test.get(k) for k in ("technique", "legacy", "name", "test", "guid", "expect", "replay")},
        "result": classify(test, own),
        "window": [iso(start), iso(end)],
        "rules": own,
        "harness_rules": sorted({r["id"] for r in rules} - {r["id"] for r in own}),
        "executed": "Done executing test" in output,
        "output_tail": output[-1500:],
        "cleanup_tail": cleanup[-500:],
    }


def serve_payload(bind: str, port: int) -> http.server.ThreadingHTTPServer:
    """Serves the file the T1105 download test fetches, so the endpoint needs no internet."""
    root = Path(tempfile.mkdtemp(prefix="atomic-payload-"))
    (root / PAYLOAD_NAME).write_text("Harmless Atomic Red Team test payload from wazuh01.\n")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer((bind, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


RESULT_STYLE = {  # Navigator color + score per result
    "PASS": ("#31a354", 2), "detected": ("#31a354", 2),
    "alerted": ("#fdae6b", 1),
    "FAIL": ("#e6550d", 0), "missed": ("#e6550d", 0),
}


def navigator_layer(label: str, results: list[dict]) -> dict:
    # One entry per technique; the worst result wins when a technique has several tests
    order = ["missed", "FAIL", "alerted", "detected", "PASS"]
    by_tech: dict[str, dict] = {}
    for r in results:
        cur = by_tech.get(r["technique"])
        if cur is None or order.index(r["result"]) < order.index(cur["result"]):
            by_tech[r["technique"]] = r
    techniques = []
    for tech, r in sorted(by_tech.items()):
        color, score = RESULT_STYLE[r["result"]]
        tests = [x for x in results if x["technique"] == tech]
        comment = "; ".join(f"#{x['test']} {x['result']}: " + (", ".join(
            f"{y['id']} (L{y['level']})" for y in x["rules"][:4]) or "no alerts") for x in tests)
        techniques.append({"techniqueID": tech, "score": score, "color": color, "comment": comment,
                           "enabled": True, "showSubtechniques": True})
    return {
        "name": f"purple-team-lab {label}",
        "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Atomic Red Team tests on win11-ep vs. Wazuh 4.14 detections",
        "techniques": techniques,
        "legendItems": [{"label": "Detected", "color": "#31a354"},
                        {"label": "Alert, not technique-mapped", "color": "#fdae6b"},
                        {"label": "Missed", "color": "#e6550d"}],
    }


def markdown(label: str, results: list[dict], started: str, harness: list[str]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    lines = [
        f"# Validation run: {label}",
        "",
        f"Run started {started} against `win11-ep` (Wazuh 4.14). "
        + ", ".join(f"**{v} {k}**" for k, v in sorted(counts.items())),
        "",
        "A control step drives the same WinRM + Invoke-AtomicTest path without executing a test; "
        "rules it triggers are attributed to the harness and left out below"
        + (f": `{'`, `'.join(harness)}`." if harness else " (none fired)."),
        "",
        "| Technique (v19) | Legacy | Test | Result | Rules that fired (id, level, description) |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        rules = "<br>".join(f"`{x['id']}` L{x['level']} {x['description']}" for x in r["rules"][:5]) or "none"
        if len(r["rules"]) > 5:
            rules += f"<br>... {len(r['rules']) - 5} more"
        ran = "" if r["executed"] else " (did not execute)"
        replay = f"<br>replay: `{'`, `'.join(r['replay'])}`" if r.get("replay") else ""
        lines.append(f"| {r['technique']} | {r.get('legacy') or ''} | #{r['test']} {r['name']}{ran} "
                     f"| **{r['result']}**{replay} | {rules} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--label", default="validation", help="name used for the result files")
    parser.add_argument("--tests", default=str(HERE / "tests.yml"))
    parser.add_argument("--out", default=str(HERE / "results"))
    parser.add_argument("--only", action="append", help="run only these techniques")
    parser.add_argument("--settle", type=int, default=60, help="seconds to wait for alerts per test")
    parser.add_argument("--gap", type=int, default=15, help="seconds between tests")
    parser.add_argument("--skip-cleanup", action="store_true")
    parser.add_argument("--endpoint", default="10.10.10.20")
    parser.add_argument("--agent", default="win11-ep")
    parser.add_argument("--win-user", default="labadmin")
    parser.add_argument("--indexer", default="https://127.0.0.1:9200")
    parser.add_argument("--indexer-user", default="admin")
    parser.add_argument("--payload-bind", default="10.10.10.10")
    parser.add_argument("--payload-port", type=int, default=8000)
    args = parser.parse_args()

    for var in ("WIN_PASSWORD", "INDEXER_PASSWORD"):
        os.environ[var] = os.environ.get(var, "").strip("\r\n")
        if not os.environ[var]:
            print(f"{var} is not set", file=sys.stderr)
            return 2

    tests = yaml.safe_load(Path(args.tests).read_text())["tests"]
    if args.only:
        tests = [t for t in tests if t["technique"] in args.only]

    server = serve_payload(args.payload_bind, args.payload_port)
    started = iso(utc_now())
    results = []
    try:
        print("[control] harness only, no atomic executed ...", flush=True)
        harness = control_run(args, tests[0])
        print(f"    harness rules: {', '.join(sorted(harness)) or 'none'}", flush=True)
        time.sleep(args.gap)
        for i, test in enumerate(tests, 1):
            print(f"[{i}/{len(tests)}] {test['technique']} #{test['test']} {test['name']} ...", flush=True)
            result = run_test(args, test, harness)
            results.append(result)
            fired = ", ".join(f"{r['id']}(L{r['level']})" for r in result["rules"][:6]) or "nothing"
            print(f"    {result['result']}: {fired}", flush=True)
            if i < len(tests):
                time.sleep(args.gap)
    finally:
        server.shutdown()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.label}.json").write_text(json.dumps(
        {"label": args.label, "started": started, "harness_rules": sorted(harness), "results": results}, indent=2))
    (out / f"{args.label}.md").write_text(markdown(args.label, results, started, sorted(harness)))
    (out / f"{args.label}-navigator-layer.json").write_text(json.dumps(navigator_layer(args.label, results), indent=2))
    print(f"Wrote {out}/{args.label}.json, .md and -navigator-layer.json")
    return 1 if any(r["result"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
