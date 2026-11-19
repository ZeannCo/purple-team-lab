#!/usr/bin/env python3
"""Triage worker: picks up alerts the Wazuh integration dropped in the inbox, runs the agent,
and appends one JSON line per verdict to the report log. Wazuh reads that log back
(localfile, json) so verdicts show up as their own alerts (rules 100900-100903).

Runs as the purplelab-triage systemd service; settings come from /etc/purplelab/triage.env.
"""
import asyncio
import json
import os
import shutil
import sys
import time
import traceback
from pathlib import Path

from agent import DEFAULT_MODEL, openrouter_client, triage

INBOX = Path(os.environ.get("TRIAGE_INBOX", "/var/lib/purplelab/triage/inbox"))
REPORT_LOG = Path(os.environ.get("TRIAGE_REPORT_LOG", "/var/log/purplelab/triage.json"))
MODEL = os.environ.get("TRIAGE_MODEL", DEFAULT_MODEL)
POLL_SECONDS = 5
# Alert-storm protection: the same rule on the same host is triaged once per DEDUP window, and at
# most MAX_PER_HOUR alerts reach the model; the rest are set aside, never silently dropped.
DEDUP_SECONDS = int(os.environ.get("TRIAGE_DEDUP_SECONDS", "900"))
MAX_PER_HOUR = int(os.environ.get("TRIAGE_MAX_PER_HOUR", "60"))


def move(path: Path, folder: str) -> None:
    dest = INBOX.parent / folder
    dest.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), dest / path.name)


def main() -> int:
    client = openrouter_client()
    REPORT_LOG.parent.mkdir(parents=True, exist_ok=True)
    print(f"triage worker: model={MODEL} inbox={INBOX} log={REPORT_LOG} "
          f"dedup={DEDUP_SECONDS}s cap={MAX_PER_HOUR}/h", flush=True)
    last_triaged: dict[tuple[str, str], float] = {}
    recent: list[float] = []
    while True:
        for path in sorted(INBOX.glob("*.json")):
            try:
                alert = json.loads(path.read_text())
                now = time.time()
                key = (alert.get("rule", {}).get("id", ""), alert.get("agent", {}).get("name", ""))
                recent = [t for t in recent if now - t < 3600]
                if now - last_triaged.get(key, 0) < DEDUP_SECONDS:
                    print(f"{path.name}: duplicate of rule {key[0]} on {key[1]} within {DEDUP_SECONDS}s, set aside", flush=True)
                    move(path, "duplicate")
                    continue
                if len(recent) >= MAX_PER_HOUR:
                    print(f"{path.name}: hourly cap of {MAX_PER_HOUR} reached, deferred", flush=True)
                    move(path, "deferred")
                    continue
                last_triaged[key] = now
                recent.append(now)
                report = asyncio.run(triage(alert, MODEL, client))
                with REPORT_LOG.open("a") as log:
                    # Top-level key so the Wazuh rules can tell verdicts apart from anything else
                    log.write(json.dumps({"purplelab_triage": {
                        k: report[k] for k in ("verdict", "attack_technique", "confidence", "summary",
                                               "model", "alert", "latency_s", "cost_usd")
                    } | {"tool_calls": len(report["tool_calls"])}}) + "\n")
                print(f"{path.name}: {report['verdict']} ({report['model']}, {report['latency_s']}s)", flush=True)
                move(path, "done")
            except Exception:
                traceback.print_exc()
                move(path, "error")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
