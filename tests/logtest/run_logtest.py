#!/usr/bin/env python3
"""Replay captured Windows events through a Wazuh manager's logtest API and check which rule fires.

Each tests/logtest/cases/*.yml file holds cases:

    - name: certutil downloads over HTTP
      event: {win: {system: {...}, eventdata: {...}}}   # data.win from a real alert
      expect_rule: "100130"        # rule that must fire (omit for a negative case)
      expect_level: 12             # optional
      not_rules: ["100130"]        # for benign look-alikes: these must NOT fire

    - name: three discovery commands in a row
      events: [{win: ...}, {win: ...}, {win: ...}]  # replayed in one logtest session (frequency rules);
      expect_rule: "100190"                         # checks apply to the last event

Usage (CI): python3 run_logtest.py --api https://localhost:55000 --user wazuh-wui
API password comes from WAZUH_API_PASSWORD.

logtest cannot run the built-in windows_eventchannel decoder, so Windows events fall through to the
JSON decoder. The documented workaround is to point base rule 60000 at the json decoder; CI does that
inside its throwaway manager container (never on the lab manager). The fixtures are data.win from
real alerts, which already carry the eventchannel decoder's escaping (doubled backslashes).
"""
import argparse
import json
import os
import sys
from pathlib import Path

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # manager API uses a self-signed cert
CASES_DIR = Path(__file__).resolve().parent / "cases"


def token(api: str, user: str, password: str) -> str:
    resp = requests.post(f"{api}/security/user/authenticate", auth=(user, password), verify=False, timeout=30)
    resp.raise_for_status()
    return resp.json()["data"]["token"]


def logtest(api: str, jwt: str, events: list[dict]) -> dict:
    """Replays events in one logtest session (so frequency rules see all of them); returns the
    output for the last one."""
    session = None
    output: dict = {}
    for event in events:
        body = {"event": json.dumps(event), "log_format": "json", "location": "EventChannel"}
        if session:
            body["token"] = session
        resp = requests.put(f"{api}/logtest", json=body, headers={"Authorization": f"Bearer {jwt}"},
                            verify=False, timeout=30)
        resp.raise_for_status()
        data = resp.json()["data"]
        session, output = data.get("token", session), data["output"]
    if session:
        requests.delete(f"{api}/logtest/sessions/{session}", headers={"Authorization": f"Bearer {jwt}"},
                        verify=False, timeout=30)
    return output


def check(case: dict, output: dict) -> list[str]:
    rule = output.get("rule", {})
    fired = str(rule.get("id", ""))
    problems = []
    if "expect_rule" in case and fired != str(case["expect_rule"]):
        problems.append(f"expected rule {case['expect_rule']}, got {fired or 'none'} ({rule.get('description', '')})")
    if "expect_level" in case and rule.get("level") != case["expect_level"]:
        problems.append(f"expected level {case['expect_level']}, got {rule.get('level')}")
    if fired in {str(r) for r in case.get("not_rules", [])}:
        problems.append(f"rule {fired} fired on a benign event")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", default="https://localhost:55000")
    parser.add_argument("--user", default="wazuh-wui")
    parser.add_argument("--cases", default=str(CASES_DIR))
    args = parser.parse_args()

    password = os.environ.get("WAZUH_API_PASSWORD", "").strip("\r\n")
    if not password:
        print("WAZUH_API_PASSWORD is not set", file=sys.stderr)
        return 2

    jwt = token(args.api, args.user, password)
    failures = total = 0
    for path in sorted(Path(args.cases).glob("*.yml")):
        for case in yaml.safe_load(path.read_text()) or []:
            total += 1
            output = logtest(args.api, jwt, case.get("events") or [case["event"]])
            problems = check(case, output)
            rule = output.get("rule", {})
            status = "FAIL" if problems else "ok"
            print(f"[{status}] {path.stem}: {case['name']} -> {rule.get('id', 'none')} L{rule.get('level', '-')}")
            for p in problems:
                print(f"       {p}")
            failures += bool(problems)

    print(f"\n{total - failures}/{total} cases passed")
    return 1 if failures or not total else 0


if __name__ == "__main__":
    sys.exit(main())
