#!/usr/bin/env python3
"""Read-only MCP server over the Wazuh indexer, for the triage agent.

Exposes a few fixed, parameterized queries; the model never writes raw queries and has no
write access. Speaks MCP over stdio (the agent starts it as a subprocess).

Environment: INDEXER_PASSWORD (required), INDEXER_URL (default https://127.0.0.1:9200),
INDEXER_USER (default admin), TRIAGE_AS_OF (alert time; defaults to now).

Every query is anchored to TRIAGE_AS_OF: nothing after the alert (+5 min) is visible and host
look-backs are capped at 2 hours. In production the agent runs right after the alert, so this is
what it would see; in the eval it stops a replayed alert from seeing the future.
"""
import datetime as dt
import os
import re
from collections import Counter

import requests
import urllib3
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # installer's self-signed cert

INDEXER = os.environ.get("INDEXER_URL", "https://127.0.0.1:9200")
AUTH = (os.environ.get("INDEXER_USER", "admin"), os.environ.get("INDEXER_PASSWORD", "").strip("\r\n"))
MAX_TEXT = 300  # long command lines and script blocks are cut to keep tool output small
MAX_LOOKBACK_H = 2  # host-level searches look at most this far back from the alert
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)

mcp = MCPServer("wazuh-readonly", instructions="Read-only queries over Wazuh alerts for SOC triage.")
# The lab's own harness activity (detections/wazuh/9900-*) is test-rig plumbing a real SOC wouldn't
# have; keeping it out of tool results stops the agent from reasoning about the rig instead of the host.
HIDE = [{"term": {"rule.groups": "lab_harness"}}]


def _as_of() -> dt.datetime:
    value = os.environ.get("TRIAGE_AS_OF")
    return _parse_time(value) if value else dt.datetime.now(dt.timezone.utc)


def _window(hours: float) -> dict:
    """Range filter for the hours before the alert, never past it (+5 min of slack)."""
    end = _as_of()
    return {"range": {"timestamp": {"gte": _iso(end - dt.timedelta(hours=min(hours, MAX_LOOKBACK_H))),
                                    "lte": _iso(end + dt.timedelta(minutes=5))}}}


def _search(body: dict) -> dict:
    resp = requests.post(f"{INDEXER}/wazuh-alerts-*/_search", json=body, auth=AUTH, verify=False, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _parse_time(value: str) -> dt.datetime:
    # Alerts use "+0800"-style offsets; models may also pass "Z" or no offset at all (taken as UTC)
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.strip().replace("Z", "+00:00"))
    ts = dt.datetime.fromisoformat(value)
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.timezone.utc)


def _iso(ts: dt.datetime) -> str:
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _brief(src: dict) -> dict:
    """The fields an analyst looks at first, without the rest of the event."""
    win = src.get("data", {}).get("win", {})
    ed = win.get("eventdata", {})
    out = {
        "time": src.get("timestamp"),
        "rule": src.get("rule", {}).get("id"),
        "level": src.get("rule", {}).get("level"),
        "description": src.get("rule", {}).get("description"),
        "mitre": src.get("rule", {}).get("mitre", {}).get("id", []),
        "event_id": win.get("system", {}).get("eventID"),
    }
    for key in ("image", "commandLine", "parentImage", "parentCommandLine", "user", "targetFilename",
                "targetObject", "details", "scriptBlockText", "targetUserName", "ipAddress",
                "threat Name", "path"):
        if ed.get(key):
            out[key] = str(ed[key])[:MAX_TEXT]
    return out


@mcp.tool(annotations=READ_ONLY)
def host_timeline(agent_name: str, around: str, minutes_before: int = 10, minutes_after: int = 5,
                  min_level: int = 3, limit: int = 40) -> list[dict]:
    """Alerts from one host in a time window around a moment (ISO 8601), oldest first.
    Use it to see what else happened on the host just before and after the alert."""
    center = min(_parse_time(around), _as_of())
    latest = _as_of() + dt.timedelta(minutes=5)
    body = {
        "size": min(limit, 100), "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"must_not": HIDE, "filter": [
            {"term": {"agent.name": agent_name}},
            {"range": {"rule.level": {"gte": min_level}}},
            {"range": {"timestamp": {"gte": _iso(center - dt.timedelta(minutes=min(minutes_before, 120))),
                                     "lte": _iso(min(center + dt.timedelta(minutes=min(minutes_after, 60)), latest))}}},
        ]}},
    }
    return [_brief(h["_source"]) for h in _search(body)["hits"]["hits"]]


@mcp.tool(annotations=READ_ONLY)
def rule_prevalence(rule_id: str, days: int = 7) -> dict:
    """How often a rule fired in the N days before the alert, on how many hosts, and the most common
    command lines behind it. Rules that fire constantly with the same command line are often
    routine activity; a first-ever occurrence deserves more attention."""
    body = {
        "size": 200, "sort": [{"timestamp": "desc"}],
        "_source": ["timestamp", "agent.name", "data.win.eventdata.commandLine", "data.win.eventdata.scriptBlockText"],
        "query": {"bool": {"filter": [
            {"term": {"rule.id": rule_id}},
            {"range": {"timestamp": {"gte": _iso(_as_of() - dt.timedelta(days=min(days, 30))), "lte": _iso(_as_of())}}},
        ]}},
    }
    result = _search(body)
    hits = [h["_source"] for h in result["hits"]["hits"]]
    commands = Counter(
        str((h.get("data", {}).get("win", {}).get("eventdata", {}).get("commandLine")
             or h.get("data", {}).get("win", {}).get("eventdata", {}).get("scriptBlockText") or ""))[:120]
        for h in hits)
    return {
        "rule": rule_id,
        "count": result["hits"]["total"]["value"],
        "hosts": sorted({h.get("agent", {}).get("name") for h in hits}),
        "first_seen": hits[-1]["timestamp"] if hits else None,
        "last_seen": hits[0]["timestamp"] if hits else None,
        "top_command_lines": [{"text": c, "count": n} for c, n in commands.most_common(5) if c],
    }


@mcp.tool(annotations=READ_ONLY)
def search_host_activity(agent_name: str, text: str, hours: int = 2, limit: int = 20) -> list[dict]:
    """Alerts on a host in the hours before the alert (max 2) whose process image, command line,
    parent, script block or file path contains the given text (case-insensitive). Use it to pivot
    on a file name, a user or a tool."""
    needle = "*" + text.replace("*", "").replace("?", "")[:80] + "*"
    fields = ["data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.parentImage",
              "data.win.eventdata.parentCommandLine", "data.win.eventdata.scriptBlockText",
              "data.win.eventdata.targetFilename", "data.win.eventdata.targetObject"]
    body = {
        "size": min(limit, 50), "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"must_not": HIDE,
            "filter": [{"term": {"agent.name": agent_name}},
                       _window(hours)],
            "should": [{"wildcard": {f: {"value": needle, "case_insensitive": True}}} for f in fields],
            "minimum_should_match": 1,
        }},
    }
    return [_brief(h["_source"]) for h in _search(body)["hits"]["hits"]]


@mcp.tool(annotations=READ_ONLY)
def defender_activity(agent_name: str, hours: int = 2) -> list[dict]:
    """Microsoft Defender detections and configuration changes on a host in the hours before the
    alert (max 2): what was blocked, the threat name and the command line Defender acted on."""
    body = {
        "size": 30, "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"must_not": HIDE, "filter": [
            {"term": {"agent.name": agent_name}},
            {"term": {"data.win.system.providerName": "Microsoft-Windows-Windows Defender"}},
            _window(hours),
        ]}},
    }
    return [_brief(h["_source"]) for h in _search(body)["hits"]["hits"]]


if __name__ == "__main__":
    mcp.run()
