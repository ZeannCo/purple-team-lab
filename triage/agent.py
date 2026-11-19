#!/usr/bin/env python3
"""Tier-1 triage of one Wazuh alert by an LLM (via OpenRouter) that investigates through the
read-only Wazuh MCP server.

    OPENROUTER_API_KEY=... INDEXER_PASSWORD=... python3 agent.py alert.json --model anthropic/claude-haiku-5.5

Prints a JSON report: verdict, ATT&CK technique, confidence, evidence, recommended actions,
plus the model, tool calls, tokens, cost and latency.
"""
import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI

HERE = Path(__file__).resolve().parent
DEFAULT_MODEL = "anthropic/claude-haiku-5.5"
MAX_TOOL_CALLS = 8
MAX_TOOL_OUTPUT = 6000
VERDICTS = ("true_positive", "benign", "needs_escalation")

SYSTEM_PROMPT = """You are a Tier-1 SOC analyst triaging a Wazuh alert from a small Windows environment.

Environment:
- WIN11-EP (agent win11-ep, 10.10.10.20): a Windows 11 workstation with Sysmon, PowerShell script
  block logging and Microsoft Defender.
- wazuh01 (10.10.10.10): the security server. Administrators can run remote commands from it.

Investigate with the tools before deciding: look at what happened on the host around the alert,
how common the rule is, and pivot on suspicious names, paths or tools. You have at most {budget}
tool calls. Base the verdict on the activity itself, not on who or what launched it.

Verdicts:
- true_positive: the activity matches a malicious technique (even if it was blocked).
- benign: routine or administrative activity with a credible legitimate explanation.
- needs_escalation: suspicious but you cannot tell either way from the available data.

Answer with only this JSON object, no other text:
{{"verdict": "true_positive|benign|needs_escalation",
  "attack_technique": "MITRE ATT&CK ID such as T1053.005, or null",
  "confidence": 0.0-1.0,
  "summary": "one or two sentences",
  "evidence": ["specific observations from the alert and tool results"],
  "recommended_actions": ["next steps for the responder"]}}"""


def alert_brief(alert: dict) -> dict:
    """Only what an analyst would see in the alert itself; the rest comes from investigation."""
    ed = alert.get("data", {}).get("win", {}).get("eventdata", {})
    keep = ("image", "commandLine", "parentImage", "parentCommandLine", "user", "targetFilename",
            "targetObject", "details", "scriptBlockText", "targetUserName", "subjectUserName",
            "ipAddress", "threat Name", "path", "originalFileName")
    return {
        "timestamp": alert.get("timestamp"),
        "agent": alert.get("agent", {}).get("name"),
        "rule": {k: alert.get("rule", {}).get(k) for k in ("id", "level", "description", "groups")}
                | {"mitre": alert.get("rule", {}).get("mitre", {}).get("id", [])},
        "event_id": alert.get("data", {}).get("win", {}).get("system", {}).get("eventID"),
        "event": {k: str(v)[:600] for k, v in ed.items() if k in keep and v},
    }


def parse_report(text: str) -> dict | None:
    match = re.search(r"\{.*\}", text or "", re.S)
    if not match:
        return None
    try:
        report = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return report if report.get("verdict") in VERDICTS else None


def _usage(resp) -> tuple[int, int, float]:
    usage = resp.usage
    if usage is None:
        return 0, 0, 0.0
    extra = getattr(usage, "model_extra", None) or {}
    return usage.prompt_tokens or 0, usage.completion_tokens or 0, float(extra.get("cost") or 0.0)


async def triage(alert: dict, model: str, client: OpenAI) -> dict:
    server = StdioServerParameters(command=sys.executable, args=[str(HERE / "wazuh_mcp_server.py")],
                                   env={k: os.environ[k] for k in ("INDEXER_PASSWORD", "INDEXER_URL", "INDEXER_USER", "PATH")
                                        if k in os.environ})
    started = time.monotonic()
    totals = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0}
    tool_log: list[dict] = []

    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                    "parameters": t.input_schema}}
                 for t in (await session.list_tools()).tools]
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(budget=MAX_TOOL_CALLS)},
            {"role": "user", "content": "Triage this alert:\n" + json.dumps(alert_brief(alert), indent=1)},
        ]

        report = None
        for _ in range(MAX_TOOL_CALLS + 3):
            budget_left = MAX_TOOL_CALLS - len(tool_log)
            resp = await asyncio.to_thread(
                client.chat.completions.create, model=model, messages=messages, temperature=0,
                tools=tools, tool_choice="auto" if budget_left > 0 else "none",
                extra_body={"usage": {"include": True}})
            p, c, cost = _usage(resp)
            totals["prompt_tokens"] += p
            totals["completion_tokens"] += c
            totals["cost_usd"] += cost
            msg = resp.choices[0].message

            if msg.tool_calls and budget_left > 0:
                messages.append({"role": "assistant", "content": msg.content or "",
                                 "tool_calls": [tc.model_dump() for tc in msg.tool_calls]})
                for tc in msg.tool_calls:
                    if len(tool_log) >= MAX_TOOL_CALLS:
                        output = "Tool budget exhausted; give your verdict now."
                    else:
                        try:
                            args = json.loads(tc.function.arguments or "{}")
                            result = await session.call_tool(tc.function.name, args)
                            output = "\n".join(getattr(part, "text", "") for part in result.content)
                            if getattr(result, "is_error", False):
                                output = f"Tool error: {output}"
                        except Exception as exc:  # bad arguments from the model are reported back to it
                            args, output = {}, f"Tool error: {exc}"
                        tool_log.append({"tool": tc.function.name, "args": args})
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": output[:MAX_TOOL_OUTPUT]})
                continue

            report = parse_report(msg.content)
            if report:
                break
            messages.append({"role": "assistant", "content": msg.content or ""})
            messages.append({"role": "user", "content": "Reply with only the JSON object described above."})

    report = report or {"verdict": "needs_escalation", "attack_technique": None, "confidence": 0.0,
                        "summary": "Model did not return a valid verdict.", "evidence": [], "recommended_actions": [],
                        "error": "unparseable_response"}
    return {
        **report,
        "model": model,
        "alert": {"id": alert.get("id"), "rule": alert.get("rule", {}).get("id"),
                  "agent": alert.get("agent", {}).get("name"), "timestamp": alert.get("timestamp")},
        "tool_calls": tool_log,
        **totals,
        "latency_s": round(time.monotonic() - started, 1),
    }


def openrouter_client() -> OpenAI:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip("\r\n")
    if not key:
        raise SystemExit("OPENROUTER_API_KEY is not set")
    return OpenAI(base_url="https://openrouter.ai/api/v1", api_key=key, timeout=180, max_retries=4,
                  default_headers={"HTTP-Referer": "https://github.com/ZeannCo/purple-team-lab",
                                   "X-Title": "purple-team-lab triage"})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("alert_file")
    parser.add_argument("--model", default=os.environ.get("TRIAGE_MODEL", DEFAULT_MODEL))
    args = parser.parse_args()
    alert = json.loads(Path(args.alert_file).read_text())
    print(json.dumps(asyncio.run(triage(alert, args.model, openrouter_client())), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
