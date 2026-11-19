# AI alert triage

An LLM triages Wazuh alerts of level 10 and above the way a Tier-1 analyst would: it investigates
the host around the alert through a read-only MCP server, then returns a verdict that Wazuh shows
as its own alert. Models are reached through OpenRouter, so they can be swapped and compared.

```
Wazuh alert (level >= 10)
   │  integratord: custom-purplelab-triage (skips the AI's own verdict alerts)
   ▼
/var/lib/purplelab/triage/inbox/*.json
   │  worker.py (systemd: purplelab-triage, runs as its own user)
   ▼
agent.py ── OpenRouter (any tool-calling model)
   │  ▲
   ▼  │  MCP over stdio
wazuh_mcp_server.py ── read-only indexer account: wazuh-alerts-* only
   │
   ▼
/var/log/purplelab/triage.json ── manager localfile ──▶ rules 100901 / 100902 / 100903
                                                          (true positive / escalate / benign)
```

## Pieces

| File | What it does |
|---|---|
| [`wazuh_mcp_server.py`](wazuh_mcp_server.py) | MCP server (Python SDK v2) with four fixed queries: `host_timeline`, `rule_prevalence`, `search_host_activity`, `defender_activity`. All are annotated read-only; the model never writes raw queries |
| [`agent.py`](agent.py) | Tool-calling loop against OpenRouter: at most 8 tool calls, temperature 0, strict JSON verdict; records tokens, cost and latency |
| [`worker.py`](worker.py) | Watches the inbox, triages, appends one JSON line per verdict for Wazuh to read back |
| [`integration/`](integration) | Wazuh integration that hands alerts to the worker (write-then-rename, never triages its own verdicts) |
| [`eval/`](eval) | Labelled dataset and the model comparison |
| [`../detections/wazuh/9920-purplelab_triage.xml`](../detections/wazuh/9920-purplelab_triage.xml) | Verdict rules |
| [`../lab/wazuh/install-triage.sh`](../lab/wazuh/install-triage.sh) | Installer: service user, read-only indexer role, spool, integration, systemd unit |

## Safety choices

- **Least privilege:** the agent's indexer account (`purplelab_triage`) can only read `wazuh-alerts-*`
  (writes and the security index return 403). It never sees the admin password.
- **No free-form queries:** tools are fixed, parameterized searches with capped windows and result sizes.
- **Bounded:** 8 tool calls per alert, tool output truncated, one retry if the answer isn't valid JSON;
  anything unparseable becomes `needs_escalation`, never `benign`.
- **The AI can't silence alerts:** verdicts are added next to the original alert; nothing is suppressed.
- **Alert-storm protection:** the vulnerability detector once raised ~740 CVE findings at level 10+
  in one burst and they all queued for triage. Now the integration skips inventory-style groups
  (vulnerability detector, SCA, FIM). The worker triages the same rule on the same host once per
  15 minutes and at most 60 alerts an hour; anything beyond that is set aside in `duplicate/` or
  `deferred/`, never dropped silently.
- **Sees the host as of the alert:** every MCP query is anchored to the alert time (`TRIAGE_AS_OF`),
  with no look-ahead and a 2-hour look-back.
- **Secrets:** the OpenRouter key lives in `/etc/purplelab/triage.env` (root:purplelab-triage, 0640),
  is piped over SSH from the repo's gitignored `.env`, and never touches git or a command line.
- **Data:** only synthetic lab telemetry is sent to OpenRouter.

## Run it

```powershell
# Deploy: model and key come from .env (copy .env.example); the worker starts once the key is set
.\lab\build\deploy-triage.ps1

# Eval: benign activity -> labelled dataset -> model comparison
.\lab\build\Invoke-TriageEval.ps1 -GenerateBenign -BuildDataset
.\lab\build\Invoke-TriageEval.ps1 -Model deepseek/deepseek-v4.1-flash, qwen/qwen3.8-27b, z-ai/glm-5.3-flash, anthropic/claude-haiku-5.5
```
