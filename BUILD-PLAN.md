# AI-Assisted Purple Team Lab — Build Plan (Wazuh edition)

**Goal:** a home lab where Atomic Red Team attacks are detected by Wazuh, every custom detection is
automatically proven against the attack it targets, and an AI agent (OpenRouter models + a Wazuh MCP
server) triages the alerts, with measured accuracy across models.

**Host:** ASUS TUF F15 · i5-11400H (6C/12T) · 32 GB RAM · RTX 3050 4 GB · VMware Workstation 17.6.3
**Layout on D:** `D:\Labs\purple-team-lab` (this repo) · `D:\Labs\VMs` (VMs, not in git) ·
`D:\Labs\ISOs` (installers) · `D:\Labs\keys` (SSH key + lab passwords, never in git)

**SIEM choice:** Wazuh 4.14 (stable). Splunk is added later as an optional extra phase. Running
two SIEMs side by side is a portfolio point of its own.

---

## 0. Architecture

```
                 Internet (OpenRouter API, package downloads)
                                   │
                   VMware NAT (VMnet8, 192.168.110.0/24)
                                   │  host reaches the dashboard at https://192.168.110.10
  ┌────────────────────────────────┴──────────────────────────────┐
  │ wazuh01  Ubuntu 24.04 (cloud image)  8 GB / 4 vCPU / 80 GB    │
  │  nat0 192.168.110.10        lab0 10.10.10.10                  │
  │  • Wazuh 4.14 all-in-one (manager + indexer + dashboard)      │
  │  • triage agent (Python) + Wazuh MCP server                   │
  │  • validation runner (Python, pywinrm)                        │
  │  • Phase 3: Docker — vulnerable LLM app + MCP server          │
  └────────────────────────────────┬──────────────────────────────┘
                                   │  Lab segment: VMnet2 (private switch, no host adapter)
             ┌─────────────────────┴──────────────────────┐
  ┌──────────┴────────────────────────┐   ┌───────────────┴───────────────────┐
  │ win11-ep  Windows 11 Ent (eval)   │   │ dc01  Windows Server 2022 (eval)  │
  │ 10.10.10.20   5 GB / 2 vCPU       │   │ 10.10.10.5   3 GB / 2 vCPU        │
  │ Sysmon · Wazuh agent · Atomic RT  │   │ AD DS · Wazuh agent  (Phase 1b)   │
  └───────────────────────────────────┘   └───────────────────────────────────┘
```

**RAM budget:** about 13 GB in Phase 1 (wazuh01 + win11-ep) and about 16 GB once dc01 is added. Close
VS Code, browsers and chat apps while the lab runs.

**Isolation rule:** win11-ep only has internet during setup and `-GetPrereqs`. Atomics run while it
sits on VMnet2 alone. Never run atomics on the laptop itself.

---

## Phase 0 — Lab foundation

### 0.1 wazuh01 (automated)
- [x] Ubuntu 24.04 cloud image downloaded and its checksum verified (`D:\Labs\ISOs`)
- [x] SSH key generated in `D:\Labs\keys`
- [x] `lab\build\new-wazuh-vm.ps1`: imports the image, grows the disk to 80 GB, sets two NICs with
      fixed MACs, injects cloud-init (user, SSH key, static IPs) through VMware guestinfo, then boots
- [x] `lab/wazuh/install-wazuh.sh`: Wazuh 4.14 all-in-one install (`wazuh-install.sh -a`), which installed v4.14.10
- [x] Snapshots: **`base-os`**, **`wazuh-installed`**

### 0.2 win11-ep (automated)
- [x] Windows 11 Enterprise Evaluation 26H2 ISO in `D:\Labs\ISOs`
- [x] Payloads in `D:\Labs\ISOs\payloads`, each checked: Sysmon 15.22 (Microsoft-signed),
      Wazuh agent 4.14.10 (Wazuh-signed), sysmon-modular `sysmonconfig.xml` (matches the release SHA256)
- [x] `lab\build\new-win11-vm.ps1` + `lab\windows\autounattend.xml`: unattended install
      (BIOS/MBR so it boots without a keypress, TPM and Secure Boot checks bypassed for the lab)
      from a setup disc built with Windows' own IMAPI2 API, so no extra tools are needed
- [x] `lab\windows\bootstrap.ps1` at first logon: NICs by MAC (lab0 = 10.10.10.20), audit policy +
      command-line logging + script block logging, Sysmon, Wazuh agent (group `windows`), WinRM
      limited to 10.10.10.0/24, no sleep or auto-updates, VMware Tools
- [x] Agent config for the `windows` group (`lab\wazuh\shared\windows\agent.conf`: Sysmon,
      PowerShell, Defender channels) deployed with `lab\build\push-wazuh-config.ps1`
- [x] Verified: agent Active; Security, Sysmon and PowerShell events indexed; WinRM from wazuh01
      works through `validation/lab_winrm.py` (pywinrm ≥ 0.5 in `/opt/purplelab/venv`)
- [x] Snapshot: **`clean-baseline`**
- Note: built with 4 GB RAM instead of 5 GB because the host was short on free memory

---

## Phase 1 — Wazuh + Atomic Red Team

### 1.1 Confirm telemetry
- [x] Agent shows **Active**
- [x] Sysmon events arrive (filter `data.win.system.channel: Microsoft-Windows-Sysmon/Operational`)
- [x] Agent config kept in `lab/wazuh/shared/`; the Sysmon config comes from a pinned sysmon-modular release

### 1.2 Atomic Red Team
- [x] `lab\windows\install-atomics.ps1` (run over WinRM): execution policy `RemoteSigned` (Windows 11
      defaults to `Restricted`, which blocks the `powershell-yaml` module), Defender exclusion for
      `C:\AtomicRedTeam` only, Invoke-AtomicRedTeam 2.1 + 353 techniques
- [x] Tests chosen to run offline (`validation/tests.yml`, pinned by GUID); the certutil download
      fetches from wazuh01 instead of GitHub
- [x] Internet cut (NAT NIC disconnected with `vmrun`). Snapshot: **`atomics-ready`**
- [x] Baseline with built-in rules only: [`validation/results/baseline.md`](validation/results/baseline.md)

**Technique set (10 techniques, 11 tests).** Atomic Red Team moved to ATT&CK v19 in May 2026, which
renumbered two of them:

| ATT&CK v19 | Pre-v19 | Technique | Test |
|---|---|---|---|
| T1059.001 | | PowerShell | #17 encoded command, #18 known offensive cmdlets |
| T1003.001 | | LSASS memory dump | #2 comsvcs.dll MiniDump |
| T1053.005 | | Scheduled task | #2 schtasks /create |
| T1547.001 | | Registry Run keys | #1 reg add HKCU Run |
| T1218.011 | | Rundll32 | #2 vbscript via mshtml |
| T1105 | | Ingress tool transfer | #7 certutil -urlcache |
| T1136.001 | | Create local account | #4 net user /add |
| T1087.001 | | Local account discovery | #8 net user / localgroup |
| T1685.005 | T1070.001 | Clear Windows event logs | #1 wevtutil cl Security |
| T1685 | T1562.001 | Disable or modify tools (Defender) | #19 Set-MpPreference |
### 1.3 Phase 1b — Active Directory
- [ ] dc01 on VMnet2 at `10.10.10.5`, new forest `lab.local`, join win11-ep, add a Wazuh agent
- [ ] AD techniques: **T1558.003** Kerberoasting, **T1087.002** domain account discovery, **T1078** valid accounts

---

## Phase 2 — Detection-as-code pipeline

Done. Write-up: [`docs/detection-engineering-notes.md`](docs/detection-engineering-notes.md).

### 2.1 Rules
- [x] [`9900-purplelab_tuning.xml`](detections/wazuh/9900-purplelab_tuning.xml): harness false positives
      found in the baseline (PowerShell policy-probe file at level 15, WinRM NTLM logon from wazuh01,
      Atomic Red Team module source)
- [x] [`9910-purplelab_detections.xml`](detections/wazuh/9910-purplelab_detections.xml): Sysmon/PowerShell
      detections per gap, Defender-prevention enrichment (`100201`-`100204`), discovery burst (`100190`)
- [x] Files are named `99xx-` so they load after the built-in ruleset (`if_sid` parents must exist)
- [x] `lab\build\push-wazuh-config.ps1` deploys rules + agent config, checks with `wazuh-analysisd -t`
      and restores the previous rules if the check fails
- Not done: a Sigma copy of each rule. Wazuh 4.14 has no Sigma support; revisit with Wazuh 5.0 or
  the Splunk phase

### 2.2 CI: replay real events (GitHub-hosted runner, no access to the lab)
- [x] [`tests/logtest/ci.sh`](tests/logtest/ci.sh): throwaway `wazuh/wazuh-manager:4.14.10`, rules
      compiled with `wazuh-analysisd -t`, 25 cases replayed through the logtest API
- [x] Cases are `data.win` from real lab alerts ([`harvest.py`](tests/logtest/harvest.py)); the four
      processes Defender blocked are synthesized from real events of the same type and labelled
- [x] Benign look-alikes for the rules most likely to false-positive
- [x] logtest can't run the eventchannel decoder; CI patches base rule `60000` inside the container
      (`decoded_as json`, no `category`) and never touches the lab manager
- [x] Badge in the README

### 2.3 Live validation from wazuh01
- [x] [`validation/run_validation.py`](validation/run_validation.py) via `lab\build\Invoke-Validation.ps1`:
      control step (harness only) → each atomic over WinRM → indexer query for the expected rules →
      cleanup; writes `.json`, `.md` and an ATT&CK Navigator layer
- [x] Result: **11/11 PASS** ([`validation/results/validation.md`](validation/results/validation.md))

Never attach a self-hosted runner to this public repo: a pull request from a fork could run code
inside the lab. Live results are committed instead.

---

## Phase 2.5 — AI triage agent (OpenRouter)

```
Wazuh alert (level ≥ 10) ──<integration>──▶ receiver (FastAPI, wazuh01)
                                                 │
                                       triage agent (Python)
                             OpenRouter model ◀──▶ Wazuh MCP server / indexer API
                                                 │  (read-only, at most 8 tool calls)
                                                 ▼
             /var/log/triage/reports.json ──localfile──▶ Wazuh rule 100900 "AI triage verdict"
                                                 ▼
                         Verdicts appear in the Wazuh dashboard next to the original alert
```

- [ ] `<integration>` block in the manager's `ossec.conf` (`custom-triage`, `level 10`, JSON format)
- [ ] Agent: OpenAI-compatible client with `base_url=https://openrouter.ai/api/v1` and the key from `.env`
- [ ] Tools: the community Wazuh MCP server (`gbrigandi/mcp-server-wazuh`), or a small set of read-only
      indexer queries
- [ ] Output as strict JSON: `verdict`, `attack_technique`, `confidence`, `evidence`, `recommended_actions`
- [ ] Log the model, tokens, cost and latency for every alert
- [ ] **Eval:** 40–60 labelled alerts (atomic runs = true positive with a known technique, plus harmless
      admin activity that looks similar = benign), run against 3–4 OpenRouter models

| Model | Verdict acc. | FP rate | Technique ID | $/alert | Latency |
|---|---|---|---|---|---|
| _fill in_ | | | | | |

---

## Phase 3 — Detecting attacks on AI (MITRE ATLAS)
- [ ] A deliberately vulnerable LLM chat app with risky MCP tools, in Docker on wazuh01, using an
      OpenRouter model
- [ ] Every prompt, response and tool call logged as JSON, then collected by Wazuh `localfile`
- [ ] Attack it with **Promptfoo** red-team plugins (prompt injection, indirect injection, tool misuse)
- [ ] Custom Wazuh rules mapped to **MITRE ATLAS** (e.g. AML.T0051), added to the same CI and validation flow

## Phase 4 (optional) — Splunk alongside Wazuh
- [ ] Once the Splunk Developer license arrives, forward Wazuh alerts to Splunk and convert the Sigma rules to SPL
- [ ] Compare coverage between the two SIEMs in the README

---

## Portfolio deliverables
- [ ] README: pitch, architecture diagram, coverage map, results tables
- [ ] Detection results with misses documented and fixed
- [ ] AI triage model comparison + write-up of where it failed
- [ ] 3–5 min demo video: atomic runs → Wazuh alert → AI verdict shows up in the dashboard
- [ ] One LinkedIn or blog post per phase

## Safety checklist
- Atomics only on win11-ep; revert to `clean-baseline` after test sessions
- win11-ep has no internet while tests run
- Defender exclusions only inside the VM
- `D:\Labs\keys` and `.env` never go in git; rotate the OpenRouter key if it ever leaks
- Only synthetic lab data goes to OpenRouter
- Eval licenses expire (Windows 11 after 90 days, Server after 180), so keep everything rebuildable from this repo
