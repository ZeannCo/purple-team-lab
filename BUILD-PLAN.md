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
- [ ] On win11-ep (with internet), add a Defender exclusion for `C:\AtomicRedTeam` inside the VM only, then:
  ```powershell
  IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
  Install-AtomicRedTeam -getAtomics
  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
  ```
- [ ] For each technique: `-ShowDetails`, then `-CheckPrereqs`, then `-GetPrereqs`. **Read each test before running it.**
- [ ] Cut internet (VMnet2 only). Snapshot: **`atomics-ready`**
- [ ] For each technique: run the test, note which built-in Wazuh rules fired and which didn't, then clean up

**Starter technique set (10, single host):**

| ATT&CK ID | Technique | Main telemetry |
|---|---|---|
| T1059.001 | PowerShell | 4104 script block |
| T1003.001 | LSASS memory dump | Sysmon EID 10 |
| T1053.005 | Scheduled task | Sysmon EID 1 / Security 4698 |
| T1547.001 | Registry Run keys | Sysmon EID 13 |
| T1218.011 | Rundll32 | Sysmon EID 1 |
| T1105 | Ingress tool transfer (certutil) | Sysmon EID 1 / 3 |
| T1136.001 | Create local account | Security 4720 |
| T1087.001 | Local account discovery | Sysmon EID 1 |
| T1070.001 | Clear Windows event logs | Security 1102 |
| T1562.001 | Impair defenses (Defender) | Sysmon EID 1 / 13 |

### 1.3 Phase 1b — Active Directory
- [ ] dc01 on VMnet2 at `10.10.10.5`, new forest `lab.local`, join win11-ep, add a Wazuh agent
- [ ] AD techniques: **T1558.003** Kerberoasting, **T1087.002** domain account discovery, **T1078** valid accounts

---

## Phase 2 — Detection-as-code pipeline

### 2.1 Repository layout
```
purple-team-lab/
├── README.md
├── BUILD-PLAN.md
├── lab/
│   ├── build/            # VM build scripts (PowerShell + vmrun/ovftool)
│   ├── cloud-init/       # Linux VM templates (secrets filled in at build time, never committed)
│   ├── wazuh/            # install script, ossec.conf snippets
│   └── windows/          # autounattend.xml, Sysmon config, agent config
├── detections/
│   ├── wazuh/            # custom rules (XML, IDs 100100–100999): the deployed source of truth
│   └── sigma/            # Sigma version of each rule, so it can run on other SIEMs (Splunk, Wazuh 5.0)
├── tests/
│   └── logtest/          # sample events + expected rule ID for each detection
├── validation/
│   ├── tests.yml         # rule ID → atomic technique + test number
│   ├── run_validation.py
│   └── results/          # results.json, results.md, navigator_layer.json
├── triage/               # AI agent + eval (Phase 2.5)
├── atlas/                # Phase 3
└── .github/workflows/ci.yml
```

### 2.2 Write the rules
- [ ] One XML file per technique in `detections/wazuh/`. Each rule has `<mitre><id>T…</id></mitre>`,
      a clear description and a level (12+ for high confidence).
- [ ] Start with gaps: for each atomic where the built-in ruleset was silent or too noisy, write a
      custom rule (often a child rule with `<if_sid>` on the built-in Sysmon rule).
- [ ] `lab/wazuh/deploy-rules.sh` copies the rules to `/var/ossec/etc/rules/`, checks the config,
      and restarts the manager.

### 2.3 CI on every push (GitHub-hosted runner, no access to the lab)
- [ ] Start the `wazuh/wazuh-manager:4.14.x` container, mount `detections/wazuh/`
- [ ] For each file in `tests/logtest/`: feed the sample event to `wazuh-logtest` and check that the
      expected rule ID and level fire
- [ ] Fail the build on XML errors or wrong matches. Add a badge.

### 2.4 Live validation, run locally from wazuh01
`validation/run_validation.py`:
1. Check win11-ep is reachable over WinRM
2. For each entry in `tests.yml`: note the time, run `Invoke-AtomicTest <id> -TestNumbers <n>` remotely
3. Wait about 60 seconds, then query the Wazuh indexer (`wazuh-alerts-*`) for that `rule.id` after that time
4. **PASS** if the alert exists, otherwise **FAIL**, then run `-Cleanup`
5. Write `results.json`, a `results.md` table and an **ATT&CK Navigator layer** (green = detected, red = missed)

Never attach a self-hosted runner to this public repo: a pull request from a fork could run code
inside your lab. Commit the live results instead.

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
