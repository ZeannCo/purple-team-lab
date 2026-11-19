# Purple Team Lab: Wazuh + Atomic Red Team + AI triage

[![detections](https://github.com/ZeannCo/purple-team-lab/actions/workflows/detections.yml/badge.svg)](https://github.com/ZeannCo/purple-team-lab/actions/workflows/detections.yml)

A home lab for detection engineering. Atomic Red Team runs MITRE ATT&CK techniques on a Windows 11
endpoint, Wazuh detects them, and every detection is proven twice:
- **live**, by running the attack and checking the expected alert reaches the indexer
- **in CI**, by replaying real captured events through a throwaway Wazuh manager

An AI agent that triages the alerts through OpenRouter is next.

> **Status:** Phases 0-2 done. The lab is built from code; 11 Atomic Red Team tests across 10
> techniques all PASS live against custom rules, and 25 replay cases pass in CI.
> See [BUILD-PLAN.md](BUILD-PLAN.md).

## Results

| | Built-in Wazuh rules ([baseline](validation/results/baseline.md)) | After tuning + custom rules ([validation](validation/results/validation.md)) |
|---|---|---|
| Tests with a meaningful, ATT&CK-tagged alert | 3 of 11 | **11 of 11** (level 8-14) |
| Seen only as untagged Defender alerts | 4 | 0 |
| Only low severity (level 3-5) | 3 | 0 |
| Missed | 1 | 0 |
| Harness false positives in every test window | 3 rules, up to level 15 | 0 (tuned or attributed to the harness by a control step) |

The raw baseline first reported 8 of 11 as "detected". Most of that came from noise the test
harness itself caused, including a level-15 alert on a file PowerShell writes every time it starts.
How that was found and fixed, why four attacks needed Defender-aware rules, and the Wazuh quirks hit
along the way are written up in [docs/detection-engineering-notes.md](docs/detection-engineering-notes.md).

ATT&CK coverage layer (import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)):
[`validation/results/validation-navigator-layer.json`](validation/results/validation-navigator-layer.json)

## Stack

| Layer | Tooling |
|---|---|
| Virtualization | VMware Workstation 17, built from code (`ovftool`, `vmrun`, cloud-init, unattended Windows setup) |
| SIEM / XDR | Wazuh 4.14.10 all-in-one |
| Endpoint telemetry | Sysmon 15 (sysmon-modular), Windows Security, PowerShell script block logging, Defender |
| Adversary emulation | Atomic Red Team (Invoke-AtomicRedTeam 2.1, ATT&CK v19) |
| Detection-as-code | Custom Wazuh rules in [`detections/wazuh`](detections/wazuh), replayed with `logtest` in GitHub Actions |
| Live validation | [`validation/run_validation.py`](validation/run_validation.py): runs each atomic over WinRM, checks the indexer for its expected rules |
| AI triage (next) | Python agent, OpenRouter models, Wazuh MCP server |
| AI attack detection (planned) | Promptfoo vs. a vulnerable LLM app, rules mapped to MITRE ATLAS |

## Layout

```
detections/wazuh/      9900 lab tuning, 9910 detections (each rule cites the test that proves it)
tests/logtest/         replay cases from real lab events + ci.sh (throwaway manager in Docker)
validation/            tests.yml (atomic -> expected rules), runner, results
lab/build/             VM builds, config/rule deployment, validation wrapper (PowerShell)
lab/windows/           autounattend.xml, first-boot bootstrap, Atomic Red Team install
lab/wazuh/             manager install, centralized agent config
docs/                  detection engineering notes
```

## Rebuilding the lab

```powershell
# Wazuh server VM (Ubuntu 24.04 cloud image + cloud-init), then on the VM: bash lab/wazuh/install-wazuh.sh
.\lab\build\new-wazuh-vm.ps1

# Agent group config + custom rules, then the Windows 11 endpoint (unattended install, Sysmon, Wazuh agent)
.\lab\build\push-wazuh-config.ps1
.\lab\build\new-win11-vm.ps1

# Atomic Red Team on the endpoint, then a full validation run
Import-Module .\lab\build\LabCommon.psm1
Invoke-LabWindows -Script (Get-Content .\lab\windows\install-atomics.ps1 -Raw)
.\lab\build\Invoke-Validation.ps1 -Label validation
```

The Windows build expects the Windows 11 Enterprise Evaluation ISO and a `payloads` folder
(Sysmon, the sysmon-modular config, the Wazuh agent MSI) under `D:\Labs\ISOs`. Secrets (SSH key,
lab passwords) live in `D:\Labs\keys` and never enter this repo.
