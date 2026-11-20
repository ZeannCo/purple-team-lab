# Purple Team Lab: Wazuh + Atomic Red Team + AI triage + AI attack detection

[![detections](https://github.com/ZeannCo/purple-team-lab/actions/workflows/detections.yml/badge.svg)](https://github.com/ZeannCo/purple-team-lab/actions/workflows/detections.yml)

A home lab for detection engineering, built entirely from code on VMware. It has three parts:

1. **Endpoint detections:** Atomic Red Team runs MITRE ATT&CK techniques on a Windows 11 endpoint,
   and Wazuh detects them. Every detection is proven live (run the attack, check the alert) and in
   CI (replay real captured events through a throwaway Wazuh manager).
2. **AI triage:** high-severity alerts are investigated by an LLM agent (OpenRouter) through a
   read-only MCP server. Its verdict comes back into Wazuh, and four models are benchmarked on
   labelled lab alerts.
3. **Attacks on AI:** a deliberately vulnerable LLM agent is attacked with prompt injection,
   jailbreaks and tool misuse, and the attacks are detected with rules mapped to MITRE ATLAS.

> **Status:** all phases built and validated. See [BUILD-PLAN.md](BUILD-PLAN.md).

## Results

**Endpoint detections:** [baseline](validation/results/baseline.md) vs. [validated](validation/results/validation.md)

| | Built-in Wazuh rules | After tuning + custom rules |
|---|---|---|
| Atomic tests with a meaningful, ATT&CK-tagged alert | 3 of 11 | **11 of 11** (level 8-14, two runs) |
| Seen only as untagged Defender alerts | 4 | 0 |
| Only low severity (level 3-5) | 3 | 0 |
| Missed | 1 | 0 |
| Harness false positives in every test window | 3 rules, up to level 15 | 0 |

The raw baseline first reported 8 of 11 as "detected"; most of that was noise caused by the test
harness itself. See [docs/detection-engineering-notes.md](docs/detection-engineering-notes.md).

**AI triage:** 39 labelled alerts, [details](triage/eval/README.md)

| Model | Recall | Specificity | $/alert |
|---|---|---|---|
| DeepSeek V4.1 Flash (default) | 100% | 15% | $0.0026 |
| Qwen3.8 27B | 100% | **62%** | $0.0137 |
| GLM 5.3 Flash | 100% | 23% | $0.0020 |
| Claude Haiku 5.5 | 100% | 0% | $0.0037 |

Every model caught every attack; telling routine admin work apart from an attack was the hard
part. The first two eval runs measured the test rig instead of the models, and the
[eval write-up](triage/eval/README.md) covers how that was found.

**Attacks on AI (MITRE ATLAS):** [details](atlas/README.md)

| HelpBot model | Attacks detected | Benign prompts quiet | Attacks that succeeded (all detected) |
|---|---|---|---|
| DeepSeek V4.1 Flash | 6/6 | 4/4 | 0/6 |
| Qwen3-14B | 6/6 | 4/4 | 3/6: system prompt leak, credential theft, exfiltration |

ATT&CK coverage layer (import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)):
[`validation/results/validation-navigator-layer.json`](validation/results/validation-navigator-layer.json)

## Stack

| Layer | Tooling |
|---|---|
| Virtualization | VMware Workstation 17, built from code (`ovftool`, `vmrun`, cloud-init, unattended Windows setup) |
| SIEM / XDR | Wazuh 4.14.10 all-in-one |
| Endpoint telemetry | Sysmon 15 (sysmon-modular), Windows Security, PowerShell script block logging, Defender |
| Adversary emulation | Atomic Red Team (Invoke-AtomicRedTeam 2.1, ATT&CK v19) |
| Detection-as-code | Custom Wazuh rules in [`detections/wazuh`](detections/wazuh), 41 replay cases with `logtest` in GitHub Actions |
| Live validation | [`validation/run_validation.py`](validation/run_validation.py) (endpoint), [`atlas/run_attacks.py`](atlas/run_attacks.py) (AI app) |
| AI triage | Python agent, OpenRouter, read-only MCP server (Python SDK v2), Wazuh integration + worker ([`triage/`](triage)) |
| AI attack detection | HelpBot (FastAPI + MCP tools in Docker), rules mapped to MITRE ATLAS 5.6.0 ([`atlas/`](atlas)) |

## Layout

```
detections/wazuh/      9900 lab tuning, 9910 endpoint detections, 9920 AI verdicts, 9930 ATLAS
tests/logtest/         replay cases from real lab events + ci.sh (throwaway manager in Docker)
validation/            tests.yml (atomic -> expected rules), runner, results
triage/                AI triage agent, MCP server, worker, Wazuh integration, eval
atlas/                 HelpBot (vulnerable LLM agent), attack suite, results
lab/build/             VM builds and deployment scripts (PowerShell)
lab/windows/           autounattend.xml, bootstrap, Atomic Red Team install, benign activity
lab/wazuh/             manager, triage and HelpBot installers, centralized agent config
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

# AI parts: copy .env.example to .env and add an OpenRouter key first
.\lab\build\deploy-triage.ps1          # triage worker
.\lab\build\deploy-atlas.ps1           # HelpBot + ATLAS rules
.\lab\build\Invoke-AtlasAttacks.ps1    # attack suite
```

## Remote access

[`lab/wazuh/install-tailscale.sh`](lab/wazuh/install-tailscale.sh) puts the Wazuh VM on a private
Tailscale network so the dashboard can be opened from a phone or another laptop signed in to the
same account. Nothing is exposed to the public internet. Only the dashboard (443) is allowed in over
the tunnel; SSH, the indexer, the Wazuh API and the agent ports are dropped on `tailscale0`.
`sudo tailscale down` on the VM turns it off.

The Windows build expects the Windows 11 Enterprise Evaluation ISO and a `payloads` folder
(Sysmon, the sysmon-modular config, the Wazuh agent MSI) under `D:\Labs\ISOs`. Secrets (SSH key,
lab passwords) live in `D:\Labs\keys`; the OpenRouter key lives in the gitignored `.env`. None of
them enter this repo.
