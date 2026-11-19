# Purple Team Lab: Wazuh + Atomic Red Team + AI triage

A home lab for detection engineering. Atomic Red Team simulates MITRE ATT&CK techniques on a
Windows endpoint, Wazuh detects them, every custom detection is automatically tested against
the attack it targets, and an AI agent triages the alerts. The agent is benchmarked across
several LLMs through OpenRouter.

> **Status:** Phase 0 done. The Wazuh server (v4.14.10) and a Windows 11 endpoint with Sysmon and
> the Wazuh agent are both built from code, and endpoint telemetry is flowing. Atomic Red Team is
> next. See [BUILD-PLAN.md](BUILD-PLAN.md).

## Stack

| Layer | Tooling |
|---|---|
| Virtualization | VMware Workstation 17, built from code (`ovftool`, `vmrun`, cloud-init) |
| SIEM / XDR | Wazuh 4.14 all-in-one |
| Endpoint telemetry | Sysmon, Windows Security and PowerShell logs, Wazuh agent |
| Adversary emulation | Atomic Red Team (Invoke-AtomicRedTeam) |
| Detection-as-code | Custom Wazuh rules + Sigma, tested with `wazuh-logtest` in GitHub Actions |
| AI triage | Python agent, OpenRouter models, Wazuh MCP server |
| AI attack detection | Promptfoo vs. a vulnerable LLM app, rules mapped to MITRE ATLAS |

## Rebuilding the lab

```powershell
# Wazuh server VM (Ubuntu 24.04 cloud image + cloud-init)
.\lab\build\new-wazuh-vm.ps1
# then, on the VM
bash lab/wazuh/install-wazuh.sh

# Agent group config, then the Windows 11 endpoint (unattended install, Sysmon, Wazuh agent)
.\lab\build\push-wazuh-config.ps1
.\lab\build\new-win11-vm.ps1
```

The Windows build expects the Windows 11 Enterprise Evaluation ISO and a `payloads` folder
(Sysmon, the sysmon-modular config, the Wazuh agent MSI) under `D:\Labs\ISOs`.

Secrets (SSH key, lab passwords) live in `D:\Labs\keys` and never enter this repo.
