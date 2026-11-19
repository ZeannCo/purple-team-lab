# Triage eval

## Results ([run 2, clean](results/run-2-clean/summary.md))

26 malicious and 13 benign alerts from the lab; each model triaged all 39 through the same agent
and read-only MCP tools.

| Model | Recall | Specificity | FP rate | Right technique | Median latency | $/alert |
|---|---|---|---|---|---|---|
| `deepseek/deepseek-v4.1-flash` | 100% | 15% | 85% | 92% | 12 s | $0.0026 |
| `qwen/qwen3.8-27b` | 100% | **62%** | **38%** | **96%** | 26 s | $0.0137 |
| `z-ai/glm-5.3-flash` | 100% | 23% | 77% | 92% | 21 s | $0.0020 |
| `anthropic/claude-haiku-5.5` | 100% | 0% | 100% | 88% | 13 s | $0.0037 |

**Every model caught every attack, and most could not clear the benign activity.** The models
judged the *session* rather than the alert: the benign scenario has one remote admin session
create SYSTEM tasks running `-ExecutionPolicy Bypass`, add Run keys, enumerate admin groups and
drop an EICAR file within five minutes. Seen together, that is the shape of an intrusion, and the
models said so ("a chain that also included..."). Qwen3.8 27B was the one model that regularly
judged each item on its own merits: it cleared the Teams/Greenshot Run keys and the PowerShell
policy-probe file. It costs about 5x DeepSeek, which is still under 1.5 cents an alert.

Three of the four models got the one *organic* benign event right in run 1 (Windows' own `sdbinst`
maintenance), which suggests specificity is limited by how compressed the benign scenario is more
than by an inability to recognise routine activity. A fairer benign set would spread the same actions over hours, the way
real administration happens. That is the next improvement.

Total cost of the comparison: about $2.03 for both full runs (4 models × 39-43 alerts), most of it
Qwen3.8 27B ($1.31).

## How the eval was debugged (and why that matters)

The numbers above are the third attempt. The first two measured the test rig, not the models:

| Run | What went wrong | Effect |
|---|---|---|
| [Smoke test 1](results/smoke-1-rig-leakage) | The agent saw the Atomic Red Team framework (and a tuning rule calling it "authorized adversary emulation") and called real attacks benign | 2 of 3 attacks called benign |
| Fix | Prompt states the SOC convention: emulation tooling is a true positive (deconfliction comes later); lab-harness alerts hidden from the tools | [3/3 correct](results/smoke-2-after-fix) |
| [Run 1](results/run-1-contaminated-benign/summary.md) | The benign activity was delivered through the lab's base64 script staging (a genuine decode-and-execute pattern); the script's comments ("hard negatives that trip the same rules") were captured by script block logging; tools searched relative to *now*, so a replayed alert could see the Atomic runs on the same host | 71-100% false positives, with models quoting the comments back |
| Fix | Benign actions sent as plain WinRS commands ([`benign_activity.py`](../../lab/windows/benign_activity.py)); every tool anchored to the alert time with a 2-hour look-back (`TRIAGE_AS_OF`); benign run more than 3 hours after the last attack | Run 2 above |

## Dataset ([`dataset.jsonl`](dataset.jsonl))

Labels come from what the lab already knows, not from judgement calls:

| Label | Source | How it's labelled |
|---|---|---|
| **malicious** (26) | Two live validation runs ([run 1](../../validation/results/validation.md), [run 2](../../validation/results/validation-run2.md)) | Alerts of each test's expected rules inside that test's time window; the ATT&CK technique is the test's |
| **benign** (13) | [`benign_activity.py`](../../lab/windows/benign_activity.py), window in [`benign-window.json`](benign-window.json) | Every level 8+ alert in the window |

The benign alerts are **hard negatives**: routine admin activity that trips the same rules as the
attacks.
- Vendor maintenance tasks running a PowerShell script → `100140`
- OneDrive/Teams/Greenshot autostart entries written with `reg.exe` → `100151`, `92041`
- An EICAR antivirus check → `62123`
- PowerShell's policy-probe file → `92205`

Known limitations:
- Some attack artifacts carry obvious names (the "Atomic Red Team" Run value, the `T1136.001_CMD`
  user), which favours recall.
- Alerts include the rule's own ATT&CK tag, so technique accuracy partly measures reading the tag.
  That is also what an analyst sees.
- 39 alerts is enough to compare models, not to quote precise rates.

## Scoring ([`run_eval.py`](run_eval.py))

| Metric | Meaning |
|---|---|
| Recall | Malicious alerts called `true_positive` or `needs_escalation` (a human still sees them) |
| Specificity | Benign alerts called `benign` |
| FP rate | Benign alerts called `true_positive` |
| Right technique | Malicious alerts with the right ATT&CK ID (v19 or legacy; the parent technique counts) |
