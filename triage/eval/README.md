# Triage eval

## Dataset ([`dataset.jsonl`](dataset.jsonl))

Labels come from what the lab already knows, not from judgement calls:

| Label | Source | How it's labelled |
|---|---|---|
| **malicious** (26) | Two live validation runs ([run 1](../../validation/results/validation.md), [run 2](../../validation/results/validation-run2.md)) | Alerts of each test's expected rules inside that test's time window; the ATT&CK technique is the test's |
| **benign** (17) | [`benign-activity.ps1`](../../lab/windows/benign-activity.ps1), window in [`benign-window.json`](benign-window.json) | Every level 8+ alert in the window |

The benign set is made of **hard negatives**: routine admin activity that trips the *same* rules as
the attacks.
- Vendor maintenance tasks running a PowerShell script → `100140`
- OneDrive/Teams/Greenshot autostart entries written with `reg.exe` → `100151`, `92041`
- Management tooling sending an encoded one-liner → `92057`, `92058`
- An EICAR antivirus check → `62123`
- The lab's own WinRM tooling decoding base64 → `91809`, `92201`

A model can't pass by trusting the rule name; it has to look at paths, parents, names and context.

Known limitations:
- Some attack artifacts carry obvious names, such as the "Atomic Red Team" Run value and the
  `T1136.001_CMD` user. A model can key on those, which favours recall more than it would on real
  intrusions.
- Alerts include the rule's own ATT&CK tag, so technique accuracy on custom rules partly measures
  reading the tag. That is also what a human analyst would see.
- 43 alerts is enough to compare models, not to quote precise rates.

## Scoring ([`run_eval.py`](run_eval.py))

| Metric | Meaning |
|---|---|
| Recall | Malicious alerts called `true_positive` or `needs_escalation` (a human still sees them) |
| Strict TP | Malicious alerts called `true_positive` |
| Specificity | Benign alerts called `benign` |
| FP rate | Benign alerts called `true_positive` |
| Technique | Malicious alerts with the right ATT&CK ID (v19 or legacy; the parent technique counts) |

Each run writes `results/<run>/results.jsonl` (every alert, every model, with the model's summary)
and `results/<run>/summary.md`.
