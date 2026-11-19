# Detection engineering notes

What running Atomic Red Team against a default Wazuh 4.14 + Sysmon setup actually showed, and what
was changed because of it. Results: [baseline](../validation/results/baseline.md) (built-in rules
only) and [validation](../validation/results/validation.md) (after the custom rules).

## 1. The raw baseline over-reported coverage

The first run classified 8 of 11 tests as "detected": an alert tagged with the test's ATT&CK
technique fired inside the test's time window. Three rules, though, fired in **every** window,
including during steps that executed nothing:

| Rule | Level | What it really was |
|---|---|---|
| `92213` "Executable file dropped in folder commonly used by malware" (tagged T1105) | 15 | PowerShell writing `%TEMP%\__PSScriptPolicyTest_<random>.ps1`, a probe file it creates on every non-interactive start |
| `91822` "Powershell used Invoke-Command" (tagged T1059.001) | 12 | Script block logging capturing Invoke-AtomicRedTeam's own module source |
| `92657` "NTLM remote logon, possible pass-the-hash" | 6 | The validation runner's WinRM logon from the management host, 10.10.10.10 |

Two of those carry ATT&CK tags, so they handed out credit they hadn't earned: the certutil
download (T1105) looked "detected" only because of the PowerShell probe file. With the harness
noise removed, the honest baseline was: **3 detected with a meaningful rule, 4 visible only as
untagged Defender alerts, 3 detected at level 3-5, 1 missed.**

**Changes:**
- [`9900-purplelab_tuning.xml`](../detections/wazuh/9900-purplelab_tuning.xml) suppresses the probe
  file by exact pattern and downgrades the management-host logon and the Atomic Red Team module
  source to level 3, in a `lab_harness` group. The module source stays visible because outside a lab,
  Atomic Red Team turning up on a host is worth knowing about.
- The runner now starts every run with a **control step**: the same WinRM + `Invoke-AtomicTest` path
  with nothing executed. Rules that fire there are attributed to the harness, not to an atomic.

## 2. Defender stopped four attacks before Sysmon could see them

The LSASS dump (comsvcs MiniDump), rundll32 + mshtml, certutil download and the malicious-cmdlet
script were all blocked by Microsoft Defender on the **parent** `cmd.exe`/`powershell.exe` command
line (`RundllLolBin.AF`, `Powessere.G`, `Ceprolad.A`, `Mimikatz.A`). `rundll32` and `certutil` never
started, so Sysmon had nothing to log and the custom Sysmon rules had nothing to match.

The only evidence was Defender event 1116. Wazuh's built-in rule `62123` catches it at level 12, but
with no ATT&CK tag and an empty threat name in its description. The rule reads `threatName`, while
the decoded field is really `threat Name`, with a space.

**Changes:** `100201`-`100204` turn each Defender block into a tagged alert, mapped to the technique
by the blocked command line or threat name. The Sysmon rules for the same attacks (`100110`,
`100120`, `100130`, `100180`) are kept for hosts where Defender is absent or bypassed, and proven by
replay (section 5), so the coverage claim doesn't rest on Defender.

## 3. A custom rule can lose to a built-in sibling

`100150` (Run key persistence, level 10) never fired on the `reg.exe` Run-key event: the event
matched the built-in `92302` (level 6) instead and went down that branch. Attaching the same logic
under `92302` (`100151`) fixed it. Every custom rule now has a replayed event in CI, so a rule
silently losing this race fails the build instead of going unnoticed.

## 4. The Wazuh agent tripped the first discovery rule

The first version of `100190` (three `net` discovery commands in 60 s) fired during the control
step, with no test running. The cause was the Wazuh agent: `wazuh-agent.exe` runs `net user` for its
own inventory. `100188` drops agent-spawned commands, and `100189`/`100190` now count only
enumeration commands (`user`, `localgroup`, `group`, `accounts`) without `/add` or `/del`, and only
distinct command lines.

## 5. Testing Windows rules in CI: logtest can't decode eventchannel

`wazuh-logtest` cannot run the built-in `windows_eventchannel` decoder, so a replayed Windows event
falls through to the JSON decoder and no Windows rule ever matches ([Wazuh Google Group](https://groups.google.com/g/wazuh/c/s14Vj4gCiV0), [wazuh/wazuh#3665](https://github.com/wazuh/wazuh/issues/3665)).
The known workaround of changing base rule `60000` to `decoded_as json` is not enough on 4.14: the
rule also requires `<category>ossec</category>`, which JSON-decoded events don't have. Removing both
inside a throwaway `wazuh/wazuh-manager:4.14.10` container makes replay work.
[`tests/logtest/ci.sh`](../tests/logtest/ci.sh) does exactly that and is used both by GitHub Actions and on
the lab manager. The live manager is never patched.

The fixtures are the `data.win` object of real alerts from the lab
([`harvest.py`](../tests/logtest/harvest.py)), which already carry the eventchannel decoder's escaping
(doubled backslashes). The only synthesized events are the four processes Defender blocked; each is
a real Sysmon event of the same type with only the command line swapped, and is labelled as such.

## 6. ATT&CK v19 renumbered two of the techniques

Atomic Red Team moved to ATT&CK v19 in May 2026: T1070.001 (Clear Windows Event Logs) became
**T1685.005** and T1562.001 (Disable or Modify Tools) became **T1685**. Wazuh 4.14's built-in rules
still use the old IDs. The tests use the v19 IDs, list the legacy ID next to them, and the custom
rules carry both so coverage lines up in either version.

## 7. Wazuh quirks hit along the way

- Custom rule files load in one sorted list with the built-in ruleset. Files named `0900-*` loaded
  before the built-in PowerShell rules (`0915-*`), so their `if_sid` parents didn't exist yet and the
  rules were silently dropped. The custom files use `99xx-`.
- With the laptop busy running two VMs, the manager took longer than systemd's default 90 s to start.
  The install script now sets `TimeoutStartSec=300`.
- Event fields keep doubled backslashes after decoding, so a rule matching `C:\Windows` needs
  `C:\\\\Windows` in PCRE2, as the built-in rules do.
