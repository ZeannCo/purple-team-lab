#!/usr/bin/env python3
"""Routine admin activity on win11-ep that trips the same rules as the atomics: the hard negatives
for the AI triage eval.

Each action is a plain command sent over WinRS (pywinrm run_cmd): no PowerShell wrapper, no
encoding, no staged script, no comments that end up in the endpoint's logs. A first version ran
through the lab's base64 script staging, which made the "benign" activity look like a genuine
decode-and-execute chain (see triage/eval/README.md).

    WIN_PASSWORD=... python3 benign_activity.py --window-out benign-window.json
"""
import argparse
import base64
import datetime as dt
import json
import os
import sys
import time

import winrm

RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
ROUNDS = [
    {"vendor": "Contoso", "task": "NightlyBackup", "script": "backup.ps1", "run_name": "OneDrive",
     "run_data": r'\"C:\Program Files\Microsoft OneDrive\OneDrive.exe\" /background',
     "groups": ("Administrators", "Remote Desktop Users"),
     "check": "Get-Service WinRM,Sysmon64,WazuhSvc | Select-Object Name,Status"},
    {"vendor": "Fabrikam", "task": "ReportUpload", "script": "upload-reports.ps1", "run_name": "Teams",
     "run_data": r'\"C:\Program Files\WindowsApps\MSTeams\ms-teams.exe\" --system-initiated',
     "groups": ("Users", "Backup Operators"),
     "check": "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3"},
    {"vendor": "Northwind", "task": "LogRotate", "script": "rotate-logs.ps1", "run_name": "GreenshotUpdater",
     "run_data": r'\"C:\Program Files\Greenshot\Greenshot.exe\" /startup',
     "groups": ("Administrators", "Event Log Readers"),
     "check": "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,LastBootUpTime"},
]


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="10.10.10.20")
    parser.add_argument("--user", default="labadmin")
    parser.add_argument("--window-out", required=True)
    args = parser.parse_args()
    session = winrm.Session(f"http://{args.host}:5985/wsman", auth=(args.user, os.environ["WIN_PASSWORD"].strip("\r\n")),
                            transport="ntlm", operation_timeout_sec=60, read_timeout_sec=70)

    def run(command: str, *cmd_args: str, pause: int = 10) -> None:
        result = session.run_cmd(command, list(cmd_args))
        status = "ok" if result.status_code == 0 else f"exit {result.status_code}"
        print(f"  {command} {' '.join(cmd_args)[:90]} -> {status}", flush=True)
        time.sleep(pause)

    start = utc()
    for r in ROUNDS:
        folder = rf"C:\ProgramData\{r['vendor']}\Scripts"
        print(f"{r['vendor']}:", flush=True)
        run("cmd", "/c", f'mkdir "{folder}" 2>nul & echo Write-Output "{r["vendor"]} maintenance job" > "{folder}\\{r["script"]}"', pause=2)
        # Vendor maintenance task running a PowerShell script (trips 100140)
        run("schtasks", "/Create", "/F", "/SC", "DAILY", "/ST", "02:00", "/RU", "SYSTEM", "/TN", f'"{r["vendor"]}\\{r["task"]}"',
            "/TR", f'"powershell.exe -NoProfile -ExecutionPolicy Bypass -File {folder}\\{r["script"]}"')
        # Installer-style autostart entry for a known product (trips 100151 / 92041)
        run("reg", "add", RUN_KEY, "/v", r["run_name"], "/t", "REG_SZ", "/f", "/d", f'"{r["run_data"]}"')
        # Helpdesk checking an account and its groups (net.exe)
        run("cmd", "/c", f'net user {args.user} & net localgroup "{r["groups"][0]}" & net localgroup "{r["groups"][1]}"')
        # Management tooling sending a read-only check as an encoded command (trips 92057)
        encoded = base64.b64encode(r["check"].encode("utf-16-le")).decode()
        run("cmd", "/c", f"powershell.exe -NoProfile -EncodedCommand {encoded}", pause=40)

    # Antivirus check with the industry-standard EICAR test file (Defender detection, 62123)
    eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    run("powershell.exe", "-NoProfile", "-Command",
        f"\"Set-Content -Path $env:PUBLIC\\Documents\\av-check.txt -NoNewline -Value '{eicar}'\"", pause=20)

    for r in ROUNDS:
        run("schtasks", "/Delete", "/F", "/TN", f'"{r["vendor"]}\\{r["task"]}"', pause=1)
        run("reg", "delete", RUN_KEY, "/v", r["run_name"], "/f", pause=1)
        run("cmd", "/c", f'rmdir /s /q "C:\\ProgramData\\{r["vendor"]}"', pause=1)
    run("cmd", "/c", r"del /f /q %PUBLIC%\Documents\av-check.txt", pause=1)

    time.sleep(45)  # let the last events reach the indexer
    window = {"start": start, "end": utc()}
    with open(args.window_out, "w") as f:
        json.dump(window, f)
    print(f"benign window {window['start']} -> {window['end']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
