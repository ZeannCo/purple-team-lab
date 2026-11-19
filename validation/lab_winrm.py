#!/usr/bin/env python3
"""Run a PowerShell script on a lab Windows host over WinRM (NTLM, message-encrypted).

The password is read from the WIN_PASSWORD environment variable so it never appears
on a command line.

    WIN_PASSWORD=... python3 lab_winrm.py script.ps1 [--host 10.10.10.20] [--user labadmin]
"""
import argparse
import base64
import os
import sys
import uuid

import winrm

# run_ps sends the script as one "powershell -EncodedCommand" argument (UTF-16, then base64: about
# 2.7x the script length), and Windows caps a command line at 8191 characters. Longer scripts are
# staged to a temp file in chunks small enough to survive that same encoding, then run from there.
INLINE_LIMIT = 2500
CHUNK = 2000


def run(host: str, user: str, password: str, script: str):
    # Long timeouts: installs and some atomics run for minutes
    session = winrm.Session(f"http://{host}:5985/wsman", auth=(user, password), transport="ntlm",
                            operation_timeout_sec=120, read_timeout_sec=130)
    # Progress records come back as CLIXML noise on stderr; turn them off
    script = "$ProgressPreference = 'SilentlyContinue'\n" + script
    if len(script) <= INLINE_LIMIT:
        return session.run_ps(script)

    path = rf"C:\Windows\Temp\lab-{uuid.uuid4().hex}.ps1"
    payload = base64.b64encode(script.encode("utf-8")).decode()
    for i in range(0, len(payload), CHUNK):
        staged = session.run_ps(f"Add-Content -Path '{path}.b64' -Value '{payload[i:i + CHUNK]}' -NoNewline")
        if staged.status_code != 0:
            return staged
    return session.run_ps(
        f"$b = [IO.File]::ReadAllText('{path}.b64'); "
        f"[IO.File]::WriteAllBytes('{path}', [Convert]::FromBase64String($b)); "
        f"try {{ & '{path}' }} finally {{ Remove-Item '{path}', '{path}.b64' -Force -ErrorAction SilentlyContinue }}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("script", help="PowerShell script file to run")
    parser.add_argument("--host", default="10.10.10.20")
    parser.add_argument("--user", default="labadmin")
    args = parser.parse_args()

    # Strip line endings: a password piped from Windows arrives with a trailing \r
    password = os.environ.get("WIN_PASSWORD", "").strip("\r\n")
    if not password:
        print("WIN_PASSWORD is not set", file=sys.stderr)
        return 2

    with open(args.script, encoding="utf-8") as f:
        result = run(args.host, args.user, password, f.read())
    sys.stdout.write(result.std_out.decode("utf-8", "replace"))
    sys.stderr.write(result.std_err.decode("utf-8", "replace"))
    return result.status_code


if __name__ == "__main__":
    sys.exit(main())
