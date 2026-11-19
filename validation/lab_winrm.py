#!/usr/bin/env python3
"""Run a PowerShell script on a lab Windows host over WinRM (NTLM, message-encrypted).

The password is read from the WIN_PASSWORD environment variable so it never appears
on a command line.

    WIN_PASSWORD=... python3 lab_winrm.py script.ps1 [--host 10.10.10.20] [--user labadmin]
"""
import argparse
import os
import sys

import winrm


def run(host: str, user: str, password: str, script: str):
    # Long timeouts: installs and some atomics run for minutes
    session = winrm.Session(f"http://{host}:5985/wsman", auth=(user, password), transport="ntlm",
                            operation_timeout_sec=120, read_timeout_sec=130)
    # Progress records come back as CLIXML noise on stderr; turn them off
    return session.run_ps("$ProgressPreference = 'SilentlyContinue'\n" + script)


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
