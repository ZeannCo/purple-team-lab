#!/usr/bin/env python3
"""Wazuh integration (integratord): copies the alert into the triage worker's inbox.

Wazuh calls: custom-purplelab-triage <alert_file> <api_key> <hook_url>. Only the alert file is
used. The AI's own verdict alerts are skipped so triage never loops on itself, and so are
inventory-style findings: the vulnerability detector once raised ~740 CVE alerts at level 10+
in one burst, which would have queued hours of model calls.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

INBOX = Path("/var/lib/purplelab/triage/inbox")
SKIP_GROUPS = {"purplelab_triage", "vulnerability-detector", "sca", "syscheck", "rootcheck", "ossec"}


def main() -> int:
    alert = json.loads(Path(sys.argv[1]).read_text())
    if SKIP_GROUPS & set(alert.get("rule", {}).get("groups", [])):
        return 0
    name = f"{alert.get('id', 'alert').replace('.', '-')}-{alert.get('rule', {}).get('id', 'x')}.json"
    # Write then rename so the worker never reads a half-written file
    fd, tmp = tempfile.mkstemp(dir=INBOX, suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(alert, f)
    os.chmod(tmp, 0o640)
    os.rename(tmp, INBOX / name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
