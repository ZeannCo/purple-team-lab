#!/usr/bin/env python3
"""Wazuh integration (integratord): copies the alert into the triage worker's inbox.

Wazuh calls: custom-purplelab-triage <alert_file> <api_key> <hook_url>. Only the alert file is
used. The AI's own verdict alerts are skipped so triage never loops on itself.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

INBOX = Path("/var/lib/purplelab/triage/inbox")


def main() -> int:
    alert = json.loads(Path(sys.argv[1]).read_text())
    if "purplelab_triage" in alert.get("rule", {}).get("groups", []):
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
