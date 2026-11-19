#!/usr/bin/env bash
# Installs the AI triage pipeline on wazuh01. Run as labadmin from the folder holding triage/:
#   bash install-triage.sh /opt/purplelab/src
# Idempotent. The OpenRouter key is written separately (deploy-triage.ps1 pipes it in).
set -euo pipefail

SRC="${1:?usage: install-triage.sh <dir containing triage/ and detections/>}"
APP=/opt/purplelab/triage
VENV=/opt/purplelab/triage-venv
SPOOL=/var/lib/purplelab/triage
LOGDIR=/var/log/purplelab
ENVFILE=/etc/purplelab/triage.env
SVC_USER=purplelab-triage

# --- service user (can drop files into the wazuh-owned inbox through the wazuh group)
id "$SVC_USER" >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
sudo usermod -aG wazuh "$SVC_USER"

# --- code + venv
sudo mkdir -p "$APP"
sudo cp "$SRC"/triage/*.py "$SRC"/triage/requirements.txt "$APP"/
[ -x "$VENV/bin/python" ] || sudo python3 -m venv "$VENV"
sudo "$VENV/bin/pip" install -q -r "$APP/requirements.txt"

# --- spool (integratord writes as wazuh; the worker reads and moves as purplelab-triage)
sudo mkdir -p "$SPOOL"/{inbox,done,error} "$LOGDIR"
sudo chown -R "$SVC_USER":wazuh "$SPOOL"
sudo chmod 2770 "$SPOOL" "$SPOOL"/{inbox,done,error}
sudo chown "$SVC_USER":wazuh "$LOGDIR"
sudo chmod 750 "$LOGDIR"

# --- integration script
sudo install -o root -g wazuh -m 750 "$SRC"/triage/integration/custom-purplelab-triage /var/ossec/integrations/
sudo install -o root -g wazuh -m 750 "$SRC"/triage/integration/custom-purplelab-triage.py /var/ossec/integrations/

# --- read-only indexer account for the agent (alerts index only)
ADMIN_PW=$(sudo tar -O -xf "$HOME/wazuh-install/wazuh-install-files.tar" wazuh-install-files/wazuh-passwords.txt \
  | grep -A1 "username: 'admin'" | grep password | cut -d"'" -f2)
sudo mkdir -p /etc/purplelab
if ! sudo test -f "$ENVFILE" || ! sudo grep -q '^INDEXER_PASSWORD=' "$ENVFILE"; then
  TRIAGE_PW="$(openssl rand -base64 18 | tr -d '/+=')Aa1."
  api() { curl -skf -u "admin:$ADMIN_PW" -H 'Content-Type: application/json' -X PUT "https://127.0.0.1:9200/_plugins/_security/api/$1" -d "$2" >/dev/null; }
  api roles/purplelab_alerts_read '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read"]}]}'
  api internalusers/purplelab_triage "{\"password\":\"$TRIAGE_PW\",\"backend_roles\":[]}"
  api rolesmapping/purplelab_alerts_read '{"users":["purplelab_triage"]}'
  printf 'INDEXER_USER=purplelab_triage\nINDEXER_PASSWORD=%s\nTRIAGE_MODEL=anthropic/claude-haiku-5.5\n' "$TRIAGE_PW" | sudo tee "$ENVFILE" >/dev/null
fi
sudo chown root:"$SVC_USER" "$ENVFILE"
sudo chmod 640 "$ENVFILE"

# --- manager config: integration + read verdicts back
if ! sudo grep -q 'purplelab-triage BEGIN' /var/ossec/etc/ossec.conf; then
  sudo tee -a /var/ossec/etc/ossec.conf >/dev/null <<'EOF'

<!-- purplelab-triage BEGIN -->
<ossec_config>
  <integration>
    <name>custom-purplelab-triage</name>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/purplelab/triage.json</location>
  </localfile>
</ossec_config>
<!-- purplelab-triage END -->
EOF
fi

# --- worker service
sudo tee /etc/systemd/system/purplelab-triage.service >/dev/null <<EOF
[Unit]
Description=Purple team lab AI triage worker
After=network-online.target wazuh-manager.service

[Service]
User=$SVC_USER
Group=wazuh
EnvironmentFile=$ENVFILE
WorkingDirectory=$APP
ExecStart=$VENV/bin/python $APP/worker.py
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$SPOOL $LOGDIR
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload

sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
if sudo grep -q '^OPENROUTER_API_KEY=.\+' "$ENVFILE"; then
  sudo systemctl enable --now purplelab-triage
  sudo systemctl restart purplelab-triage
  echo "triage worker running"
else
  echo "triage worker installed but not started: no OPENROUTER_API_KEY in $ENVFILE yet"
fi
