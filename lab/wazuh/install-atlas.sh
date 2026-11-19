#!/usr/bin/env bash
# Builds and runs HelpBot (atlas/app) on wazuh01 and has the manager collect its log.
# Run as labadmin: bash install-atlas.sh /opt/purplelab/atlas-src
# The OpenRouter key is written to /etc/purplelab/helpbot.env by deploy-atlas.ps1 (stdin).
set -euo pipefail

SRC="${1:?usage: install-atlas.sh <dir containing app/>}"
LOGDIR=/var/log/purplelab/llmapp
ENVFILE=/etc/purplelab/helpbot.env

sudo docker build -q -t purplelab/helpbot:latest "$SRC/app" >/dev/null

# The container runs as uid 10001 and may only write its log; the manager reads it
sudo mkdir -p "$LOGDIR"
sudo touch "$LOGDIR/llm-app.json"
sudo chown -R 10001:wazuh "$LOGDIR"
sudo chmod 750 "$LOGDIR"
sudo chmod 640 "$LOGDIR/llm-app.json"

sudo docker rm -f helpbot >/dev/null 2>&1 || true
# Deliberately vulnerable app, so it gets a tight box: read-only root, no capabilities,
# no privilege escalation, capped memory, reachable from this host only
sudo docker run -d --name helpbot --restart unless-stopped \
  -p 127.0.0.1:8090:8090 --env-file "$ENVFILE" \
  -v "$LOGDIR:/logs" --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges --memory 512m --pids-limit 128 \
  purplelab/helpbot:latest >/dev/null

if ! sudo grep -q 'purplelab-atlas BEGIN' /var/ossec/etc/ossec.conf; then
  sudo tee -a /var/ossec/etc/ossec.conf >/dev/null <<'EOF'

<!-- purplelab-atlas BEGIN -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/purplelab/llmapp/llm-app.json</location>
  </localfile>
</ossec_config>
<!-- purplelab-atlas END -->
EOF
  sudo /var/ossec/bin/wazuh-analysisd -t
  sudo systemctl restart wazuh-manager
fi

for _ in $(seq 1 30); do
  curl -sf http://127.0.0.1:8090/health && echo && exit 0
  sleep 2
done
echo "HelpBot did not become healthy" >&2
sudo docker logs --tail 30 helpbot >&2
exit 1
