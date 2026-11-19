#!/usr/bin/env bash
# Starts a throwaway Wazuh manager with this repo's rules and replays tests/logtest/cases through
# logtest. Used by GitHub Actions and runnable on wazuh01 (any host with Docker and Python 3).
#
#   tests/logtest/ci.sh            # from the repo root
#   API_PORT=55001 tests/logtest/ci.sh   # when 55000 is taken (e.g. on the lab manager itself)
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14.10}"          # same build as the lab manager
API_PORT="${API_PORT:-55000}"
NAME="${CONTAINER_NAME:-purplelab-logtest}"
PYTHON="${PYTHON:-python3}"
export WAZUH_API_USER="${WAZUH_API_USER:-wazuh-wui}"
export WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-CI-only.Passw0rd!}"   # throwaway container, never exposed
repo="$(cd "$(dirname "$0")/../.." && pwd)"

cleanup() {
  if [ "${rc:-0}" -ne 0 ]; then docker exec "$NAME" tail -n 60 /var/ossec/logs/ossec.log || true; fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap 'rc=$?; cleanup' EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$API_PORT:55000" \
  -e API_USERNAME="$WAZUH_API_USER" -e API_PASSWORD="$WAZUH_API_PASSWORD" \
  -v "$repo/detections/wazuh:/repo-rules:ro" \
  "wazuh/wazuh-manager:$WAZUH_VERSION" >/dev/null

echo "Waiting for the manager API ..."
for _ in $(seq 1 60); do
  curl -skf -o /dev/null -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" \
    -X POST "https://127.0.0.1:$API_PORT/security/user/authenticate" && break
  sleep 5
done

# logtest cannot run the built-in windows_eventchannel decoder, so Windows events reach the JSON
# decoder instead. Workaround: let Windows base rule 60000 accept JSON-decoded events (decoded_as
# json, and drop its <category>ossec</category>, which JSON events never have in 4.14).
# This only ever touches the throwaway container.
docker exec "$NAME" bash -c '
  set -e
  base=/var/ossec/ruleset/rules/0575-win-base_rules.xml
  sed -i "s|<decoded_as>windows_eventchannel</decoded_as>|<decoded_as>json</decoded_as>|" "$base"
  sed -i "/<rule id=\"60000\"/,/<\/rule>/{/<category>ossec<\/category>/d}" "$base"
  install -o wazuh -g wazuh -m 660 /repo-rules/*.xml /var/ossec/etc/rules/
  /var/ossec/bin/wazuh-analysisd -t
  /var/ossec/bin/wazuh-control restart >/dev/null'

echo "Waiting for analysisd ..."
for _ in $(seq 1 30); do
  docker exec "$NAME" /var/ossec/bin/wazuh-control status | grep -q "wazuh-analysisd is running" && break
  sleep 2
done
sleep 10

"$PYTHON" "$repo/tests/logtest/run_logtest.py" --api "https://127.0.0.1:$API_PORT" --user "$WAZUH_API_USER"
