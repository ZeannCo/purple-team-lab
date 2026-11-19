#!/usr/bin/env bash
# Installs Wazuh all-in-one (manager + indexer + dashboard) on wazuh01.
# Run on the VM as labadmin: bash install-wazuh.sh
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14}"
WORKDIR="${HOME}/wazuh-install"

mkdir -p "$WORKDIR" && cd "$WORKDIR"
curl -sSfO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
sudo bash ./wazuh-install.sh -a

# The installer writes every generated password into this archive; keep it root-only
sudo chmod 600 wazuh-install-files.tar
echo
echo "Wazuh ${WAZUH_VERSION} installed. Dashboard: https://192.168.110.10 (user: admin)"
echo "Passwords: sudo tar -O -xf ${WORKDIR}/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt"
