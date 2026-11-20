#!/usr/bin/env bash
# Remote access to the Wazuh dashboard over Tailscale: reachable only from devices signed in to
# your tailnet, never from the public internet. Run as labadmin on wazuh01:
#   bash install-tailscale.sh            # install + start login (prints the sign-in link)
#   sudo tailscale down                  # turn remote access off again
#
# Only the dashboard (443) is allowed in over the tunnel. SSH, the indexer (9200), the Wazuh API
# (55000) and the agent ports stay reachable from the lab network only. Tailscale runs with
# --netfilter-mode=off so its own rules don't accept everything on tailscale0 ahead of these.
set -euo pipefail

TS_HOSTNAME="${TS_HOSTNAME:-wazuh01-lab}"

command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sudo sh
sudo systemctl enable --now tailscaled

sudo tee /usr/local/sbin/purplelab-tailscale-fw >/dev/null <<'EOF'
#!/bin/sh
# Inbound over tailscale0: established traffic and the Wazuh dashboard only
for ipt in iptables ip6tables; do
  $ipt -D INPUT -i tailscale0 -j PURPLELAB-TS 2>/dev/null || true
  $ipt -N PURPLELAB-TS 2>/dev/null || $ipt -F PURPLELAB-TS
  $ipt -A PURPLELAB-TS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $ipt -A PURPLELAB-TS -p tcp --dport 443 -j ACCEPT
  $ipt -A PURPLELAB-TS -j DROP
  $ipt -I INPUT 1 -i tailscale0 -j PURPLELAB-TS
done
EOF
sudo chmod 755 /usr/local/sbin/purplelab-tailscale-fw

sudo tee /etc/systemd/system/purplelab-tailscale-fw.service >/dev/null <<'EOF'
[Unit]
Description=Purple team lab: only the Wazuh dashboard is reachable over Tailscale
After=network-pre.target
Before=tailscaled.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/purplelab-tailscale-fw

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now purplelab-tailscale-fw

if sudo tailscale status >/dev/null 2>&1; then
  echo "Already signed in: https://$(sudo tailscale ip -4 | head -1)"
  exit 0
fi

# Login blocks until the sign-in link is used. Run it as a transient systemd unit: a background
# process started over SSH (nohup) died with the session before the link was approved.
sudo systemctl stop purplelab-tailscale-login 2>/dev/null || true
sudo systemd-run --unit=purplelab-tailscale-login --collect \
  tailscale up --hostname="$TS_HOSTNAME" --netfilter-mode=off --accept-dns=false >/dev/null
for _ in $(seq 1 30); do
  url=$(sudo tailscale status 2>/dev/null | grep -o 'https://login.tailscale.com/[^ ]*' | head -1 || true)
  [ -n "$url" ] && { echo "SIGN-IN LINK: $url"; exit 0; }
  sleep 1
done
echo "No sign-in link yet; check: sudo journalctl -u purplelab-tailscale-login" >&2
exit 1
