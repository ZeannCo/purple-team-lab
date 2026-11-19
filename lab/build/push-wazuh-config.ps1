<#
.SYNOPSIS
  Pushes this repo's Wazuh content to wazuh01:
    - lab\wazuh\shared\<group>\agent.conf  -> centralized agent config (groups created if missing)
    - detections\wazuh\*.xml               -> /var/ossec/etc/rules/
  Rules are checked with wazuh-analysisd -t before the manager restarts; on a failed check the
  previous rules are put back and the manager is left untouched.
#>
[CmdletBinding()]
param(
    [string]$WazuhHost = '192.168.110.10',
    [string]$SshKey    = 'D:\Labs\keys\purplelab_ed25519'
)

$ErrorActionPreference = 'Stop'
$repo   = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$target = "labadmin@$WazuhHost"

ssh -i $SshKey $target 'rm -rf /tmp/purplelab-push && mkdir -p /tmp/purplelab-push/rules'
scp -q -r -i $SshKey (Join-Path $repo 'lab\wazuh\shared') "${target}:/tmp/purplelab-push/shared"
scp -q -i $SshKey (Get-ChildItem (Join-Path $repo 'detections\wazuh') -Filter *.xml).FullName "${target}:/tmp/purplelab-push/rules/"
if ($LASTEXITCODE -ne 0) { throw "scp failed ($LASTEXITCODE)" }

$remote = @'
set -euo pipefail
cd /tmp/purplelab-push
for dir in shared/*/; do
  group=$(basename "$dir")
  sudo test -d "/var/ossec/etc/shared/$group" || sudo /var/ossec/bin/agent_groups -a -g "$group" -q
  sudo install -o wazuh -g wazuh -m 660 "$dir/agent.conf" "/var/ossec/etc/shared/$group/agent.conf"
  sudo /var/ossec/bin/verify-agent-conf -f "/var/ossec/etc/shared/$group/agent.conf" >/dev/null
  echo "agent group $group: agent.conf deployed"
done

backup=$(mktemp -d)
sudo cp -a /var/ossec/etc/rules/. "$backup/"
sudo install -o wazuh -g wazuh -m 660 rules/*.xml /var/ossec/etc/rules/
if ! sudo /var/ossec/bin/wazuh-analysisd -t; then
  echo "Rule check failed; restoring previous rules" >&2
  sudo cp -a "$backup/." /var/ossec/etc/rules/
  exit 1
fi
sudo systemctl restart wazuh-manager
echo "rules deployed: $(ls rules | tr '\n' ' ')"
rm -rf /tmp/purplelab-push
'@
ssh -i $SshKey $target $remote.Replace("`r", '')
if ($LASTEXITCODE -ne 0) { throw "Remote deploy failed ($LASTEXITCODE)" }
