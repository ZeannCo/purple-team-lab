<#
.SYNOPSIS
  Pushes the centralized agent config in lab\wazuh\shared\<group>\agent.conf to wazuh01,
  creating each agent group if it does not exist yet.
#>
[CmdletBinding()]
param(
    [string]$WazuhHost = '192.168.110.10',
    [string]$SshKey    = 'D:\Labs\keys\purplelab_ed25519'
)

$ErrorActionPreference = 'Stop'
$shared = Join-Path $PSScriptRoot '..\wazuh\shared'

ssh -i $SshKey "labadmin@$WazuhHost" 'rm -rf /tmp/wazuh-shared'
scp -r -i $SshKey $shared "labadmin@${WazuhHost}:/tmp/wazuh-shared"
if ($LASTEXITCODE -ne 0) { throw "scp failed ($LASTEXITCODE)" }

$remote = @'
set -euo pipefail
for dir in /tmp/wazuh-shared/*/; do
  group=$(basename "$dir")
  [ -d "/var/ossec/etc/shared/$group" ] || sudo /var/ossec/bin/agent_groups -a -g "$group" -q
  sudo install -o wazuh -g wazuh -m 660 "$dir/agent.conf" "/var/ossec/etc/shared/$group/agent.conf"
  sudo /var/ossec/bin/verify-agent-conf -f "/var/ossec/etc/shared/$group/agent.conf"
  echo "group $group: agent.conf deployed"
done
rm -rf /tmp/wazuh-shared
'@
ssh -i $SshKey "labadmin@$WazuhHost" $remote.Replace("`r", '')
if ($LASTEXITCODE -ne 0) { throw "Remote deploy failed ($LASTEXITCODE)" }
