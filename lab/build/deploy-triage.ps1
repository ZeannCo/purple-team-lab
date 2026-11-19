<#
.SYNOPSIS
  Deploys the AI triage pipeline to wazuh01: rules, integration, worker service, read-only
  indexer account. If D:\Labs\keys\openrouter.key exists, its key is written to the worker's
  env file on the VM (piped over SSH, never on a command line) and the worker is started.
#>
[CmdletBinding()]
param(
    [string]$WazuhHost = '192.168.110.10',
    [string]$KeysDir   = 'D:\Labs\keys',
    [string]$Model
)

$ErrorActionPreference = 'Stop'
$repo   = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$key    = Join-Path $KeysDir 'purplelab_ed25519'
$target = "labadmin@$WazuhHost"

& (Join-Path $PSScriptRoot 'push-wazuh-config.ps1') -WazuhHost $WazuhHost -SshKey $key

ssh -i $key $target 'rm -rf /opt/purplelab/src && mkdir -p /opt/purplelab/src'
scp -q -r -i $key (Join-Path $repo 'triage') "${target}:/opt/purplelab/src/"
scp -q -i $key (Join-Path $repo 'lab\wazuh\install-triage.sh') "${target}:/opt/purplelab/src/"
ssh -i $key $target "sed -i 's/\r$//' /opt/purplelab/src/install-triage.sh /opt/purplelab/src/triage/integration/custom-purplelab-triage"

$keyFile = Join-Path $KeysDir 'openrouter.key'
if (Test-Path $keyFile) {
    $openrouter = (Get-Content $keyFile -Raw).Trim()
    $setModel = if ($Model) { "sudo sed -i '/^TRIAGE_MODEL=/d' /etc/purplelab/triage.env; echo 'TRIAGE_MODEL=$Model' | sudo tee -a /etc/purplelab/triage.env >/dev/null;" } else { '' }
    # Install first so the env file exists, then replace the key line from stdin
    ssh -i $key $target 'bash /opt/purplelab/src/install-triage.sh /opt/purplelab/src'
    $openrouter | ssh -i $key $target ("read -r K; K=`${K%`$'\r'}; sudo sed -i '/^OPENROUTER_API_KEY=/d' /etc/purplelab/triage.env; " +
        "printf 'OPENROUTER_API_KEY=%s\n' `"`$K`" | sudo tee -a /etc/purplelab/triage.env >/dev/null; $setModel" +
        "sudo systemctl enable --now purplelab-triage >/dev/null 2>&1; sudo systemctl restart purplelab-triage; systemctl is-active purplelab-triage")
} else {
    ssh -i $key $target 'bash /opt/purplelab/src/install-triage.sh /opt/purplelab/src'
    Write-Host "No $keyFile yet: triage worker installed but not started."
}
