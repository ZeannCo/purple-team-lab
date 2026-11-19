<#
.SYNOPSIS
  Deploys the AI triage pipeline to wazuh01: rules, integration, worker service, read-only
  indexer account. If the repo's .env has OPENROUTER_API_KEY, the key and TRIAGE_MODEL are written
  to the worker's env file on the VM (piped over SSH, never on a command line) and the worker starts.
#>
[CmdletBinding()]
param(
    [string]$WazuhHost = '192.168.110.10',
    [string]$KeysDir   = 'D:\Labs\keys',
    [string]$Model     # overrides TRIAGE_MODEL from .env
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
$repo   = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$key    = Join-Path $KeysDir 'purplelab_ed25519'
$target = "labadmin@$WazuhHost"
$envVars = Get-LabEnv
if (-not $Model) { $Model = $envVars['TRIAGE_MODEL'] }
if ($Model -and $Model -notmatch '^[\w.\-/:]+$') { throw "Unexpected characters in model ID: $Model" }

& (Join-Path $PSScriptRoot 'push-wazuh-config.ps1') -WazuhHost $WazuhHost -SshKey $key

ssh -i $key $target 'rm -rf /opt/purplelab/src && mkdir -p /opt/purplelab/src'
scp -q -r -i $key (Join-Path $repo 'triage') "${target}:/opt/purplelab/src/"
scp -q -i $key (Join-Path $repo 'lab\wazuh\install-triage.sh') "${target}:/opt/purplelab/src/"
ssh -i $key $target "sed -i 's/\r$//' /opt/purplelab/src/install-triage.sh /opt/purplelab/src/triage/integration/custom-purplelab-triage"
ssh -i $key $target 'bash /opt/purplelab/src/install-triage.sh /opt/purplelab/src'

if ($Model) {
    ssh -i $key $target ("sudo sed -i '/^TRIAGE_MODEL=/d' /etc/purplelab/triage.env; " +
        "echo 'TRIAGE_MODEL=$Model' | sudo tee -a /etc/purplelab/triage.env >/dev/null")
}

$openrouter = $envVars['OPENROUTER_API_KEY']
if ($openrouter) {
    # Replace the key line from stdin, then (re)start the worker
    $openrouter | ssh -i $key $target ("read -r K; K=`${K%`$'\r'}; sudo sed -i '/^OPENROUTER_API_KEY=/d' /etc/purplelab/triage.env; " +
        "printf 'OPENROUTER_API_KEY=%s\n' `"`$K`" | sudo tee -a /etc/purplelab/triage.env >/dev/null; " +
        "sudo systemctl enable --now purplelab-triage >/dev/null 2>&1; sudo systemctl restart purplelab-triage; systemctl is-active purplelab-triage")
    Write-Host "Triage worker running with $Model"
} else {
    Write-Host "No OPENROUTER_API_KEY in .env yet: triage worker installed but not started."
}
