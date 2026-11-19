<#
.SYNOPSIS
  Deploys the Phase 3 target: HelpBot (atlas/app) in Docker on wazuh01, its log collection, and the
  ATLAS rules. The OpenRouter key and model come from the repo's .env (key piped over SSH).
#>
[CmdletBinding()]
param(
    [string]$WazuhHost = '192.168.110.10',
    [string]$KeysDir   = 'D:\Labs\keys',
    [string]$Model     # overrides HELPBOT_MODEL / TRIAGE_MODEL from .env, e.g. to test a weaker model
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
$repo   = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$key    = Join-Path $KeysDir 'purplelab_ed25519'
$target = "labadmin@$WazuhHost"
$envVars = Get-LabEnv
if (-not $envVars['OPENROUTER_API_KEY']) { throw "Put your OpenRouter key in the repo's .env first." }
$model = if ($Model) { $Model } elseif ($envVars['HELPBOT_MODEL']) { $envVars['HELPBOT_MODEL'] } else { $envVars['TRIAGE_MODEL'] }
if ($model -notmatch '^[\w.\-/:]+$') { throw "Unexpected characters in model ID: $model" }

& (Join-Path $PSScriptRoot 'push-wazuh-config.ps1') -WazuhHost $WazuhHost -SshKey $key

ssh -i $key $target 'rm -rf /opt/purplelab/atlas-src && mkdir -p /opt/purplelab/atlas-src'
scp -q -r -i $key (Join-Path $repo 'atlas\app') "${target}:/opt/purplelab/atlas-src/"
scp -q -i $key (Join-Path $repo 'lab\wazuh\install-atlas.sh') "${target}:/opt/purplelab/atlas-src/"

# Env file for the container: key from stdin, never on a command line
$envVars['OPENROUTER_API_KEY'] | ssh -i $key $target ("read -r K; K=`${K%`$'\r'}; sudo mkdir -p /etc/purplelab; " +
    "printf 'OPENROUTER_API_KEY=%s\nHELPBOT_MODEL=$model\n' `"`$K`" | sudo tee /etc/purplelab/helpbot.env >/dev/null; " +
    "sudo chmod 600 /etc/purplelab/helpbot.env; sed -i 's/\r$//' /opt/purplelab/atlas-src/install-atlas.sh")
ssh -i $key $target 'bash /opt/purplelab/atlas-src/install-atlas.sh /opt/purplelab/atlas-src'
if ($LASTEXITCODE -ne 0) { throw "HelpBot deploy failed" }
