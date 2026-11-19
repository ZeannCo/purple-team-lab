<#
.SYNOPSIS
  Runs atlas/run_attacks.py on wazuh01 against HelpBot and copies the results into atlas\results.
#>
[CmdletBinding()]
param(
    [string]$Label     = 'atlas',
    [string]$WazuhHost = '192.168.110.10',
    [string]$KeysDir   = 'D:\Labs\keys'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
$repo   = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$key    = Join-Path $KeysDir 'purplelab_ed25519'
$target = "labadmin@$WazuhHost"
$remote = '/opt/purplelab/atlas-run'

ssh -i $key $target "mkdir -p $remote/results"
scp -q -i $key (Join-Path $repo 'atlas\run_attacks.py') (Join-Path $repo 'atlas\attacks.yml') "${target}:$remote/"
$admin = Get-LabPassword (Join-Path $KeysDir 'lab-credentials.txt') 'wazuh01_dashboard_admin'
$admin | ssh -i $key $target ("read -r INDEXER_PASSWORD; export INDEXER_PASSWORD; cd $remote && " +
    "/opt/purplelab/venv/bin/python run_attacks.py --label $Label")
$rc = $LASTEXITCODE
New-Item -ItemType Directory -Force (Join-Path $repo 'atlas\results') | Out-Null
scp -q -i $key "${target}:$remote/results/$Label.*" (Join-Path $repo 'atlas\results')
exit $rc
