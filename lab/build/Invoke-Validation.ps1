<#
.SYNOPSIS
  Runs validation/run_validation.py on wazuh01 and copies the results back into the repo.

.EXAMPLE
  .\lab\build\Invoke-Validation.ps1 -Label baseline
  .\lab\build\Invoke-Validation.ps1 -Only T1105,T1685
#>
[CmdletBinding()]
param(
    [string]$Label     = 'validation',
    [string[]]$Only,
    [int]$Settle       = 60,
    [string]$WazuhHost = '192.168.110.10',
    [string]$KeysDir   = 'D:\Labs\keys'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
$key       = Join-Path $KeysDir 'purplelab_ed25519'
$credFile  = Join-Path $KeysDir 'lab-credentials.txt'
$localDir  = Resolve-Path (Join-Path $PSScriptRoot '..\..\validation')
$remoteDir = '/opt/purplelab/validation'
$target    = "labadmin@$WazuhHost"

ssh -i $key $target "mkdir -p $remoteDir/results"
$files = 'lab_winrm.py', 'run_validation.py', 'tests.yml', 'requirements.txt' | ForEach-Object { Join-Path $localDir $_ }
scp -q -i $key @files "${target}:$remoteDir/"
ssh -i $key $target "/opt/purplelab/venv/bin/pip install -q -r $remoteDir/requirements.txt"
if ($LASTEXITCODE -ne 0) { throw "pip install failed on wazuh01" }

$onlyArgs = if ($Only) { ($Only | ForEach-Object { "--only $_" }) -join ' ' } else { '' }
$secrets  = (Get-LabPassword $credFile 'win11-ep_labadmin') + "`n" + (Get-LabPassword $credFile 'wazuh01_dashboard_admin')
$secrets | ssh -i $key $target ("read -r WIN_PASSWORD; read -r INDEXER_PASSWORD; export WIN_PASSWORD INDEXER_PASSWORD; " +
    "cd $remoteDir && /opt/purplelab/venv/bin/python run_validation.py --label $Label --settle $Settle $onlyArgs")
$rc = $LASTEXITCODE

New-Item -ItemType Directory -Force (Join-Path $localDir 'results') | Out-Null
scp -q -i $key "${target}:$remoteDir/results/$Label*" (Join-Path $localDir 'results')
Write-Host "Results copied to $(Join-Path $localDir 'results')"
exit $rc
