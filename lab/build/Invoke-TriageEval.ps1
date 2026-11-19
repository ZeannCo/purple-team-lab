<#
.SYNOPSIS
  Builds the triage eval set and runs the model comparison on wazuh01.

.DESCRIPTION
  -GenerateBenign  runs lab\windows\benign-activity.ps1 on win11-ep and records the time window
  -BuildDataset    labels alerts from validation runs (malicious) and the benign window
  -Model           runs the eval for these OpenRouter models (needs OPENROUTER_API_KEY in the repo's .env)
  Results are copied back into triage\eval\.
#>
[CmdletBinding()]
param(
    [switch]$GenerateBenign,
    [switch]$BuildDataset,
    [string[]]$Validation = @('validation', 'validation-run2'),
    [string[]]$Model,
    [int]$Limit,
    [string]$WazuhHost = '192.168.110.10',
    [string]$KeysDir   = 'D:\Labs\keys'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
$repo   = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$key    = Join-Path $KeysDir 'purplelab_ed25519'
$target = "labadmin@$WazuhHost"
$evalDir = Join-Path $repo 'triage\eval'
$remote = '/opt/purplelab/eval'

ssh -i $key $target "mkdir -p $remote/eval $remote/results"
scp -q -i $key (Join-Path $repo 'triage\agent.py') (Join-Path $repo 'triage\wazuh_mcp_server.py') "${target}:$remote/"
scp -q -i $key (Join-Path $evalDir 'build_dataset.py') (Join-Path $evalDir 'run_eval.py') "${target}:$remote/eval/"

if ($GenerateBenign) {
    # Plain WinRS commands (no PowerShell encoding or staging) so the benign activity looks like what it is
    scp -q -i $key (Join-Path $repo 'lab\windows\benign_activity.py') "${target}:$remote/"
    $win = Get-LabPassword (Join-Path $KeysDir 'lab-credentials.txt') 'win11-ep_labadmin'
    $win | ssh -i $key $target ("read -r WIN_PASSWORD; export WIN_PASSWORD; cd $remote && " +
        "/opt/purplelab/venv/bin/python benign_activity.py --window-out $remote/results/benign-window.json")
    scp -q -i $key "${target}:$remote/results/benign-window.json" (Join-Path $evalDir 'benign-window.json')
}

if ($BuildDataset) {
    $files = $Validation | ForEach-Object { Join-Path $repo "validation\results\$_.json" }
    scp -q -i $key @files (Join-Path $evalDir 'benign-window.json') "${target}:$remote/results/"
    $vArgs = ($Validation | ForEach-Object { "--validation $remote/results/$_.json" }) -join ' '
    $admin = Get-LabPassword (Join-Path $KeysDir 'lab-credentials.txt') 'wazuh01_dashboard_admin'
    $admin | ssh -i $key $target ("read -r INDEXER_PASSWORD; export INDEXER_PASSWORD; cd $remote/eval && " +
        "/opt/purplelab/triage-venv/bin/python build_dataset.py $vArgs --benign-window $remote/results/benign-window.json --out $remote/eval/dataset.jsonl")
    scp -q -i $key "${target}:$remote/eval/dataset.jsonl" $evalDir
}

if ($Model) {
    $openrouter = (Get-LabEnv)['OPENROUTER_API_KEY']
    if (-not $openrouter) { throw "Put your OpenRouter API key in the repo's .env (OPENROUTER_API_KEY=...) first." }
    foreach ($m in $Model) { if ($m -notmatch '^[\w.\-/:]+$') { throw "Unexpected characters in model ID: $m" } }
    scp -q -i $key (Join-Path $evalDir 'dataset.jsonl') "${target}:$remote/eval/"
    $mArgs = ($Model | ForEach-Object { "--model $_" }) -join ' '
    $lArg  = if ($Limit) { "--limit $Limit" } else { '' }
    $run   = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmm')
    # Key and the triage account's password go over stdin; the eval reads alerts with the read-only account
    $openrouter | ssh -i $key $target ("read -r OPENROUTER_API_KEY; OPENROUTER_API_KEY=`${OPENROUTER_API_KEY%`$'\r'}; export OPENROUTER_API_KEY; " +
        "export INDEXER_USER=purplelab_triage INDEXER_PASSWORD=`$(sudo grep ^INDEXER_PASSWORD= /etc/purplelab/triage.env | cut -d= -f2-); " +
        "cd $remote/eval && /opt/purplelab/triage-venv/bin/python run_eval.py $mArgs $lArg --run $run")
    New-Item -ItemType Directory -Force (Join-Path $evalDir "results\$run") | Out-Null
    scp -q -i $key "${target}:$remote/eval/results/$run/*" (Join-Path $evalDir "results\$run")
    Write-Host "Results in triage\eval\results\$run"
}
