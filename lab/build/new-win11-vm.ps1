<#
.SYNOPSIS
  Builds the win11-ep VM: unattended Windows 11 install, then bootstrap.ps1 installs
  Sysmon, the Wazuh agent, WinRM and VMware Tools.

.DESCRIPTION
  1. Renders autounattend.xml with the labadmin password and packs it, bootstrap.ps1 and
     the payloads (Sysmon, sysmon-modular config, Wazuh agent MSI) into a setup ISO
  2. Creates the disk and a .vmx with three CDs (Windows, setup disc, VMware Tools) and
     two NICs with fixed MACs: NAT (nat0) and VMnet2 (lab0, 10.10.10.20)
  3. Boots it and waits until the agent shows Active on wazuh01

  Run push-wazuh-config.ps1 first so the "windows" agent group exists.
#>
[CmdletBinding()]
param(
    [string]$WindowsIso = 'D:\Labs\ISOs\Win11_Enterprise_Eval_26H2_x64_en-us.iso',
    [string]$Payloads   = 'D:\Labs\ISOs\payloads',
    [string]$VmRoot     = 'D:\Labs\VMs',
    [string]$KeysDir    = 'D:\Labs\keys',
    [string]$Name       = 'win11-ep',
    [int]$MemoryMB      = 5120,
    [int]$Cpus          = 2,
    [string]$DiskSize   = '64GB',
    [string]$WazuhHost  = '192.168.110.10',
    [int]$TimeoutMinutes = 60
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
$vmrun        = Get-VmwareTool 'vmrun.exe'
$vdiskmanager = Get-VmwareTool 'vmware-vdiskmanager.exe'
$toolsIso     = Get-VmwareTool 'windows.iso'
$windowsDir   = Join-Path $PSScriptRoot '..\windows'
$vmDir        = Join-Path $VmRoot $Name
$vmx          = Join-Path $vmDir "$Name.vmx"
$sshKey       = Join-Path $KeysDir 'purplelab_ed25519'

if (Test-Path $vmx) { throw "$vmx already exists. Delete the VM first if you want to rebuild it." }
foreach ($p in $WindowsIso, $Payloads, $sshKey) { if (-not (Test-Path $p)) { throw "Missing: $p" } }
New-Item -ItemType Directory -Force $vmDir | Out-Null

# --- 1. Setup disc (rendered password stays in the VM folder, outside the repo)
$password = Get-LabPassword (Join-Path $KeysDir 'lab-credentials.txt') "${Name}_labadmin"
$discDir = Join-Path $vmDir 'setup-disc'
New-Item -ItemType Directory -Force $discDir | Out-Null
(Get-Content (Join-Path $windowsDir 'autounattend.xml') -Raw).Replace('${LAB_PASSWORD}', $password) |
    Set-Content (Join-Path $discDir 'autounattend.xml') -Encoding utf8NoBOM -NoNewline
Copy-Item (Join-Path $windowsDir 'bootstrap.ps1') $discDir
New-Item -ItemType File -Force (Join-Path $discDir 'purplelab.marker') | Out-Null
Copy-Item $Payloads (Join-Path $discDir 'payloads') -Recurse -Force
$setupIso = Join-Path $vmDir 'setup-disc.iso'
New-IsoFromFolder $discDir $setupIso 'PURPLELAB'
Remove-Item $discDir -Recurse -Force -ErrorAction Continue
Write-Host "Setup disc: $setupIso"

# --- 2. Disk and .vmx (BIOS firmware: the Windows ISO boots without a keypress)
& $vdiskmanager -c -s $DiskSize -a ide -t 0 (Join-Path $vmDir "$Name.vmdk") | Out-Null
if ($LASTEXITCODE -ne 0) { throw "vmware-vdiskmanager failed ($LASTEXITCODE)" }

$settings = [ordered]@{
    '.encoding'                = 'UTF-8'
    'config.version'           = '8'
    'virtualHW.version'        = '21'
    'displayName'              = $Name
    'guestOS'                  = 'windows9-64'
    'firmware'                 = 'bios'
    'memsize'                  = "$MemoryMB"
    'numvcpus'                 = "$Cpus"
    'cpuid.coresPerSocket'     = "$Cpus"
    'mks.enable3d'             = 'FALSE'
    'pciBridge0.present'       = 'TRUE'
    'pciBridge4.present'       = 'TRUE'
    'pciBridge4.virtualDev'    = 'pcieRootPort'
    'pciBridge4.functions'     = '8'
    'pciBridge5.present'       = 'TRUE'
    'pciBridge5.virtualDev'    = 'pcieRootPort'
    'pciBridge5.functions'     = '8'
    'vmci0.present'            = 'TRUE'
    'hpet0.present'            = 'TRUE'
    'usb.present'              = 'TRUE'
    'ehci.present'             = 'TRUE'
    'sata0.present'            = 'TRUE'
    'sata0:0.present'          = 'TRUE'
    'sata0:0.fileName'         = "$Name.vmdk"
    'sata0:1.present'          = 'TRUE'
    'sata0:1.deviceType'       = 'cdrom-image'
    'sata0:1.fileName'         = $WindowsIso
    'sata0:2.present'          = 'TRUE'
    'sata0:2.deviceType'       = 'cdrom-image'
    'sata0:2.fileName'         = $setupIso
    'sata0:3.present'          = 'TRUE'
    'sata0:3.deviceType'       = 'cdrom-image'
    'sata0:3.fileName'         = $toolsIso
    'ethernet0.present'        = 'TRUE'
    'ethernet0.virtualDev'     = 'e1000e'
    'ethernet0.connectionType' = 'nat'
    'ethernet0.addressType'    = 'static'
    'ethernet0.address'        = '00:50:56:10:00:20'
    'ethernet1.present'        = 'TRUE'
    'ethernet1.virtualDev'     = 'e1000e'
    'ethernet1.connectionType' = 'custom'
    'ethernet1.vnet'           = 'VMnet2'
    'ethernet1.addressType'    = 'static'
    'ethernet1.address'        = '00:50:56:10:10:20'
    'tools.syncTime'           = 'FALSE'
}
$settings.GetEnumerator() | ForEach-Object { "$($_.Key) = `"$($_.Value)`"" } | Set-Content $vmx -Encoding utf8NoBOM

# --- 3. Boot and wait for the Wazuh agent to report in
& $vmrun -T ws start $vmx nogui
if ($LASTEXITCODE -ne 0) { throw "vmrun start failed ($LASTEXITCODE)" }
Write-Host "Installing Windows (usually 20-40 minutes) ..."

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 60
    $status = ssh -i $sshKey -o ConnectTimeout=10 "labadmin@$WazuhHost" "sudo /var/ossec/bin/agent_control -l | grep -i 'Name: $Name'" 2>$null
    if ($status -match 'Active') {
        Write-Host "$Name is installed and its Wazuh agent is Active: $status"
        exit 0
    }
}
throw "$Name's agent did not become Active within $TimeoutMinutes minutes. Check the VM console and C:\PurpleLab\bootstrap.log."
