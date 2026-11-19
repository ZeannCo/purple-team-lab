<#
.SYNOPSIS
  Builds the wazuh01 VM from the Ubuntu 24.04 cloud image (no installer).

.DESCRIPTION
  1. Imports the OVA with ovftool into $VmRoot\$Name
  2. Grows the disk (cloud-init growpart expands the root filesystem on first boot)
  3. Sets RAM/CPU and two NICs with fixed MACs: NAT (nat0) and VMnet2 (lab0)
  4. Injects cloud-init user-data/metadata through VMware guestinfo
  5. Boots the VM headless and waits for SSH

  Secrets (SSH key, console password) come from $KeysDir and are never written to the repo.
#>
[CmdletBinding()]
param(
    [string]$Ova      = 'D:\Labs\ISOs\noble-server-cloudimg-amd64.ova',
    [string]$VmRoot   = 'D:\Labs\VMs',
    [string]$KeysDir  = 'D:\Labs\keys',
    [string]$Name     = 'wazuh01',
    [int]$MemoryMB    = 8192,
    [int]$Cpus        = 4,
    [string]$DiskSize = '80GB',
    [string]$NatIp    = '192.168.110.10'
)

$ErrorActionPreference = 'Stop'
$vmwareDir    = 'C:\Program Files (x86)\VMware\VMware Workstation'
$ovftool      = Join-Path $vmwareDir 'OVFTool\ovftool.exe'
$vmrun        = Join-Path $vmwareDir 'vmrun.exe'
$vdiskmanager = Join-Path $vmwareDir 'vmware-vdiskmanager.exe'
$cloudInitDir = Join-Path $PSScriptRoot "..\cloud-init\$Name"
$vmDir        = Join-Path $VmRoot $Name
$vmx          = Join-Path $vmDir "$Name.vmx"
$pubKeyPath   = Join-Path $KeysDir 'purplelab_ed25519.pub'
$credFile     = Join-Path $KeysDir 'lab-credentials.txt'

if (Test-Path $vmx) { throw "$vmx already exists. Delete the VM first if you want to rebuild it." }
foreach ($p in $Ova, $ovftool, $vmrun, $vdiskmanager, $pubKeyPath) {
    if (-not (Test-Path $p)) { throw "Missing: $p" }
}
Import-Module (Join-Path $PSScriptRoot 'LabCommon.psm1') -Force
Protect-LabFile ($pubKeyPath -replace '\.pub$', '')
$password = Get-LabPassword $credFile "${Name}_labadmin"

# --- Render cloud-init (LF line endings) and base64 it for guestinfo
function ConvertTo-GuestInfo([string]$text) {
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text.Replace("`r`n", "`n")))
}
$userData = (Get-Content (Join-Path $cloudInitDir 'user-data.yaml') -Raw).
    Replace('${SSH_PUBLIC_KEY}', (Get-Content $pubKeyPath -Raw).Trim()).
    Replace('${LAB_PASSWORD}', $password)
$metaData = Get-Content (Join-Path $cloudInitDir 'metadata.yaml') -Raw

# --- 1. Import
Write-Host "Importing $Ova ..."
& $ovftool --acceptAllEulas --allowExtraConfig --diskMode=monolithicSparse "--name=$Name" $Ova $VmRoot
if ($LASTEXITCODE -ne 0) { throw "ovftool failed ($LASTEXITCODE)" }

# --- 2. Grow the disk
$disk = Get-ChildItem $vmDir -Filter *.vmdk | Select-Object -First 1
Write-Host "Expanding $($disk.Name) to $DiskSize ..."
& $vdiskmanager -x $DiskSize $disk.FullName
if ($LASTEXITCODE -ne 0) { throw "vmware-vdiskmanager failed ($LASTEXITCODE)" }

# --- 3/4. Rewrite hardware, NICs and guestinfo in the .vmx
# Drop every key we set below (including all ethernetN.* from the OVA) so none appear twice
$keep = Get-Content $vmx | Where-Object { $_ -notmatch '^(memsize|numvcpus|displayName|ethernet\d+\.[\w.:]+|guestinfo\.[\w.]+)\s*=' }
$settings = [ordered]@{
    'displayName'                 = $Name
    'memsize'                     = "$MemoryMB"
    'numvcpus'                    = "$Cpus"
    'ethernet0.present'           = 'TRUE'
    'ethernet0.virtualDev'        = 'vmxnet3'
    'ethernet0.connectionType'    = 'nat'
    'ethernet0.addressType'       = 'static'
    'ethernet0.address'           = '00:50:56:10:00:10'
    'ethernet1.present'           = 'TRUE'
    'ethernet1.virtualDev'        = 'vmxnet3'
    'ethernet1.connectionType'    = 'custom'
    'ethernet1.vnet'              = 'VMnet2'
    'ethernet1.addressType'       = 'static'
    'ethernet1.address'           = '00:50:56:10:10:10'
    'guestinfo.metadata'          = (ConvertTo-GuestInfo $metaData)
    'guestinfo.metadata.encoding' = 'base64'
    'guestinfo.userdata'          = (ConvertTo-GuestInfo $userData)
    'guestinfo.userdata.encoding' = 'base64'
}
$lines = $keep + ($settings.GetEnumerator() | ForEach-Object { "$($_.Key) = `"$($_.Value)`"" })
Set-Content -Path $vmx -Value $lines -Encoding utf8NoBOM

# --- 5. Boot and wait for SSH
Write-Host "Starting $Name ..."
& $vmrun -T ws start $vmx nogui
if ($LASTEXITCODE -ne 0) { throw "vmrun start failed ($LASTEXITCODE)" }

$deadline = (Get-Date).AddMinutes(10)
while ((Get-Date) -lt $deadline) {
    if (Test-Connection -TargetName $NatIp -TcpPort 22 -Quiet -TimeoutSeconds 2) {
        Write-Host "$Name is up: ssh -i $KeysDir\purplelab_ed25519 labadmin@$NatIp"
        exit 0
    }
    Start-Sleep -Seconds 10
}
throw "$Name did not answer on ${NatIp}:22 within 10 minutes. Check the VMware console."
