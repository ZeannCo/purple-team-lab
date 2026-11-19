<#
  Installs Invoke-AtomicRedTeam and the atomics library on win11-ep.
  Run remotely: Invoke-LabWindows -Script (Get-Content lab\windows\install-atomics.ps1 -Raw)
  Needs internet (NAT NIC connected).
#>
$ErrorActionPreference = 'Stop'

# Windows 11 defaults to Restricted, which blocks the powershell-yaml module Atomic Red Team loads
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# Defender would quarantine parts of the atomics library; exclude only this folder, only in this VM
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
$module = Get-Module Invoke-AtomicRedTeam
"Invoke-AtomicRedTeam $($module.Version) installed"
"Techniques in library: $((Get-ChildItem 'C:\AtomicRedTeam\atomics' -Directory -Filter 'T*').Count)"
