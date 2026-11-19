<#
  Runs once at first logon on win11-ep, from the setup disc built by new-win11-vm.ps1.
  Configures networking, the logging detections depend on, Sysmon, the Wazuh agent,
  WinRM (lab subnet only) and VMware Tools, then reboots.
  Log: C:\PurpleLab\bootstrap.log
#>
$ErrorActionPreference = 'Continue'
$src  = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = 'C:\PurpleLab'
New-Item -ItemType Directory -Force $work | Out-Null
Start-Transcript -Path "$work\bootstrap.log" -Append
Copy-Item "$src\payloads" $work -Recurse -Force

# --- Network: name NICs by their fixed MACs; static IP on the lab segment
Rename-NetAdapter -Name (Get-NetAdapter | Where-Object MacAddress -eq '00-50-56-10-00-20').Name -NewName nat0
Rename-NetAdapter -Name (Get-NetAdapter | Where-Object MacAddress -eq '00-50-56-10-10-20').Name -NewName lab0
New-NetIPAddress -InterfaceAlias lab0 -IPAddress 10.10.10.20 -PrefixLength 24 | Out-Null
Add-Content "$env:SystemRoot\System32\drivers\etc\hosts" "`r`n10.10.10.10 wazuh01.lab.local wazuh01`r`n10.10.10.5  dc01.lab.local dc01"
foreach ($i in 1..12) {
    if (Get-NetConnectionProfile -InterfaceAlias lab0 -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Seconds 5
}
Set-NetConnectionProfile -InterfaceAlias lab0 -NetworkCategory Private

# --- Logging the detections depend on
$audit = 'Process Creation', 'Logon', 'User Account Management', 'Security Group Management',
         'Other Object Access Events', 'Audit Policy Change', 'Security System Extension'
foreach ($sub in $audit) { auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null }
reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
reg add 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null

# --- Sysmon (sysmon-modular config)
& "$work\payloads\Sysmon\Sysmon64.exe" -accepteula -i "$work\payloads\sysmonconfig.xml"

# --- Wazuh agent: enrolls with the manager over the lab segment into the "windows" group
$msi = Get-ChildItem "$work\payloads" -Filter 'wazuh-agent-*.msi' | Select-Object -First 1
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$($msi.FullName)`" /qn WAZUH_MANAGER=10.10.10.10 WAZUH_AGENT_NAME=win11-ep WAZUH_AGENT_GROUP=windows"
Start-Service WazuhSvc

# --- WinRM for the validation runner, reachable from the lab subnet only
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' | Set-NetFirewallRule -RemoteAddress 10.10.10.0/24
New-NetFirewallRule -DisplayName 'Lab ICMPv4 echo' -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.10.10.0/24 -Action Allow | Out-Null

# --- Keep the lab VM predictable: no sleep, no automatic updates mid-test
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f | Out-Null

# --- VMware Tools last; its reboot is deferred to the restart below
$tools = Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path (Join-Path $_.Root 'VMwareToolsUpgrader.exe') } | Select-Object -First 1
if ($tools) { Start-Process (Join-Path $tools.Root 'setup.exe') -Wait -ArgumentList '/S /v "/qn REBOOT=R"' }

New-Item -ItemType File -Force "$work\bootstrap.done" | Out-Null
Stop-Transcript
Restart-Computer -Force
