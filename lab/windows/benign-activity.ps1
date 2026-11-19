<#
  Routine admin activity that trips the same rules as the atomics, to give the AI triage eval
  hard negatives: a correct analyst should call these benign (or at most escalate), not malicious.
  Run remotely: Invoke-LabWindows -Script (Get-Content lab\windows\benign-activity.ps1 -Raw)
  Each round is ~70 s apart so the discovery-burst rule (60 s window) can fire once per round.
#>
$ErrorActionPreference = 'Continue'

$rounds = @(
    @{ Vendor = 'Contoso';  Task = 'NightlyBackup'; Script = 'backup.ps1'; RunName = 'OneDrive'
       RunData = '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'
       Groups = @('Administrators', 'Remote Desktop Users'); Check = 'Get-Service WinRM,Sysmon64,WazuhSvc | Select-Object Name,Status' },
    @{ Vendor = 'Fabrikam'; Task = 'ReportUpload'; Script = 'upload-reports.ps1'; RunName = 'Teams'
       RunData = '"C:\Program Files\WindowsApps\MSTeams\ms-teams.exe" --system-initiated'
       Groups = @('Users', 'Backup Operators'); Check = 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3' },
    @{ Vendor = 'Northwind'; Task = 'LogRotate'; Script = 'rotate-logs.ps1'; RunName = 'GreenshotUpdater'
       RunData = '"C:\Program Files\Greenshot\Greenshot.exe" /startup'
       Groups = @('Administrators', 'Event Log Readers'); Check = 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,LastBootUpTime' }
)

foreach ($r in $rounds) {
    $dir = "C:\ProgramData\$($r.Vendor)\Scripts"
    New-Item -ItemType Directory -Force $dir | Out-Null
    Set-Content (Join-Path $dir $r.Script) "Write-Output '$($r.Vendor) maintenance job'"

    # Vendor maintenance task run through PowerShell (scheduled task + script host -> 100140)
    schtasks /Create /F /SC DAILY /ST 02:00 /RU SYSTEM /TN "$($r.Vendor)\$($r.Task)" `
        /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dir\$($r.Script)" | Out-Null
    Start-Sleep -Seconds 10

    # Software autostart entry written by an installer-style reg.exe call (Run key -> 100151).
    # Windows PowerShell 5.1 drops embedded quotes when calling native programs; escape them for reg.exe
    reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v $r.RunName /t REG_SZ /f /d $r.RunData.Replace('"', '\"') | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "reg add failed for $($r.RunName)" }
    Start-Sleep -Seconds 10

    # Helpdesk checking an account and group membership (net burst -> 100190)
    cmd /c "net user labadmin & net localgroup `"$($r.Groups[0])`" & net localgroup `"$($r.Groups[1])`"" | Out-Null
    Start-Sleep -Seconds 10

    # Management tooling sending an encoded one-liner (encoded PowerShell from cmd -> 92057)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($r.Check))
    cmd /c "powershell.exe -NoProfile -EncodedCommand $encoded" | Out-Null
    Start-Sleep -Seconds 40
}

# Antivirus check with the industry-standard EICAR test string (Defender detection -> 62123)
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "$env:PUBLIC\Documents\av-check.txt" -Value $eicar -NoNewline -ErrorAction SilentlyContinue
Start-Sleep -Seconds 20

# Clean up
foreach ($r in $rounds) {
    schtasks /Delete /F /TN "$($r.Vendor)\$($r.Task)" | Out-Null
    reg delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v $r.RunName /f | Out-Null
    Remove-Item "C:\ProgramData\$($r.Vendor)" -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item "$env:PUBLIC\Documents\av-check.txt" -Force -ErrorAction SilentlyContinue
'benign activity done'
