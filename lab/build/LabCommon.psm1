# Shared helpers for the lab build scripts.

$script:VmwareDir = 'C:\Program Files (x86)\VMware\VMware Workstation'

function Get-VmwareTool([string]$Name) {
    $path = Get-ChildItem $script:VmwareDir -Recurse -Filter $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $path) { throw "VMware tool not found: $Name" }
    $path.FullName
}

# Windows OpenSSH refuses keys other users can read; also used for the credentials file
function Protect-LabFile([string]$Path) {
    icacls $Path /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
}

# Returns the password stored under $Key in the credentials file, generating and saving one if missing
function Get-LabPassword([string]$CredFile, [string]$Key) {
    $creds = @{}
    if (Test-Path $CredFile) {
        Get-Content $CredFile | Where-Object { $_ -match '^([^=]+)=(.*)$' } | ForEach-Object { $creds[$Matches[1]] = $Matches[2] }
    }
    if ($creds.ContainsKey($Key)) { return $creds[$Key] }

    $chars = [char[]]'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $password = -join (1..20 | ForEach-Object { $chars[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($chars.Length)] })
    Add-Content -Path $CredFile -Value "$Key=$password"
    Protect-LabFile $CredFile
    Write-Host "Password for $Key saved to $CredFile"
    $password
}

# Builds an ISO-9660/Joliet image from a folder with the built-in IMAPI2 COM API (no extra tools)
function New-IsoFromFolder([string]$Source, [string]$Path, [string]$Label) {
    if (-not ('LabIsoWriter' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
public static class LabIsoWriter {
    public static void Save(object stream, string path, int blockSize, int totalBlocks) {
        var istream = (IStream)stream;
        var buffer = new byte[blockSize * 64];
        long remaining = (long)blockSize * totalBlocks;
        using (var file = File.Create(path)) {
            while (remaining > 0) {
                int chunk = (int)Math.Min(buffer.Length, remaining);
                istream.Read(buffer, chunk, IntPtr.Zero);
                file.Write(buffer, 0, chunk);
                remaining -= chunk;
            }
        }
    }
}
'@
    }
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $fsi.FileSystemsToCreate = 3   # ISO9660 + Joliet
    $fsi.VolumeName = $Label
    $fsi.Root.AddTree($Source, $false)
    $image = $fsi.CreateResultImage()
    [LabIsoWriter]::Save($image.ImageStream, $Path, $image.BlockSize, $image.TotalBlocks)

    # IMAPI keeps the source files open until its COM objects are released
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($image)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($fsi)
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}

# Runs a PowerShell script on win11-ep through wazuh01 (WinRM over the lab segment);
# the password is piped over SSH stdin, never put on a command line
function Invoke-LabWindows {
    param(
        [Parameter(Mandatory)][string]$Script,
        [string]$WazuhHost = '192.168.110.10',
        [string]$KeysDir   = 'D:\Labs\keys',
        [string]$Target    = '10.10.10.20',
        [string]$Account   = 'win11-ep_labadmin'
    )
    $key = Join-Path $KeysDir 'purplelab_ed25519'
    $password = Get-LabPassword (Join-Path $KeysDir 'lab-credentials.txt') $Account
    $local = Join-Path $env:TEMP "lab-$([guid]::NewGuid().ToString('N')).ps1"
    Set-Content $local $Script -Encoding utf8NoBOM
    $remote = "/tmp/$(Split-Path $local -Leaf)"
    scp -q -i $key (Join-Path $PSScriptRoot '..\..\validation\lab_winrm.py') $local "labadmin@${WazuhHost}:/tmp/"
    Remove-Item $local
    $password | ssh -i $key "labadmin@$WazuhHost" "read -r WIN_PASSWORD; export WIN_PASSWORD; /opt/purplelab/venv/bin/python /tmp/lab_winrm.py $remote --host $Target; rc=`$?; rm -f $remote; exit `$rc"
}

Export-ModuleMember -Function Get-VmwareTool, Protect-LabFile, Get-LabPassword, New-IsoFromFolder, Invoke-LabWindows
