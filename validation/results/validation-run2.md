# Validation run: validation-run2

Run started 2026-11-19T14:00:28.844Z against `win11-ep` (Wazuh 4.14). **11 PASS**

A control step drives the same WinRM + Invoke-AtomicTest path without executing a test; rules it triggers are attributed to the harness and left out below: `100189`, `60137`, `60608`, `60642`, `67027`, `67028`, `91816`, `91819`, `91820`, `92021`, `92032`, `92052`, `92205`.

| Technique (v19) | Legacy | Test | Result | Rules that fired (id, level, description) |
|---|---|---|---|---|
| T1059.001 |  | #17 PowerShell Command Execution (encoded command) | **PASS** | `92057` L12 Powershell.exe spawned a powershell process which executed a base64 encoded command |
| T1059.001 |  | #18 PowerShell Invoke Known Malicious Cmdlets | **PASS**<br>replay: `100180` | `100204` L13 Microsoft Defender blocked PowerShell carrying Mimikatz-family tooling<br>`62154` L5 Windows Defender: Antimalware platform feature configuration changed |
| T1003.001 |  | #2 Dump LSASS.exe Memory using comsvcs.dll | **PASS**<br>replay: `100110`, `100111` | `100201` L14 Microsoft Defender blocked an LSASS dump via comsvcs.dll MiniDump<br>`62154` L5 Windows Defender: Antimalware platform feature configuration changed |
| T1053.005 |  | #2 Scheduled task Local | **PASS** | `100140` L10 Scheduled task created that launches a script host or LOLBin: SCHTASKS  /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10<br>`62154` L5 Windows Defender: Antimalware platform feature configuration changed<br>`60228` L4 A scheduled task was created<br>`92004` L4 Powershell process spawned Windows command shell instance<br>`92110` L4 Detected WinRM activity from 0:0:0:0:0:0:0:1 to 0:0:0:0:0:0:0:1<br>... 3 more |
| T1547.001 |  | #1 Reg Key Run | **PASS** | `100151` L10 Run key persistence set by C:\\WINDOWS\\system32\\reg.exe: HKU\\S-1-5-21-1820488127-2641986668-2134518055-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Atomic Red Team<br>`92041` L10 Value added to registry key has Base64-like pattern |
| T1218.011 |  | #2 Rundll32 execute VBscript command | **PASS**<br>replay: `100120` | `100202` L13 Microsoft Defender blocked rundll32 script execution through mshtml<br>`62154` L5 Windows Defender: Antimalware platform feature configuration changed |
| T1105 |  | #7 certutil download (urlcache) | **PASS**<br>replay: `100130` | `100203` L12 Microsoft Defender blocked a certutil download<br>`62154` L5 Windows Defender: Antimalware platform feature configuration changed |
| T1136.001 |  | #4 Create a new user in a command prompt | **PASS** | `92040` L12 net1.exe executed a user creation command<br>`60109` L8 User account enabled or created<br>`60110` L8 User account changed<br>`60160` L5 Domain Users Group Changed<br>`60170` L5 Users Group Changed<br>... 1 more |
| T1087.001 |  | #8 Enumerate all accounts on Windows (Local) | **PASS** | `100190` L8 Burst of local account and group discovery commands on WIN11-EP<br>`92036` L3 A C:\\Windows\\System32\\net.exe binary was started by a Windows cmd shell |
| T1685.005 | T1070.001 | #1 Clear Logs (Security) | **PASS** | `100160` L12 Security audit log was cleared by WIN11-EP\labadmin<br>`100161` L12 Event log cleared with wevtutil: wevtutil  cl Security<br>`62154` L5 Windows Defender: Antimalware platform feature configuration changed<br>`61104` L3 Service startup type was changed |
| T1685 | T1562.001 | #19 Tamper with Windows Defender ATP PowerShell | **PASS** | `100170` L13 PowerShell attempted to disable Microsoft Defender protections<br>`62154` L5 Windows Defender: Antimalware platform feature configuration changed<br>`92027` L4 Powershell process spawned powershell instance |
