# provision.ps1 — turn a vanilla Windows 11 box into an attackable elmer
# test target: weak accounts, an IIS command-injection app, a service with
# a world-writable binary, and elmer itself as a SYSTEM scheduled task.
#
# Vagrant runs this elevated after provision-features.ps1 (and a reboot).
# The binary, elmer-windows.yaml, and win-www/*.asp are already in
# C:\Windows\Temp.
$ErrorActionPreference = 'Stop'

function Say([string]$Msg) {
    Write-Host ""
    Write-Host "==> $Msg" -ForegroundColor Green
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Error "provision.ps1 must run elevated"
    exit 1
}

Say "disabling the firewall (lab box)"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
# Win11 Defender quarantines the IIS web shell and certutil drops otherwise.
Add-MpPreference -ExclusionPath 'C:\inetpub\wwwroot','C:\BackupSvc','C:\Windows\Temp' -ErrorAction SilentlyContinue

Say "relaxing password policy (lab accounts are weak on purpose)"
$secpol = Join-Path $env:TEMP 'elmer-secpol.cfg'
secedit /export /cfg $secpol | Out-Null
(Get-Content $secpol) `
    -replace 'PasswordComplexity\s*=\s*1', 'PasswordComplexity = 0' `
    -replace 'MinimumPasswordLength\s*=\s*\d+', 'MinimumPasswordLength = 1' |
    Set-Content $secpol
secedit /configure /db (Join-Path $env:TEMP 'elmer-secpol.sdb') /cfg $secpol /areas SECURITYPOLICY | Out-Null
net accounts /minpwlen:1 | Out-Null

Say "creating weak accounts"
function Ensure-User([string]$Name, [string]$Password) {
    if (-not (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) {
        net user $Name $Password /add /expires:never | Out-Null
    } else {
        net user $Name $Password | Out-Null
    }
    Set-LocalUser -Name $Name -PasswordNeverExpires $true -ErrorAction SilentlyContinue
}
Ensure-User analyst 'Analyst2024!'
Ensure-User svc_backup 'backup123'
Add-LocalGroupMember -Group 'Remote Desktop Users' -Member analyst -ErrorAction SilentlyContinue

Say "planting flags"
New-Item -ItemType Directory -Force -Path 'C:\Users\svc_backup' | Out-Null
Set-Content -Path 'C:\Users\svc_backup\flag.txt' -Encoding ASCII -Value 'flag{brut3_f0rc3_st1ll_w0rks}'
icacls 'C:\Users\svc_backup\flag.txt' /inheritance:r /grant "svc_backup:F" "Administrators:F" "SYSTEM:F" | Out-Null
Set-Content -Path 'C:\Windows\flag.txt' -Encoding ASCII -Value 'flag{weak_service_dacl}'
icacls 'C:\Windows\flag.txt' /inheritance:r /grant "Administrators:F" "SYSTEM:F" | Out-Null

Say "enabling RDP and SSH password authentication"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name fDenyTSConnections -Value 0
# sshd_config: first-match wins; prepend so we beat any later PasswordAuthentication no.
$sshdCfg = 'C:\ProgramData\ssh\sshd_config'
if (Test-Path $sshdCfg) {
    $cfg = Get-Content $sshdCfg
    $cfg = $cfg | Where-Object { $_ -notmatch '^\s*PasswordAuthentication\s+' }
    Set-Content -Path $sshdCfg -Value (@('PasswordAuthentication yes') + $cfg)
    Restart-Service sshd -ErrorAction SilentlyContinue
}

Say "installing the vulnerable web app"
if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue)) {
    Write-Error "IIS is not installed - re-run provision-features.ps1 (and a reboot)"
    exit 1
}
$www = 'C:\Windows\Temp'
foreach ($f in @('index.asp', 'ping.asp')) {
    $src = Join-Path $www $f
    if (-not (Test-Path $src)) {
        Write-Error "$src not found (file provisioner should have uploaded win-www/$f)"
        exit 1
    }
    Copy-Item $src (Join-Path 'C:\inetpub\wwwroot' $f) -Force
}
Set-Content -Path 'C:\inetpub\wwwroot\flag.txt' -Encoding ASCII -Value 'flag{c0mm4nd_1nj3ct10n}'
Remove-Item 'C:\inetpub\wwwroot\iisstart.htm' -ErrorAction SilentlyContinue
Remove-Item 'C:\inetpub\wwwroot\iisstart.png' -ErrorAction SilentlyContinue
# App pool must be able to drop a web shell later.
icacls 'C:\inetpub\wwwroot' /grant "IIS APPPOOL\DefaultAppPool:(OI)(CI)M" /grant "IIS_IUSRS:(OI)(CI)M" | Out-Null
Set-Service W3SVC -StartupType Automatic
Start-Service W3SVC
# Default document: prefer index.asp over iisstart leftovers.
$appcmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
if (Test-Path $appcmd) {
    & $appcmd set config 'Default Web Site' /section:defaultDocument /enabled:true /commit:apphost 2>$null | Out-Null
    & $appcmd set config 'Default Web Site' /section:defaultDocument "/-files.[value='iisstart.htm']" /commit:apphost 2>$null | Out-Null
    & $appcmd set config 'Default Web Site' /section:defaultDocument "/+files.[value='index.asp']" /commit:apphost 2>$null | Out-Null
}

Say "adding the BackupSvc misconfiguration (writable SYSTEM task script)"
# Analog of the Linux sudo-find GTFOBin: the IIS app pool overwrites the
# script and runs the on-demand task. Win11 SCM will not launch cmd.exe
# as a service (1053), so this is a scheduled task, not a Win32 service.
New-Item -ItemType Directory -Force -Path 'C:\BackupSvc' | Out-Null
Set-Content -Path 'C:\BackupSvc\backup.bat' -Encoding ASCII -Value "@echo off`r`nexit /b 0"
icacls 'C:\BackupSvc' /grant "Users:(OI)(CI)F" /grant "IIS_IUSRS:(OI)(CI)F" /grant "IIS APPPOOL\DefaultAppPool:(OI)(CI)F" | Out-Null
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c C:\BackupSvc\backup.bat'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'BackupSvc' -Action $action -Principal $principal -Force | Out-Null
# Everyone may schtasks /run it (IIS injection is how the attacker fires it).
$sched = New-Object -ComObject 'Schedule.Service'
$sched.Connect()
$sched.GetFolder('\').GetTask('BackupSvc').SetSecurityDescriptor(
    'D:(A;;FA;;;WD)(A;;FA;;;BA)(A;;FA;;;SY)', 0)

Say "checking the web app"
$ok = $false
foreach ($i in 1..15) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 'http://127.0.0.1/ping.asp?ip=127.0.0.1'
        if ($r.StatusCode -eq 200) { $ok = $true; break }
    } catch {
        Start-Sleep 2
    }
}
if (-not $ok) {
    Write-Error "IIS did not serve ping.asp on localhost"
    exit 1
}

Say "installing elmer"
$bin = $null
foreach ($cand in @($env:ELMER_BIN, 'C:\Windows\Temp\elmer.exe', 'C:\tmp\elmer.exe')) {
    if ($cand -and (Test-Path $cand)) { $bin = $cand; break }
}
if (-not $bin) {
    Write-Host "elmer binary not found."
    Write-Host "  build it:   make build-windows     (repo root)"
    Write-Host "  then run:   vagrant provision win01"
    Write-Host "or set ELMER_BIN to the uploaded .exe"
    exit 1
}
$yaml = 'C:\Windows\Temp\elmer.yaml'
if (-not (Test-Path $yaml)) {
    Write-Error "elmer.yaml not found at $yaml"
    exit 1
}
New-Item -ItemType Directory -Force -Path 'C:\elmer', 'C:\ProgramData\elmer' | Out-Null
Copy-Item $bin 'C:\elmer\elmer.exe' -Force
Copy-Item $yaml 'C:\elmer\elmer.yaml' -Force
# So `vagrant winrm -c elmer ...` resolves.
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notlike '*C:\elmer*') {
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;C:\elmer", 'Machine')
}
$env:Path += ';C:\elmer'

# 4688 + command line is the rich process telemetry source. Do this here
# as well as `elmer harden` so a failed admin heuristic cannot skip it.
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable | Out-Null
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /failure:enable | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

# 4688 + command line is the rich process telemetry source.
& 'C:\elmer\elmer.exe' harden

Get-Process -Name elmer -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1

$elmerCmd = 'C:\elmer\elmer.exe start -c C:\elmer\elmer.yaml'
$elmerAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $elmerCmd >> C:\elmer\elmer.log 2>&1"
$elmerTrigger = New-ScheduledTaskTrigger -AtStartup
$elmerPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName elmer -Action $elmerAction -Trigger $elmerTrigger -Principal $elmerPrincipal -Force | Out-Null

# Baseline after the elmer task exists so the sweep does not page it.
& 'C:\elmer\elmer.exe' audit -c 'C:\elmer\elmer.yaml' --write-baseline | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "elmer audit --write-baseline failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $elmerCmd >> C:\elmer\elmer.log 2>&1" -WindowStyle Hidden
Start-Sleep 5
if (-not (Get-Process -Name elmer -ErrorAction SilentlyContinue)) {
    Write-Host "elmer did not start:"
    if (Test-Path 'C:\elmer\elmer.log') { Get-Content 'C:\elmer\elmer.log' -Tail 40 }
    exit 1
}

Say "target ready"
Write-Host ""
Write-Host "  vulnerable app : http://192.168.56.20/ping.asp?ip=127.0.0.1"
Write-Host "  accounts       : analyst / Analyst2024!"
Write-Host "                   svc_backup / backup123   (brute-forceable)"
Write-Host "  privesc        : IIS app pool may schtasks /run BackupSvc"
Write-Host "                   (script at C:\BackupSvc\backup.bat is world-writable, SYSTEM)"
Write-Host "  flags          : C:\Users\svc_backup\flag.txt, C:\inetpub\wwwroot\flag.txt, C:\Windows\flag.txt"
Write-Host ""
Write-Host "  watch elmer    : vagrant winrm win01 -s powershell -c `"Get-Content C:\elmer\elmer.log -Wait`""
Write-Host "  attack it      : vm/attacks-win/run-all.sh   (from the repo root, on the host)"
Write-Host ""
