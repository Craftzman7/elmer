# provision-features.ps1 — enable IIS + classic ASP. Kept in its own file
# so PowerShell never has to parse the configure script's web content.
# Vagrant reboots after this provisioner.
$ErrorActionPreference = 'Stop'

function Say([string]$Msg) {
    Write-Host ""
    Write-Host "==> $Msg" -ForegroundColor Green
}

Say "enabling IIS + classic ASP"
$features = @(
    'IIS-WebServerRole',
    'IIS-WebServer',
    'IIS-CommonHttpFeatures',
    'IIS-StaticContent',
    'IIS-DefaultDocument',
    'IIS-DirectoryBrowsing',
    'IIS-HttpErrors',
    'IIS-ApplicationDevelopment',
    'IIS-ASP',
    'IIS-ISAPIExtensions',
    'IIS-ISAPIFilter',
    'IIS-HealthAndDiagnostics',
    'IIS-HttpLogging',
    'IIS-RequestFiltering',
    'IIS-Security',
    'IIS-WebServerManagementTools'
)
$enabled = (Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServer).State -eq 'Enabled'
if (-not $enabled) {
    Enable-WindowsOptionalFeature -Online -FeatureName $features -All -NoRestart | Out-Null
} else {
    Write-Host "IIS already enabled"
}
# OpenSSH Server ships in the gusztavvargadr box; make sure it is up
# so the attack chain can use it as a second foothold.
$sshd = Get-Service sshd -ErrorAction SilentlyContinue
if ($sshd) {
    Set-Service sshd -StartupType Automatic
    if ($sshd.Status -ne 'Running') { Start-Service sshd }
}
Say "features ready (reboot follows)"
