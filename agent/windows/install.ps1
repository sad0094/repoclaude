<#
Installs the Nobet Agent on Windows Server. Run from an elevated PowerShell:

  .\install.ps1 -Manager https://panel.example.com -Token nbt_... [-EnableConnectionAudit]

-EnableConnectionAudit turns on the "Filtering Platform Connection" and "Filtering Platform
Packet Drop" audit subcategories so that EVERY inbound connection attempt (allowed and blocked)
is visible to the agent. This writes many events to the Security log; without the switch the
agent only sees connections that were actually established (capture mode "poll").

-EnableFileAudit turns on the "File System" audit subcategory and lets the agent add an audit
rule (SACL) to the sensitive folders that are defined in the Manager panel, so that file
operations in those folders are reported together with the user name. Inform the employees
of the company before enabling this (KVKK / data-protection law).

ASCII-only on purpose (see nobet-agent.ps1).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Manager,
    [Parameter(Mandatory = $true)][string]$Token,
    [switch]$EnableConnectionAudit,
    [switch]$EnableFileAudit
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}

$programDir = Join-Path $env:ProgramFiles 'Nobet'
$dataDir = Join-Path $env:ProgramData 'Nobet'
$configFile = Join-Path $dataDir 'agent.json'
$taskName = 'NobetAgent'

New-Item -ItemType Directory -Force -Path $programDir, $dataDir | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'nobet-agent.ps1') -Destination $programDir -Force

# The config holds the agent token: only SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) may read it.
# SIDs are used because group names are localized.
& icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict permissions on the configuration directory.' }

$capture = 'poll'
if ($EnableConnectionAudit) {
    # Subcategory GUIDs are used because subcategory names are localized.
    & auditpol.exe /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed for Filtering Platform Connection.' }
    & auditpol.exe /set '/subcategory:{0CCE9225-69AE-11D9-BED3-505054503030}' /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed for Filtering Platform Packet Drop.' }
    $capture = 'audit'
}

if ($EnableFileAudit) {
    & auditpol.exe /set '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed for File System.' }
}

if (Test-Path -LiteralPath $configFile) {
    Write-Host "$configFile already exists; left unchanged."
} else {
    @{ manager = $Manager; token = $Token; interval = 30; scan_interval = 300; capture = $capture
       file_audit = [bool]$EnableFileAudit } |
        ConvertTo-Json | Set-Content -LiteralPath $configFile -Encoding UTF8
}

$script = Join-Path $programDir 'nobet-agent.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $script)
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "Nobet Agent installed (capture mode: $capture)."
Write-Host "Log: $(Join-Path $dataDir 'agent.log')   Task: Get-ScheduledTask -TaskName $taskName"
