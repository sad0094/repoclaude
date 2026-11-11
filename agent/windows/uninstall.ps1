<#
Removes the Nobet Agent scheduled task and program files. Run from an elevated PowerShell.
The audit policy is left as it is; to turn connection auditing off again:
  auditpol /set "/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
  auditpol /set "/subcategory:{0CCE9225-69AE-11D9-BED3-505054503030}" /failure:disable
#>
[CmdletBinding()]
param([switch]$KeepConfig)
$ErrorActionPreference = 'Stop'
$taskName = 'NobetAgent'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
$programDir = Join-Path $env:ProgramFiles 'Nobet'
if (Test-Path -LiteralPath $programDir) { Remove-Item -LiteralPath $programDir -Recurse -Force }
$dataDir = Join-Path $env:ProgramData 'Nobet'
if (-not $KeepConfig -and (Test-Path -LiteralPath $dataDir)) { Remove-Item -LiteralPath $dataDir -Recurse -Force }
Write-Host 'Nobet Agent removed.'
