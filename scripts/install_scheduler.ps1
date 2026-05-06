#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers the NullBot signature updater as a Windows Scheduled Task.

.DESCRIPTION
    Creates a task that runs update_feeds.py every 6 hours using the system Python.
    Requires Administrator privileges and Python on PATH.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install_scheduler.ps1
#>

$ErrorActionPreference = "Stop"

$scriptPath = "C:\ProgramData\NullBot\signatures\updater\update_feeds.py"
$workDir    = "C:\ProgramData\NullBot"
$taskName   = "NullBot Signature Updater"

$action = New-ScheduledTaskAction `
    -Execute "python.exe" `
    -Argument $scriptPath `
    -WorkingDirectory $workDir

$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 6) `
    -RepetitionDuration ([timespan]::MaxValue)

$settings = New-ScheduledTaskSettingsSet `
    -RunOnlyIfNetworkAvailable `
    -WakeToRun:$false `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName    $taskName `
    -Action      $action `
    -Trigger     $trigger `
    -Settings    $settings `
    -Description "Updates NullBot threat signatures every 6 hours" `
    -RunLevel    Highest `
    -Force

Write-Host "Task '$taskName' registered. First run: $(Get-Date)"
