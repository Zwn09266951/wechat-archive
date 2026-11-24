<#
.SYNOPSIS
  注册或更新 Windows 定时任务（WeChatDailyArchive），默认每 30 分钟增量归档一次微信聊天记录。
#>
param(
    [int]$IntervalMinutes = 30,
    [string]$TaskName = "WeChatDailyArchive"
)

$ErrorActionPreference = "Stop"

# 解析 py.exe 的真实路径，避免计划任务环境 PATH 差异
$pyCmd = (Get-Command py -ErrorAction Stop).Source
$scriptPath = "D:\wechat-archive\src\run_archive.py"
$workDir = "D:\wechat-archive"

$action = New-ScheduledTaskAction `
    -Execute $pyCmd `
    -Argument "`"$scriptPath`"" `
    -WorkingDirectory $workDir

$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "个人微信 4.x 本地聊天记录只读增量 Markdown 归档（每 $IntervalMinutes 分钟执行一次）" `
    -Force | Out-Null

Write-Host "[OK] 已注册 Windows 定时任务: $TaskName (每 $IntervalMinutes 分钟增量运行一次)"
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State
