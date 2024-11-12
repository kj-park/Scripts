function Register-EnableIntuneEnroll {
    $Action = New-ScheduledTaskAction -Execute PowerShell.exe -Argument {-ExecutionPolicy Bypass -File C:\Temp\Enable-IntuneEnroll.ps1}
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Settings = New-ScheduledTaskSettingsSet
    $Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM'
    $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
    Register-ScheduledTask -TaskName 'Enable-IntuneEnroll' -InputObject $Task

    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 98 -Message 'STATUS:Register-EnableIntuneEnroll'
}