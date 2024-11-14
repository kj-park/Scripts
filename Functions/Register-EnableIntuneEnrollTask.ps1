function Register-EnableIntuneEnrollTask {
    $Action = New-ScheduledTaskAction -Execute PowerShell.exe -Argument {-ExecutionPolicy Bypass -File C:\Temp\Enable-IntuneEnroll.ps1}
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Settings = New-ScheduledTaskSettingsSet -Priority 4
    $Principal = New-ScheduledTaskPrincipal -UserId (whoami) -LogonType Interactive
    $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
    Register-ScheduledTask -TaskName 'Enable-IntuneEnroll' -InputObject $Task
}