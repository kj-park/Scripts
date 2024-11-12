function UnRegister-EnableIntuneEnroll {
    Get-ScheduledTask -TaskName 'Enable-IntuneEnroll' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue 
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 99 -Message 'STATUS:UnRegister-EnableIntuneEnroll'
}