function UnRegister-EnableIntuneEnroll {
    Get-ScheduledTask -TaskName 'Enable-IntuneEnroll' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue     
}