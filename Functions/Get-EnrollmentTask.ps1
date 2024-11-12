function Get-EnrollmentTask {
    $Tasks = @()
    $ScheduledTaskObject = New-Object -ComObject Schedule.Service
    $ScheduledTaskObject.Connect()
    $EnterpriseMgmt = $ScheduledTaskObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
    $ReturnTasks = $null; $ReturnTasks = $EnterpriseMgmt.GetTasks(0)
    if ( $null -ne $ReturnTasks ) {
        $Tasks += $ReturnTasks
        return $Tasks.Name
    }
}