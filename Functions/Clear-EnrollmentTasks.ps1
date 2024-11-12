function Clear-EnrollmentTasks {
    param (
        $EnrollmentTaskName = "Schedule created by enrollment client for automatically enrolling in MDM from AAD"
    )
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 5 -Message "STEP : IntuneEnrollment : Clear-EnrollmentTasks"
    $Name = Get-EnrollmentTask
    if ( [string]::IsNullOrEmpty($Name) ) { $Name = $EnrollmentTaskName }
    $Task = $null; $Task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ( $null -ne $Task ) {
        $Task | Unregister-ScheduledTask -Confirm:$false
    }
    $ScheduledTaskObject = New-Object -ComObject Schedule.Service
    $ScheduledTaskObject.Connect()
    $EnterpriseMgmt = $ScheduledTaskObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")

    $Folders = @()
    $Folders += $EnterpriseMgmt.GetFolders(0) | Select-Object -Property Name,Path
    if ( $Folders.Count -gt 0 ) {
        foreach ( $Folder in $Folders ) {
            Get-ScheduledTask | Where-Object { $PSItem.Taskpath -match "\\Microsoft\\Windows\\EnterpriseMgmt\\$($Folder.Name)\\*" } | Unregister-ScheduledTask -Confirm:$false
            $EnterpriseMgmt.DeleteFolder($Folder.Name,0)
        }
    }
}