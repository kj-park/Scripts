function Get-EnrollmentIds {
    $EnrollmentIds = @()
    $CurrentEnrollmentId = Get-CurrentEnrollmentId
    if ( $null -ne $CurrentEnrollmentId ) { $EnrollmentIds += $CurrentEnrollmentId }
    $ScheduledTaskObject = New-Object -ComObject Schedule.Service
    $ScheduledTaskObject.Connect()
    $EnterpriseMgmt = $ScheduledTaskObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
    $FolderIds = @()
    $FolderIds += $EnterpriseMgmt.GetFolders(0) | Select-Object -ExpandProperty Name
    if ( $FolderIds.Count -gt 0 ) {
        foreach ( $Id in $FolderIds ) {
            if ( $CurrentEnrollmentId -ne $Id -and $Id -match '\w{8}-\w{4}-\w{4}-\w{4}-\w{12}' ) { $EnrollmentIds += $Id }
        }
    }
    return $EnrollmentIds
}