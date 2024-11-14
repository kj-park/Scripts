function Get-EnableIntuneEnrollTask {
    $Task = Get-ScheduledTask -TaskName 'Enable-IntuneEnroll' -ErrorAction SilentlyContinue
    if ( $null -ne $Task ) { return $Task }
}