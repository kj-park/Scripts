function Get-DeviceManagementEventLogs {
    param (
        [Validateset(71,75,76,95)][Int]$Id = 71,
        $MaxEvents = 100
    )
    $LogAdmin = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    $EventLogs = $null; $EventLogs = Get-WinEvent -FilterHashtable @{ LogName=$LogAdmin; Id=$Id } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    if ( $null -ne $EventLogs ) {
        return $EventLogs
    }
}