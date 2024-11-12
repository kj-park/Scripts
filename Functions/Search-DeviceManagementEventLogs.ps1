function Search-DeviceManagementEventLogs {
    param (
        $QueryXPath = (Build-WinEventFilterXPath),
        $MaxEvents = 100
    )
    $LogAdmin = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    $EventLogs = $null; $EventLogs = Get-WinEvent -LogName $LogAdmin -FilterXPath $QueryXPath -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    if ( $null -ne $EventLogs ) {
        return $EventLogs
    }
}