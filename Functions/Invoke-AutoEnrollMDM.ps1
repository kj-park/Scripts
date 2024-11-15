function Invoke-AutoEnrollMDM {
    param ( $MaxCount = 30 )
    for ( $i = 1; $i -le $MaxCount; $i++ ) {
        try { $IsDeviceRegisteredWithManagement = [MdmInterop]::IsDeviceRegisteredWithManagement() } catch { $IsDeviceRegisteredWithManagement = if ( (Get-DeviceInfo).ManagementType -eq "MDM" ) {$true} else {$false} }
        if ( ! $IsDeviceRegisteredWithManagement ) {
            invoke-Expression "C:\Temp\Intune\PSTools\PsExec64.exe -accepteula -nobanner -s  C:\Windows\System32\DeviceEnroller.exe /c /AutoEnrollMDM"
            if ( $LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -2145910774 ) {
                Write-Host -Object "`t> 'DeviceEnroller.exe /c /AutoEnrollMDM' retruned: Success or AlreadyEnrolled" -ForegroundColor Cyan
                return
            } 
            else {
                Write-Host -Object "`t> 'DeviceEnroller.exe /c /AutoEnrollMDM' retruned: ox$($LASTEXITCODE.ToString("X8"))" -ForegroundColor Magenta
                Start-Sleep -Seconds 60
            }
        } else { return }
    }
}