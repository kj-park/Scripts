function Invoke-AutoEnrollMDM {
    param ( $MaxCount = 30 )
    for ( $i = 1; $i -le $MaxCount; $i++ ) {
        $AutoEnrollMDM = Start-Process -FilePath C:\Temp\Intune\PSTools\PsExec64.exe -ArgumentList "-accepteula -nobanner -s C:\Windows\System32\DeviceEnroller.exe /c /AutoEnrollMDM" -PassThru
        if ( $AutoEnrollMDM.ExitCode -eq 0 ) {
            Write-Host -Object "`t> 'DeviceEnroller.exe /c /AutoEnrollMDM' retruned: 0x0" -ForegroundColor Cyan
            return
        } 
        else {
            $Result = $AutoEnrollMDM.ExitCode.ToString("x8")
            Write-Host -Object "`t> 'DeviceEnroller.exe /c /AutoEnrollMDM' retruned: 0x$Result" -ForegroundColor Magenta
            Start-Sleep -Seconds 60
        }
    } 
}