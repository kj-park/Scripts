function Invoke-AutoEnrollMDM {
    param ( $MaxCount = 30 )
    for ( $i = 1; $i -le $MaxCount; $i++ ) {
        $AutoEnrollMDM = Start-Process -FilePath C:\Temp\Intune\PSTools\PsExec64.exe -ArgumentList "-accepteula -nobanner -s C:\Windows\System32\DeviceEnroller.exe /c /AutoEnrollMDM" -PassThru
        $Result = $AutoEnrollMDM.ExitCode
        if ( $Result -eq 0 ) {
            Write-Host -Object "`t> 'DeviceEnroller.exe /c /AutoEnrollMDM' retruned: $($Result.ToString('x8'))" -ForegroundColor Cyan
            return
        } 
        else {
            Write-Host -Object "`t> 'DeviceEnroller.exe /c /AutoEnrollMDM' retruned: $($Result.ToString('x8'))" -ForegroundColor Magenta
            Start-Sleep -Seconds 60
        }
    }
}