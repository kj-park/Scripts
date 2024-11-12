function Join-AzureAD {
    param ( $PSToolPath = 'C:\Temp\Intune\PSTools', $LogPath = 'C:\Temp\Intune\Logs' )
    $AzureAdJoined  = if ( (C:\Windows\system32\dsregcmd.exe /status | Select-String "AzureAdJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { $true } else { $false }
    if ( $AzureAdJoined ) {
        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 2 -Message "STEP : AzureADJoin : 디바이스가 AzureAD Joined 상태입니다."
        return $true
    }
    else {
        Set-EnrollmentRegistry
        Enable-ScheduledTask -TaskName '\Microsoft\Windows\Workplace Join\Automatic-Device-Join' -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName '\Microsoft\Windows\Workplace Join\Automatic-Device-Join' -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        C:\Temp\Intune\PSTools\PsExec64.exe -accepteula -s C:\Windows\system32\dsregcmd.exe /join /debug | Out-File -FilePath "$LogPath\dsregcmd-join-debug.log"
        Start-Sleep -Seconds 5
        $Result = Get-ScheduledTaskInfo -TaskName '\Microsoft\Windows\Workplace Join\Automatic-Device-Join' | Select-Object -ExpandProperty LastTaskResult
        if ( $Result -eq 0 ) {
            New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 3 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Join 작업을 수행하였습니다. PC 재시작이 필요합니다.`n`t> Log Location: $LogPath\dsregcmd-join-debug.log"
            return $true
        }
        else {
            New-IntuneEventLog -Source AzureADJoin -EntryType Error -EventId 4 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Error : ($($Result.ToString('x'))).`n`t> Log Location: $LogPath\dsregcmd-join-debug.log"
            return $false
        }
    }
}