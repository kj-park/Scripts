function New-EnrollmentScheduledTask {
    param (
        $Reset = $true,
        [Switch]$Start
    )
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 8 -Message "STEP : IntuneEnrollment : New-EnrollmentScheduledTask"

    $ScheduledTaskXml = "<?xml version=""1.0"" encoding=""UTF-16""?><Task version=""1.3"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task""><RegistrationInfo><Author>Microsoft Corporation</Author><URI>\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD</URI><SecurityDescriptor>D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;LS)</SecurityDescriptor></RegistrationInfo> <Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval><Duration>P1D</Duration><StopAtDurationEnd>true</StopAtDurationEnd></Repetition><StartBoundary>$((Get-Date).AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss"))+09:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Principals><Principal id=""Author""><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context=""Author""><Exec><Command>%windir%\system32\deviceenroller.exe</Command><Arguments>/c /AutoEnrollMDM</Arguments></Exec></Actions></Task>"
    <# by DeviceCredential
    $ScheduledTaskXml = "<?xml version=""1.0"" encoding=""UTF-16""?><Task version=""1.3"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task""><RegistrationInfo><Author>Microsoft Corporation</Author><URI>\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD</URI><SecurityDescriptor>D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;LS)</SecurityDescriptor></RegistrationInfo> <Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval><Duration>P1D</Duration><StopAtDurationEnd>true</StopAtDurationEnd></Repetition><StartBoundary>$((Get-Date).AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss"))+09:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Principals><Principal id=""Author""><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context=""Author""><Exec><Command>%windir%\system32\deviceenroller.exe</Command><Arguments>/c /AutoEnrollMDMUsingAADDeviceCredential</Arguments></Exec></Actions></Task>"

    <Arguments>/c /AutoEnrollMDM</Arguments>
    <Arguments>//c /AutoEnrollMDMUsingAADDeviceCredential</Arguments>
    #>
    $TaskName = 'Schedule created by enrollment client for automatically enrolling in MDM from AAD'

    $Task = $null; $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ( $null -eq $Task ) {
        Register-ScheduledTask -XML $ScheduledTaskXml -TaskName "\Microsoft\Windows\EnterpriseMgmt\$TaskName" -Force
    }
    else {
        if ( $Reset ) {
            $Task | Unregister-ScheduledTask -Confirm:$false
            Register-ScheduledTask -XML $ScheduledTaskXml -TaskName "\Microsoft\Windows\EnterpriseMgmt\$TaskName" -Force
        }
        else {
            Write-Host -Object "`t> MDM Scheduled Task is existed." -ForegroundColor Red
        }
    }
    if ( $Start ) {
        Start-ScheduledTask -TaskName "\Microsoft\Windows\EnterpriseMgmt\$TaskName"
        Start-Sleep -Seconds 5
        $TaskInfo = $null; $TaskInfo = Get-ScheduledTaskInfo -TaskName "\Microsoft\Windows\EnterpriseMgmt\$TaskName" -ErrorAction SilentlyContinue
        if ( $null -eq $TaskInfo ) { $LastTaskResult = $null }
        else { $LastTaskResult = $TaskInfo.LastTaskResult.ToString("x") }
        Write-Host -Object "`t> MDM Scheduled Task : Last Task Result returned: $LastTaskResult" -ForegroundColor Red
    }
}