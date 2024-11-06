# .VERSION:1.0


#region define functions


function Save-Tools {
    New-Item -Path C:\ -Name Scripts -ItemType Directory -Force | Out-Null
    if ( ! (Test-Path -Path C:\Scripts\PSTools.zip) ) {
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile C:\Scripts\PSTools.zip
    }
    Expand-Archive -Path C:\Scripts\PSTools.zip -DestinationPath C:\Scripts\PSTools
    if ( ! (Test-Path -Path C:\Scripts\Resolve-IntuneEnrollmentFunctions.ps1) ) {
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/kj-park/Scripts/refs/heads/main/Resolve-IntuneEnrollmentFunctions.ps1' -OutFile C:\Scripts\Resolve-IntuneEnrollmentFunctions.ps1
    }
    Write-Host "# Downloaded the PSTools and Intune Enrollment Functions Script file to C:\Scripts" -ForegroundColor Yellow
}


#endregion define functions


#region Executing Script


    # Download Related Tool

    Save-Tools
    . C:\Scripts\Define-IntuneEnrollFunctions.ps1


    # Dignosing Azure AD Joined

    New-Item -Path C:\Scripts -Name Logs -ItemType Directory -Force | Out-Null

    C:\Windows\system32\dsregcmd.exe /status /debug | Out-File -FilePath C:\Scripts\Logs\dsregcmd-status-before.log -Force

    $AzureAdJoined  = if ( (Dsregcmd.exe /status | Select-String "AzureAdJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { $true } else { $false }
    # $DomainJoined  = if ( (Dsregcmd.exe /status | Select-String "DomainJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { $true } else { $false }    

    $LogAdmin = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"

    $QueryXPath = Build-FilterXPath -SearchString "(EventID=75)"
    $MDMEnvent = $null; $MDMEnvent = Get-WinEvent -LogName $LogAdmin -FilterXPath $QueryXPath -MaxEvents 1 -ErrorAction SilentlyContinue
    if ( $null -eq $MDMEnvent ) { $Enrolled = $false } else { $Enrolled = $true; "Success" | Out-File -FilePath C:\Scripts\Logs\mdm-enrolled.log -Force }

    if ( $AzureAdJoined ) {

        "[START] : $((Get-Date).ToString('yyyy-MM-dd HH-mm-ss'))" | Out-File -FilePath C:\Scripts\Logs\Enrollments.log -Force
        if ( $Enrolled ) {
            Write-Host -Object "STATUS: 정상적으로 Intune Enrollment 작업이 완료되었습니다.`n" -ForegroundColor Cyan
            Add-Content -Path C:\Scripts\Logs\Enrollments.log -Value "STATUS: 정상적으로 Intune Enrollment 작업이 완료되었습니다."
        }
        else {
            Write-Host -Object "STATUS: Enrollment 관련 Registries 및 Scheduled Tasks Clear 작업:`n" -ForegroundColor Cyan
            Add-Content -Path C:\Scripts\Logs\Enrollments.log -Value "STATUS : Enrollment 관련 Registries 및 Scheduled Tasks Clear 작업:"

            Clear-EnrollmentRegistry
            Add-Content -Path C:\Scripts\Logs\Enrollments.log -Value "`tTASK : 01 : Clear-EnrollmentRegistry"
            Write-StatusLog -Resource HDO:MDM:Reset -Status "01 : Clear-EnrollmentRegistry"

            Clear-CurrentEnrollmentId
            Add-Content -Path C:\Scripts\Logs\Enrollments.log -Value "`tTASK : 02 : Clear-CurrentEnrollmentId"
            Write-StatusLog -Resource HDO:MDM:Reset -Status "02 : Clear-CurrentEnrollmentId"


            Clear-EnrollmentTasks
            Add-Content -Path C:\Scripts\Logs\Enrollments.log -Value "`tTASK : 03 : Clear-EnrollmentTasks"
            Write-StatusLog -Resource HDO:MDM:Reset -Status "03 : Clear-EnrollmentTasks"

            Set-RegistryForEnrollment
            Add-Content -Path C:\Scripts\Logs\Enrollments.log -Value "`tTASK : 04 : Set-RegistryForEnrollment"
            Write-StatusLog -Resource HDO:MDM:Reset -Status "04 : Set-RegistryForEnrollment"


            New-MDMScheduledTask -Start
            Add-Content -Path C:\Scripts\Logs\Enrollments.log -Value "`tTASK : 05 : New-MDMScheduledTask"
            Write-StatusLog -Resource HDO:MDM:Reset -Status "05 : New-MDMScheduledTask"

            C:\Scripts\PSTools\PsExec64.exe -accepteula -s C:\Windows\system32\deviceenroller.exe /c /AutoEnrollMDM | Out-File -FilePath C:\Scripts\Logs\deviceenroller-autoenrollmdm.log

            Add-Content -Path C:\Scripts\Logs\Enrollments.log -Value "[END] : $((Get-Date).ToString('yyyy-MM-dd HH-mm-ss'))"

        }
    }
    else {

        "[START] : $((Get-Date).ToString('yyyy-MM-dd HH-mm-ss'))" | Out-File -FilePath C:\Scripts\Logs\AzureADJoin.log -Force

        C:\Scripts\PSTools\PsExec64.exe -accepteula -s C:\Windows\system32\dsregcmd.exe /join /debug | Out-File -FilePath C:\Scripts\Logs\dsregcmd-join-debug.log
        Add-Content -Path C:\Scripts\Logs\AzureADJoin.log -Value "`tTASK : 01 : dsregcmd.exe /join /debug"
        Write-StatusLog -Resource HDO:MDM:AzureADJoin -Status "01 : dsregcmd.exe /join /debug"

        Start-ScheduledTask -TaskName '\Microsoft\Windows\Workplace Join\Automatic-Device-Join'
        Add-Content -Path C:\Scripts\Logs\AzureADJoin.log -Value "`tTASK : 02 : Start Scheduled Task : Automatic-Device-Join"
        Write-StatusLog -Resource HDO:MDM:AzureADJoin -Status "02 : Start Scheduled Task : Automatic-Device-Join"

        Add-Content -Path C:\Scripts\Logs\AzureADJoin.log -Value "[END] : $((Get-Date).ToString('yyyy-MM-dd HH-mm-ss'))"

    }


#endregion Executing Script
