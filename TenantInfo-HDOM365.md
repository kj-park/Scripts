

# Entra Hybrid Joined 환경에서 Windows device들의 AzureAD Join 및 Intune Enrollment를 개선하기 위한 Scripts

Entra Hybrid Joined 환경에서 Windows device들의 AzureAD Join 및 Intune Enrollment를 개선하기 위한 Scripts 입니다.

## Script의 전체 Progress Overview

    - STEP 0 : Save-Tools

    - STEP 1 : AzureADJoin 여부를 dsregcmd /status 의 결과에서 DeviceId 값이 있는지로 판단
               (또는, Get-DeviceInfo 명령으로 RegistrationDataTime 값을 가져오는지 여부로 판단)

        STEP 1-1 : AzureADJoin : NO
            - dsregcmd /leave
            - 컴퓨터 Restart
            - "psexec -s C:\Windows\System32\dsregcmd.exe /join /debug" 명령으로 다시 join 시도합니다. (system 계정으로 실행합니다.)
            - 컴퓨터 Restart

        STEP 1-2 : AzureADJoin : YES
            - TASK : Enroll to Intune

    - STEP 2 : Intune Enrollment Task

        STEP 2-1 : Clear-EnrollmentRegistry
        STEP 2-2 : Clear-CurrentEnrollmentId
        STEP 2-3 : Clear-EnrollmentTasks
        STEP 2-4 : Clear-IntuneCertificate
        STEP 2-5 : New-EnrollmentScheduledTask -Start
        STEP 2-6 : deviceenroller.exe /c /AutoEnrollMDM

## REF : Utilization Functions

    - Save-Tools
    - New-IntuneEventLog
    - Register-ActionTool

## REF : STATUS, TASK, & STEP

    - STATUS:
        - STATUS:DOMAINJOINED
        - STATUS:AZUREADJOINED
        - STATUS:INTUNEENROLLED

    - TASKS & STEPS, STATUS:
        - TASK:START                : 0   : IntuneEnrollment : START
        - TASK:AzureADJoin          : 1   : AzureADJoin      : TASK:AzureADJoin
            - STATUS:DOMAINJOINED   : 2   : AzureADJoin      : STATUS:DOMAINJOINED
                - STEP:LEAVE        : 3   : AzureADJoin      : STEP:LEAVE
                - STEP:JOIN         : 4   : AzureADJoin      : STEP:JOIN
        - TASK:IntuneEnrollment     : 5   : IntuneEnrollment : TASK:IntuneEnrollment
            - STATUS:AZUREADJOINED  : 6   : IntuneEnrollment : STATUS:AZUREADJOINED
                - STEP:RESET        : 7   : IntuneEnrollment : STEP:RESET
            - STATUS:INTUNEENROLLED : 8   : IntuneEnrollment : STATUS:INTUNEENROLLED
        - TASK:CLEARTASK            : 9   : IntuneEnrollment : TASK:CLEARTASK
        - STEP: END                 : 100 : IntuneEnrollment : END

# Scheduled Task Configuration

    $TaskName   = "Intune Enrollment Task" 
    $Trigger    = New-ScheduledTaskTrigger -AtLogon
    $Action     = New-ScheduledTaskAction -Execute powershell.exe -Argument '-ExecutionPolicy Bypass -File "C:\Temp\Intune\Register-Intune.ps1"'
    #$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"

    $Task = Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -Action $Action #-Principal $Principal




#region Set Variable for HD현대오일뱅크

<#
Remove-Variable ClientId -Force
Remove-Variable ClientSecret -Force
Remove-Variable TenantId -Force
Remove-Variable TenantName -Force
#>

New-Variable -Name ClientId     -Value "2e1bbbd9-a60f-4969-99a3-474cd3ba824f"     -Option ReadOnly -Force
New-Variable -Name ClientSecret -Value "PVl8Q~QteRzRnTGTyYXOsQt7~xzwkQTd7hGMOa3q" -Option ReadOnly -Force
New-Variable -Name TenantId     -Value "2ff1913c-2506-4fc1-98e5-2e18c7333baa"     -Option ReadOnly -Force
New-Variable -Name TenantName   -Value "hdom365.onmicrosoft.com"                  -Option ReadOnly -Force

#endregion Set Variable for HD현대오일뱅크

