# .VERSION:1.0


#region define functions


    # Download PSTools

    function Save-Tools {
        New-Item -Path C:\ -Name Scripts -ItemType Directory -Force | Out-Null
        if ( ! (Test-Path -Path C:\Scripts\PSTools.zip) ) {
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile C:\Scripts\PSTools.zip
        }
        Expand-Archive -Path C:\Scripts\PSTools.zip -DestinationPath C:\Scripts\PSTools
        <#
        if ( ! (Test-Path -Path C:\Scripts\Define-IntuneEnrollFunctions.ps1) ) {
            Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/kj-park/Scripts/refs/heads/main/Define-IntuneEnrollFunctions.ps1' -OutFile C:\Scripts\Define-IntuneEnrollFunctions.ps1
        }
            #>
        Write-Host "# Downloaded the PSTools and Intune Enrollment Functions Script file to C:\Scripts" -ForegroundColor Yellow
    }
  

    # Create MDM Enrollment Scheduled Task

    function New-MDMScheduledTask {
        param (
            $Reset = $true,
            [Switch]$Start
        )
        $ScheduledTaskXml = "<?xml version=""1.0"" encoding=""UTF-16""?><Task version=""1.3"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task""><RegistrationInfo><Author>Microsoft Corporation</Author><URI>\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD</URI><SecurityDescriptor>D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;LS)</SecurityDescriptor></RegistrationInfo> <Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval><Duration>P1D</Duration><StopAtDurationEnd>true</StopAtDurationEnd></Repetition><StartBoundary>$((Get-Date).AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss"))+09:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Principals><Principal id=""Author""><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context=""Author""><Exec><Command>%windir%\system32\deviceenroller.exe</Command><Arguments>/c /AutoEnrollMDM</Arguments></Exec></Actions></Task>"
        <# by DeviceCredential
        $ScheduledTaskXml = "<?xml version=""1.0"" encoding=""UTF-16""?><Task version=""1.3"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task""><RegistrationInfo><Author>Microsoft Corporation</Author><URI>\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD</URI><SecurityDescriptor>D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;LS)</SecurityDescriptor></RegistrationInfo> <Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval><Duration>P1D</Duration><StopAtDurationEnd>true</StopAtDurationEnd></Repetition><StartBoundary>$((Get-Date).AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss"))+09:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Principals><Principal id=""Author""><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context=""Author""><Exec><Command>%windir%\system32\deviceenroller.exe</Command><Arguments>/c /AutoEnrollMDMUsingAADDeviceCredential</Arguments></Exec></Actions></Task>"
    
        <Arguments>/c /AutoEnrollMDM</Arguments>
        <Arguments>//c /AutoEnrollMDMUsingAADDeviceCredential</Arguments>
        #>

        $Task = $null; $Task = Get-ScheduledTask -TaskName 'Schedule created by enrollment client for automatically enrolling in MDM from AAD' -ErrorAction SilentlyContinue
        if ( $null -eq $Task ) {
            Register-ScheduledTask -XML $ScheduledTaskXml -TaskName '\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD' -Force
        }
        else {
            if ( $Reset ) {
                $Task | Unregister-ScheduledTask -Confirm:$false
                Register-ScheduledTask -XML $ScheduledTaskXml -TaskName '\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD' -Force
            }
            else {
                Write-Host -Object "`t> MDM Scheduled Task is existed." -ForegroundColor Red
            }
        }
        if ( $Start ) {
            Start-ScheduledTask -TaskName '\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD'
            Start-Sleep -Seconds 10
            $LastTaskResult = (Get-ScheduledTaskInfo -TaskName '\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD').LastTaskResult.ToString("x")
            Write-Host -Object "`t> MDM Scheduled Task : Last Task Result returned: $LastTaskResult" -ForegroundColor Red
        }
    }

    function Start-MDMScheduledTask {
        Start-ScheduledTask -TaskName '\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD'
        Start-Sleep -Seconds 10
        $LastTaskResult = (Get-ScheduledTaskInfo -TaskName '\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD').LastTaskResult.ToString("x")
        Write-Host -Object "`t> MDM Scheduled Task : Last Task Result returned: $LastTaskResult" -ForegroundColor Red
    }


    # Get Current EnrollmentId

    function Get-CurrentEnrollmentId {
        $EnrollmentGUID = $null; $EnrollmentGUID = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -ErrorAction SilentlyContinue).CurrentEnrollmentId
        return $EnrollmentGUID
    }

    function Clear-CurrentEnrollmentId {
        $CurrentEnrollmentId = $null; $CurrentEnrollmentId = Get-CurrentEnrollmentId
        if ( $null -ne $CurrentEnrollmentId ) { Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -Force }
    }

    function Get-EnrollmentIdsFromFolder {
        param ( [Switch]$IncludePath )
        $ScheduledTaskObject = New-Object -ComObject Schedule.Service
        $ScheduledTaskObject.Connect()
        $EnterpriseMgmt = $ScheduledTaskObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
        $Folders = @()
        $Folders += $EnterpriseMgmt.GetFolders(0) | Select-Object -Property Name,Path
        if ( $Folders.Count -gt 0 ) {
            if ( $IncludePath ) {
                return $Folders
            }
            else {
                return $Folders.Name
            }
        }
    }

    function Get-TargetEnrollmentIds {
        $EnrollmentIds = @()
        $CurrentEnrollmentId = Get-CurrentEnrollmentId
        if ( $null -ne $CurrentEnrollmentId ) { $EnrollmentIds += $CurrentEnrollmentId }
        $Ids = Get-EnrollmentIdsFromFolder
        if ( $null -ne $Folders ) {
            foreach ( $Id in $Ids ) {
                if ( $CurrentEnrollmentId -ne $Id ) { $EnrollmentIds += $Id }
            }
        }
        return $EnrollmentIds
    }


    # Clear Current EnrollmentId in Registry

    function Clear-EnrollmentRegistry {
        param ($EnrollmentGUIDs = (Get-TargetEnrollmentIds))

        $RegistryKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Enrollments"
            "HKLM:\SOFTWARE\Microsoft\Enrollments\Status"
            "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked"
            "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled"
            "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers"
            "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"
            "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger"
            "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions"
        )
        if ( $null -ne $EnrollmentGUIDs ) {
            foreach ( $EnrollmentGUID in $EnrollmentGUIDs ) {
                foreach ($Key in $RegistryKeys) {
                    Write-Host "`t> Processing registry key $Key" -ForegroundColor Red
                    # Remove registry entries
                    if (Test-Path -Path $Key) {
                        # Search for and remove keys with matching GUID
                        Write-Host "`t`t> GUID entry found in $Key. Removing..." -ForegroundColor Red
                        Get-ChildItem -Path $Key | Where-Object { $_.Name -match $EnrollmentGUID } | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }


    # Clear Scheduled Tasks for EnrollmentId

    function Get-MDMTask {
        $Name = $null
        $Tasks = @()
        $ScheduledTaskObject = New-Object -ComObject Schedule.Service
        $ScheduledTaskObject.Connect()
        $EnterpriseMgmt = $ScheduledTaskObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
        $ReturnTasks = $null; $ReturnTasks = $EnterpriseMgmt.GetTasks(0)
        if ( $null -ne $ReturnTasks ) {
            $Tasks += $ReturnTasks
            return $Tasks.Name
        }
    }

    function Clear-EnrollmentTasks {
        param (
            $MDMTaskName = "Schedule created by enrollment client for automatically enrolling in MDM from AAD"
        )
        $EnrollmentGUIDs = Get-EnrollmentIdsFromFolder
        $Name = Get-MDMTask
        if ( [string]::IsNullOrEmpty($Name) ) { $Name = $MDMTaskName }
        $Task = $null; $Task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
        if ( $null -ne $Task ) {
            $Task | Unregister-ScheduledTask -Confirm:$false
        }
        $ScheduledTaskObject = New-Object -ComObject Schedule.Service
        $ScheduledTaskObject.Connect()
        $EnterpriseMgmt = $ScheduledTaskObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")

        $Folders = @()
        $Folders += $EnterpriseMgmt.GetFolders(0) | Select-Object -Property Name,Path
        if ( $Folders.Count -gt 0 ) {
            foreach ( $Folder in $Folders ) {
                Get-ScheduledTask | Where-Object { $PSItem.Taskpath -match "\\Microsoft\\Windows\\EnterpriseMgmt\\$($Folder.Name)\\*" } | Unregister-ScheduledTask -Confirm:$false
                $EnterpriseMgmt.DeleteFolder($Folder.Name,0)
            }

        }
    }


    # Clear Intune Certificate

    function Clear-IntuneCertificate {
        $IntuneCerts = @()
        $Certs = Get-ChildItem -Path Cert:\LocalMachine\My
        if ($Certs.Count -gt 0 ) {
            foreach ( $Cert in $Certs ) {
                if ( $Cert.Issuer -eq 'CN=Microsoft Intune MDM Device CA' ) { $IntuneCerts += $Cert }
                if ( $Cert.Issuer -like '*CN=MS-Organization*' ) { $IntuneCerts += $Cert }
            }
        }
        $IntuneCerts | Remove-Item -Confirm:$false
    }

    
    # Set Registries for MDM Enrollment

    function Set-RegistryForEnrollment {
        <# TODO: $TenantId = "2ff1913c-2506-4fc1-98e5-2e18c7333baa"; $TenantName = "hdom365.onmicrosoft.com" #>
        param (
            $TenantId = "2ff1913c-2506-4fc1-98e5-2e18c7333baa",
            $TenantName = "hdom365.onmicrosoft.com"
        )

        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\' -Name MDM -Force -ErrorAction SilentlyContinue
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -Name AutoEnrollMDM -Value 1 -Force -ErrorAction SilentlyContinue
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -Name UseAADCredentialType -Value 1 -Force -ErrorAction SilentlyContinue # User: 1, Device: 2

        $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$TenantId"

        New-ItemProperty -LiteralPath $Path -Name "MdmEnrollmentUrl" -Value "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc" -PropertyType String -Force -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath $Path  -Name "MdmTermsOfUseUrl" -Value "https://portal.manage.microsoft.com/TermsofUse.aspx" -PropertyType String -Force -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath $Path -Name "MdmComplianceUrl" -Value "https://portal.manage.microsoft.com/?portalAction=Compliance" -PropertyType String -Force -ErrorAction SilentlyContinue

        New-ItemProperty -LiteralPath $Path -Name "AuthCodeUrl" -Value "https://login.microsoftonline.com/$TenantId/oauth2/authorize" -PropertyType String -Force -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath $Path -Name "AccessTokenUrl" -Value "https://login.microsoftonline.com/$TenantId/oauth2/token" -PropertyType String -Force -ErrorAction SilentlyContinue

        $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD"

        New-ItemProperty -LiteralPath $Path -Name "TenantId" -Value $TenantId -PropertyType String -Force -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath $Path -Name "TenantName" -Value $TenantName -PropertyType String -Force -ErrorAction SilentlyContinue
    }

    
    # Write and Get Status to Event log : Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational : 4027

    function Write-StatusLog {
        param ( [String]$Resource, [String]$Status )
        New-WinEvent -ProviderName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider -Id 4027 -Payload @($Resource,$Status)
    }

    function Get-StatusLog {
        param ($MaxEvents = 1)        
        $EventLogs = $null; $EventLogs = Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational"; Id=4027 } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        if ( $null -ne $EventLogs ) {
            $Logs = @()
            foreach ( $EventLog in $EventLogs ) {
                $Status = [PSCustomObject]@{Resource=$null;Status=$null}
                $Status.Resource = $EventLog.Properties.Item(0).Value
                $Status.Status   = $EventLog.Properties.Item(1).Value
                $Logs += $Status
            }
            return $Logs
        }
    }


    # Get Error from Event Log : Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin : 71, 76, 95, 75

    function Build-FilterXPath {
        param (
            $SearchString = "(EventID=71 or EventID=75 or EventID=76 or EventID=95)"
        )
        $QueryXPath = "<QueryList><Query><Select>*[System[$SearchString]]</Select></Query></QueryList>"
        return $QueryXPath
    }

    function Get-MDMEventLogs {
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

    function Search-MDMEventLogs {
        param (
            $QueryXPath = (Build-FilterXPath),
            $MaxEvents = 100
        )
        $LogAdmin = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
        $EventLogs = $null; $EventLogs = Get-WinEvent -LogName $LogAdmin -FilterXPath $QueryXPath -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        if ( $null -ne $EventLogs ) {
            return $EventLogs
        }
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
