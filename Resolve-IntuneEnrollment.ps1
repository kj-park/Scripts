

#region define functions



    # Download PSTools

    function Download-PSTools {
        New-Item -Path C:\ -Name Scripts -ItemType Directory -Force
        if ( ! (Test-Path -Path C:\Scripts\PSTools.zip) {
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile C:\Scripts\PSTools.zip
        }
        Expand-Archive -Path C:\Scripts\PSTools.zip -DestinationPath C:\Scripts\PSTools -Force
        Remove-Item C:\Scripts\PSTools.zip
    }


    # Build Filtered Event Log Query by EventId

    function Build-FilterXPath {
        param (
            <#
            $SearchString = "(EventID=76 or EventID=95)"
            $SearchString = "(EventID=76)"
            #>
            $SearchString 
        )
        $QueryXPath = "<QueryList><Query><Select>*[System[$SearchString]]</Select></Query></QueryList>"
        return $QueryXPath
    }


    # Create MDM Enrollment Scheduled Task

    function Create-MDMScheduledTask {
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
                Write-Host -Object "MDM Scheduled Task is existed." -ForegroundColor Red
            }
        }
        if ( $Start ) {
            Start-ScheduledTask -TaskName '\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD'
        }
    }

    function Start-MDMScheduledTask {
        Start-ScheduledTask -TaskName '\Microsoft\Windows\EnterpriseMgmt\Schedule created by enrollment client for automatically enrolling in MDM from AAD'
    }


    # Get Current EnrollmentId

    function Get-CurrentEnrollmentId {
        $EnrollmentGUID = $null; $EnrollmentGUID = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId).CurrentEnrollmentId
        return $EnrollmentGUID
    }

    function Clear-CurrentEnrollmentId {
        $CurrentEnrollmentId = $null; $CurrentEnrollmentId = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId
        if ( $null -ne $CurrentEnrollmentId ) { Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -Force }
    }

    function Get-EnrollmentIds {
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
        $Ids = Get-EnrollmentIds
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
                    Write-Host "Processing registry key $Key"
                    # Remove registry entries
                    if (Test-Path -Path $Key) {
                        # Search for and remove keys with matching GUID
                        Write-Host " - GUID entry found in $Key. Removing..."
                        Get-ChildItem -Path $Key | Where-Object { $_.Name -match $EnrollmentGUID } | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }


    # Clear Scheduled Tasks for EnrollmentId

    function Get-MDMTaskName {
        $Name = $null
        $ScheduledTaskObject = New-Object -ComObject Schedule.Service
        $ScheduledTaskObject.Connect()

        $EnterpriseMgmt = $ScheduledTaskObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
        $ReturnTask = $null; $ReturnTask = $EnterpriseMgmt.GetTasks(0)
        if ( $null -ne $ReturnTask ) {
            $Name = $ReturnTask | Select-Object -ExpandProperty Name
        }
        return $Name
    }

    function Clear-EnrollmentTasks {
        param (
            $MDMTaskName = "Schedule created by enrollment client for automatically enrolling in MDM from AAD"
        )
        $EnrollmentGUIDs = Get-EnrollmentIds
        $Name = Get-MDMTaskName
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
                if ( $Cert.Issuer -eq 'CN=Microsoft Intune MDM Device CA' ) { $IntuneCerts += $IntuneCert }
                if ( $Cert.Issuer -like '*CN=MS-Organization*' ) { $IntuneCerts += $IntuneCert }
            }
        }
        $IntuneCerts | Remove-Item -Confirm:$false    
    }

    
    # Set Registries for MDM Enrollment

    function Prepare-EnrollmentRegistries {
        param ( $TenantId = "2ff1913c-2506-4fc1-98e5-2e18c7333baa" ) <# TODO: $TenantId = "2ff1913c-2506-4fc1-98e5-2e18c7333baa" #>

        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\' -Name MDM -Force -ErrorAction SilentlyContinue
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -Name AutoEnrollMDM -Value 1 -Force -ErrorAction SilentlyContinue
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -Name UseAADCredentialType -Value 1 -Force -ErrorAction SilentlyContinue

        $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$TenantId"

        New-ItemProperty -LiteralPath $Path -Name "MdmEnrollmentUrl" -Value "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc" -PropertyType String -Force -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath $Path  -Name "MdmTermsOfUseUrl" -Value "https://portal.manage.microsoft.com/TermsofUse.aspx" -PropertyType String -Force -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath $Path -Name "MdmComplianceUrl" -Value "https://portal.manage.microsoft.com/?portalAction=Compliance" -PropertyType String -Force -ErrorAction SilentlyContinue

        New-ItemProperty -LiteralPath $Path -Name "AuthCodeUrl" -Value "https://login.microsoftonline.com/$TenantId/oauth2/authorize" -PropertyType String -Force -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath $Path -Name "AccessTokenUrl" -Value "https://login.microsoftonline.com/$TenantId/oauth2/token" -PropertyType String -Force -ErrorAction SilentlyContinue
    }


    # Write Event Log for Status: Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational - 4027 - 다음 리소스(%1)에 현재 상태(%2)가 있습니다.

    function Write-StatusLog {
        param ( [String]$Resource, [String]$Status )
        New-WinEvent -ProviderName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider -Id 4027 -Payload @($Resource,$Status)
    }

    function Get-StatusLog {
        $Status = [PSCustomObject]@{Resource=$null;Status=$null}
        $EventLog = $null; $EventLog = Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational"; Id=4027 } -MaxEvents 1
        if ( $null -ne $EventLog ) {
            $Status.Resource = $EventLog.Properties.Item(0).Value
            $Status.Status   = $EventLog.Properties.Item(1).Value
            return $Status
        }
    }



#endregion define functions


#region Executing Script

    # Dignosing Azure AD Joined

    $AzureAdJoined  = if ( (Dsregcmd.exe /status | Select-String "AzureAdJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { $true } else { $false }
    

    $LogAdmin = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"

    $QueryXPath = Build-FilterXPath -SearchString "(EventID=75)"
    $MDMEnvent = $null; $MDMEnvent = Get-WinEvent -LogName $LogAdmin -FilterXPath $QueryXPath -MaxEvents 1 -ErrorAction SilentlyContinue
    if ( $null -eq $MDMEnvent ) { $Enrolled = $false } else { $Enrolled = $true }

    if ( $AzureAdJoined ) {
        if ( $Enrolled ) { Write-Host -Object "정상적으로 Intune Enrollment 작업이 완료되었습니다.`n" -ForegroundColor Cyan }
        else {
            $EnrollmentGUID = $null; $EnrollmentGUID = Get-CurrentEnrollmentId
            if ( $null -eq $EnrollmentGUID) {

                Write-Host -Object "STATUS: CurrentEnrollmentId 가 없습니다. MDM Scheduled Task 생성:`n" -ForegroundColor Yellow

                Prepare-EnrollmentRegistries
                Write-StatusLog -Resource HDO:MDM:EnrollmentRegistries -Status Create
                Write-Host -Object "`t$(Get-StatusLog)" -ForegroundColor Magenta

                Create-MDMScheduledTask -Start
                Write-StatusLog -Resource HDO:MDM:ScheduledTask -Status Create
                Write-Host -Object "`t$(Get-StatusLog)" -ForegroundColor Magenta
            }
            else {

                Write-Host -Object "STATUS: CurrentEnrollmentId Registries 및 Scheduled Tasks Clear 작업:`n" -ForegroundColor Yellow

                Clear-EnrollmentRegistry -EnrollmentGUIDs $EnrollmentGUID
                Clear-CurrentEnrollmentId
                Write-StatusLog -Resource HDO:MDM:EnrollmentRegistry -Status Clear
                Write-Host -Object "`t$(Get-StatusLog)" -ForegroundColor Magenta

                Clear-EnrollmentTasks
                Write-StatusLog -Resource HDO:MDM:EnrollmentTasks -Status Clear
                Write-Host -Object "`t$(Get-StatusLog)" -ForegroundColor Magenta

                Prepare-EnrollmentRegistries
                Write-StatusLog -Resource HDO:MDM:EnrollmentRegistries -Status Prepare
                Write-Host -Object "`t$(Get-StatusLog)" -ForegroundColor Magenta


                Create-MDMScheduledTask -Start
                Write-StatusLog -Resource HDO:MDM:MDMScheduledTask -Status Create
                Write-Host -Object "`t$(Get-StatusLog)" -ForegroundColor Magenta                
                
            }
        }
    }
    else {
        Write-Host -Object "아래 설명하는 단계의 수행이 필요합니다:`n" -ForegroundColor Cyan
        Write-Host -Object "`t1. 관리자 권한으로 명령프롬프트(cmd)를 실행하고 ""dsregcmd /leave"" 명령을 실행하고 컴퓨터를 재시작합니다." -ForegroundColor Cyan
        Write-Host -Object "`t2. 관리자 권한으로 명령프롬프트(cmd)를 실행하고 ""dsregcmd /join /debug"" 명령을 실행하고 컴퓨터를 재시작합니다." -ForegroundColor Cyan
        Write-StatusLog -Resource ADO:AzureADJoin -Status NO
    }

    Download-PSTools

    C:\Scripts\PSTools\PsExec64.exe -accepteula -s C:\Windows\system32\deviceenroller.exe /c /AutoEnrollMDM

#endregion Executing Script
