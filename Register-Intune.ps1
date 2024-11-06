
#region Define Functions

<#
.EXAMPLE
    Popup-Window -Title "STEP: AzureAD Join" -Description "PC를 재시작하고 다음 과정을 진행해주세요." -Type 64
#>
function Popup-Window {
    param (
        $Title = 'Windows Title',
        $Description = 'Detailed Description',
        $SecondsToWait = 0,
        [ValidateSet(16, 32, 48, 64 )]
        $Type = 64
<#
16    Stop
32    Question
48    Exclamation
64    Information
#>
    )
    begin {
        $Return = $null
        $WShell = New-Object -ComObject WScript.Shell
        $SecondsToWait = 0
    }
    process {
        $Return = $WShell.Popup($Description,$SecondsToWait,$Title,$Type)
    }
    end {
        return $Return
    }
}

<#
.EXAMPLE
    New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 10001 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Join 작업을 수행하였습니다. PC 재시작이 필요합니다."
#>
function New-IntuneEventLog {
    param (
        [ValidateSet('AzureADJoin','IntuneEnrollment')]
        $Source = 'Intune Enrollment',
        [ValidateSet('Information','Warning', 'Error')]
        $EntryType = 'Information',
        [ValidateRange(0, 100)]
        $EventId = 99,
        $Message
    )
    begin {
        $LogName = 'Application'
        New-EventLog -LogName $LogName -Source $Source -ErrorAction SilentlyContinue
    }
    process {
        Write-EventLog -LogName $LogName -Source $Source -EntryType $EntryType -EventId $EventId -Message $Message
        Write-Host -Object "`n# $Message`n" -ForegroundColor Magenta
    }
}

<#
.EXAMPLE
    Save-Tools
#>
function Save-Tools {
    param ( $Path = "C:\Temp", $FolderName = "Intune" )
    New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 0 -Message "STEP : AzureADJoin : Downloaded the Diag & Execute Tool : $Path\$FolderName"
    New-Item -Path $Path -Name $FolderName -ItemType Directory -Force | Out-Null
    New-Item -Path "$Path\$FolderName" -Name Logs -ItemType Directory -Force | Out-Null
    New-Item -Path "$Path\$FolderName" -Name PSTools -ItemType Directory -Force | Out-Null
    if ( !(Test-Path -Path "$Path\$FolderName\PSTools.zip") ) {
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile "$Path\$FolderName\PSTools.zip"
    }
    Expand-Archive -Path "$Path\$FolderName\PSTools.zip" -DestinationPath "$Path\$FolderName\PSTools" -Force
}

<#
.EXAMPLE
    Set-RegistryForEnrollment -TenantId '2ff1913c-2506-4fc1-98e5-2e18c7333baa' -TenantName 'hdom365.onmicrosoft.com'
.EXAMPLE
    Set-RegistryForEnrollment
#>
function Set-RegistryForEnrollment {
    <# TODO: $TenantId = "2ff1913c-2506-4fc1-98e5-2e18c7333baa"; $TenantName = "hdom365.onmicrosoft.com" #>
    param (
        $TenantId = "2ff1913c-2506-4fc1-98e5-2e18c7333baa",
        $TenantName = "hdom365.onmicrosoft.com"
    )
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 5 -Message "STEP : IntuneEnrollment : Set-RegistryForEnrollment"

    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\' -Name MDM -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -Name AutoEnrollMDM -Value 1 -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -Name UseAADCredentialType -Value 1 -Force -ErrorAction SilentlyContinue # User: 1, Device: 2

    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$TenantId"

    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\' -Name $TenantId -Force -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $Path -Name "MdmEnrollmentUrl" -Value "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc" -PropertyType String -Force -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $Path  -Name "MdmTermsOfUseUrl" -Value "https://portal.manage.microsoft.com/TermsofUse.aspx" -PropertyType String -Force -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $Path -Name "MdmComplianceUrl" -Value "https://portal.manage.microsoft.com/?portalAction=Compliance" -PropertyType String -Force -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $Path -Name "AuthCodeUrl" -Value "https://login.microsoftonline.com/$TenantId/oauth2/authorize" -PropertyType String -Force -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $Path -Name "AccessTokenUrl" -Value "https://login.microsoftonline.com/$TenantId/oauth2/token" -PropertyType String -Force -ErrorAction SilentlyContinue

    $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD"

    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\' -Name 'CDJ' -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\' -Name 'AAD' -Force -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $Path -Name "TenantId" -Value $TenantId -PropertyType String -Force -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $Path -Name "TenantName" -Value $TenantName -PropertyType String -Force -ErrorAction SilentlyContinue
}

<#
.EXAMPLE
    Join-AzureAD
#>
function Join-AzureAD {
    param ( $PSToolPath = 'C:\Temp\Intune\PSTools', $LogPath = 'C:\Temp\Intune\Logs' )
    $AzureAdJoined  = if ( (Dsregcmd.exe /status | Select-String "AzureAdJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { $true } else { $false }
    if ( $AzureAdJoined ) {
        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 2 -Message "STEP : AzureADJoin : 디바이스가 AzureAD Joined 상태입니다."
        Popup-Window -Title "STEP: AzureAD Join" -Description "디바이스가 AzureAD Joined 상태입니다.`nPC 재시작하지 않고 다음 과정을 진행할 수 있습니다."
    }
    else {
        Set-RegistryForEnrollment
        Enable-ScheduledTask -TaskName '\Microsoft\Windows\Workplace Join\Automatic-Device-Join' -ErrorAction SilentlyContinue
        C:\Temp\Intune\PSTools\PsExec64.exe -accepteula -s C:\Windows\system32\dsregcmd.exe /join /debug | Out-File -FilePath "$LogPath\dsregcmd-join-debug.log"
        Start-Sleep -Seconds 1
        $Result = Get-ScheduledTaskInfo -TaskName '\Microsoft\Windows\Workplace Join\Automatic-Device-Join' | Select-Object -ExpandProperty LastTaskResult
        if ( $Result -eq 0 ) {
            New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 3 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Join 작업을 수행하였습니다. PC 재시작이 필요합니다.`n`t> Log Location: $LogPath\dsregcmd-join-debug.log"
        }
        else {
            New-IntuneEventLog -Source AzureADJoin -EntryType Error -EventId 4 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Error : ($($Result.ToString('x'))).`n`t> Log Location: $LogPath\dsregcmd-join-debug.log"
        }
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

function Get-DeviceManagementEventLogs {
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

function Search-DeviceManagementEventLogs {
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

function Clear-EnrollmentRegistry {
    param ($EnrollmentGUIDs = (Get-TargetEnrollmentIds))
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 2 -Message "STEP : IntuneEnrollment : Clear-EnrollmentRegistry"
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

function Get-CurrentEnrollmentId {
    $EnrollmentGUID = $null; $EnrollmentGUID = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -ErrorAction SilentlyContinue).CurrentEnrollmentId
    return $EnrollmentGUID
}

function Clear-CurrentEnrollmentId {
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 3 -Message "STEP : IntuneEnrollment : Clear-CurrentEnrollmentId"
    $CurrentEnrollmentId = $null; $CurrentEnrollmentId = Get-CurrentEnrollmentId
    if ( $null -ne $CurrentEnrollmentId ) { Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -Force }
}

function Get-EnrollmentTask {
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

function Clear-EnrollmentTasks {
    param (
        $EnrollmentTaskName = "Schedule created by enrollment client for automatically enrolling in MDM from AAD"
    )
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 4 -Message "STEP : IntuneEnrollment : Clear-EnrollmentTasks"
    $Name = Get-EnrollmentTask
    if ( [string]::IsNullOrEmpty($Name) ) { $Name = $EnrollmentTaskName }
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

function New-EnrollmentScheduledTask {
    param (
        $Reset = $true,
        [Switch]$Start
    )
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 6 -Message "STEP : IntuneEnrollment : New-EnrollmentScheduledTask"

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
        Start-Sleep -Seconds 10
        $LastTaskResult = (Get-ScheduledTaskInfo -TaskName "\Microsoft\Windows\EnterpriseMgmt\$TaskName").LastTaskResult.ToString("x")
        Write-Host -Object "`t> MDM Scheduled Task : Last Task Result returned: $LastTaskResult" -ForegroundColor Red
    }
}

#endregion Define Functions

New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 99 -Message "STEP : IntuneEnrollment : START"

Save-Tools

$DeviceManagementEvent = $null; $DeviceManagementEvent = Get-DeviceManagementEventLogs -Id 75
if ( $null -eq $DeviceManagementEvent ) { $Enrolled = $false } else { $Enrolled = $true; "Success" }

if ( $Enrolled ) {
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 1 -Message "STATUS : IntuneEnrollment : 정상적으로 Intune Enrollment 작업이 완료되었습니다."
}
else {
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 1 -Message "STATUS : IntuneEnrollment : 정상적으로 Intune Enrollment 작업이 완료되었습니다."
    Clear-EnrollmentRegistry

    Clear-CurrentEnrollmentId

    Clear-EnrollmentTasks

    Set-RegistryForEnrollment

    New-EnrollmentScheduledTask -Start

    C:\Temp\Intune\PSTools\PsExec64.exe -accepteula -s C:\Windows\system32\deviceenroller.exe /c /AutoEnrollMDM | Out-File -FilePath C:\Temp\Intune\Logs\deviceenroller-autoenrollmdm.log
}

New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 100 -Message "STEP : IntuneEnrollment : END"
