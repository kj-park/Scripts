

<#
@echo off
Copy \\server\sharefolder\Intune\Enable-IntuneEnroll.ps1 C:\Temp /Y
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process PowerShell.exe -ArgumentList '-ExecutionPolicy Bypass -File ""C:\Temp\Enable-IntuneEnroll.ps1""' -Verb RunAs"
#>

#region Set Variable for the specific Tenant

<#
Remove-Variable TenantId -Force
Remove-Variable TenantName -Force
#>

New-Variable -Name TenantId     -Value "xxxxxxxx-xxxx-xxx-xxxx-xxxxxxxxxxxx"    -Option ReadOnly -Force
New-Variable -Name TenantName   -Value "xxxx.onmicrosoft.com"                   -Option ReadOnly -Force

#region Set Variable for the specific Tenant


#region Define Types: MdmInterop, NetInterop

if (-not ([System.Management.Automation.PSTypeName]'MdmInterop').Type) {
$isRegisteredPinvoke = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class MdmInterop
{
    //DeviceRegistrationBasicInfo - Information about the device registration.
    //MaxDeviceInfoClass      - Max Information about the device registration.
    private enum _REGISTRATION_INFORMATION_CLASS
    {
        DeviceRegistrationBasicInfo = 1,
        MaxDeviceInfoClass
    }

    private  enum DEVICEREGISTRATIONTYPE
    {
        DEVICEREGISTRATIONTYPE_MDM_ONLY = 0,
        DEVICEREGISTRATIONTYPE_MAM = 5,
        DEVICEREGISTRATIONTYPE_MDM_DEVICEWIDE_WITH_AAD = 6,
        DEVICEREGISTRATIONTYPE_MDM_USERSPECIFIC_WITH_AAD = 13
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct _MANAGEMENT_REGISTRATION_INFO
    {
        public bool fDeviceRegisteredWithManagement;
        public int dwDeviceRegistionKind;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pszUPN;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pszMDMServiceUri;
    }

    [DllImport("mdmregistration.dll")]
    private static extern int IsDeviceRegisteredWithManagement(ref bool isDeviceRegisteredWithManagement, int upnMaxLength, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder upn);

    [DllImport("mdmregistration.dll")]
    private static extern int GetDeviceRegistrationInfo(_REGISTRATION_INFORMATION_CLASS classType, out IntPtr regInfo);

    public static bool IsDeviceRegisteredWithManagement()
    {
        bool isRegistered = false;
        StringBuilder upn = new StringBuilder(256);
        int hr = IsDeviceRegisteredWithManagement(ref isRegistered, upn.MaxCapacity, upn);
        if (hr != 0)
        {
            throw new Win32Exception(hr);
        }

        //Console.WriteLine("IsDeviceRegisteredWithManagement: Result: 0x{0:x} Upn: {1} IsRegistered: {2}", hr, upn, isRegistered);
        return isRegistered;
    }

    public static bool IsAadBasedEnrollment()
    {
        bool result = false;
        IntPtr pPtr = IntPtr.Zero;

        _REGISTRATION_INFORMATION_CLASS classType = _REGISTRATION_INFORMATION_CLASS.DeviceRegistrationBasicInfo;

        int hr = 0;
        try
        {
            hr = GetDeviceRegistrationInfo(classType, out pPtr);
        }
        catch
        {
            //OS Not support
            return result;
        }

        if (hr != 0)
        {
            throw new Win32Exception(hr);
        }

        _MANAGEMENT_REGISTRATION_INFO regInfo = (_MANAGEMENT_REGISTRATION_INFO)(Marshal.PtrToStructure(pPtr, typeof(_MANAGEMENT_REGISTRATION_INFO)));

        if (regInfo.dwDeviceRegistionKind == (int)DEVICEREGISTRATIONTYPE.DEVICEREGISTRATIONTYPE_MDM_DEVICEWIDE_WITH_AAD)
        {
            result = true;
        }

        return result;
    }
}
"@
Add-Type -TypeDefinition $isRegisteredPinvoke -Language CSharp -ErrorAction SilentlyContinue
}

if (-not ([System.Management.Automation.PSTypeName]'NetInterop').Type) {
$isAADJoinPinvoke = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

    public static class NetInterop
    {
        [DllImport("netapi32.dll")]
        public static extern int NetGetAadJoinInformation(string pcszTenantId, out IntPtr ppJoinInfo);

        [DllImport("netapi32.dll")]
        public static extern void NetFreeAadJoinInformation(IntPtr pJoinInfo);

        [DllImport("netapi32.dll")]
        public static extern int NetGetJoinInformation(string server, out IntPtr name, out NetJoinStatus status);

        //NetSetupUnknownStatus - The status is unknown.
        //NetSetupUnjoined      - The computer is not joined.
        //NetSetupWorkgroupName - The computer is joined to a workgroup.
        //NetSetupDomainName    - The computer is joined to a domain.
        public enum NetJoinStatus
        {
            NetSetupUnknownStatus = 0,
            NetSetupUnjoined,
            NetSetupWorkgroupName,
            NetSetupDomainName
        }

        public static bool IsADJoined()
        {
            IntPtr pPtr = IntPtr.Zero;
            NetJoinStatus joinStatus = new NetJoinStatus();

            int hr = NetGetJoinInformation(null, out pPtr, out joinStatus);

            if (hr != 0)
            {
                throw new Win32Exception(hr);
            }

            if (joinStatus == NetJoinStatus.NetSetupDomainName)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsAADJoined()
        {
            bool result = false;
            IntPtr pPtr = IntPtr.Zero;

            int hr = 0;
            try
            {
                hr = NetGetAadJoinInformation(null, out pPtr);
                if (hr == 1)
                {
                    //In correct function on 17763.1577 server
                    return false;
                }
                else if(hr != 0)
                {
                    throw new Win32Exception(hr);
                }

                if (pPtr != IntPtr.Zero)
                {
                    result = true;
                }
                else
                {
                    result = false;
                }
            }
            catch
            {
                //OS Not support
                return false;
            }
            finally
            {
                if(pPtr != IntPtr.Zero)
                {
                    NetFreeAadJoinInformation(pPtr);
                }
            }

            return result;
        }
    }
"@
Add-Type -TypeDefinition $isAADJoinPinvoke -Language CSharp -ErrorAction SilentlyContinue
}

#endregion #region Define Types: MdmInterop, NetInterop


#region Define Functions

function Invoke-PopupWindow {
    <#
    .DESCRIPTION
    Script에서 사용자의 선택을 확인하기 위해 Window를 popup하고 선택을 확인합니다.

    .EXAMPLE
        Invoke-PopupWindow -Title "STEP: AzureAD Join" -Description "PC를 재시작하고 다음 과정을 진행해주세요." -Style OkCancel -IconType Exclamation
    #>
    param (
        $Title = 'Windows Title',
        $Description = 'Detailed Description',
        $SecondsToWait = 0,
        [ValidateSet('OkOnly', 'OkCancel', 'AbortRetryIgnore', 'YesNoCancel', 'YesNo', 'RetryCancel')]
        $Style = 'OkCancel',
        [ValidateSet('Critical', 'Question', 'Exclamation', 'Information' )]
        $IconType = 'Information'
    )
    begin {
        $IntStyle = switch ($Style) { 'OkOnly' {0}; 'OkCancel' {1}; 'AbortRetryIgnore' {2}; 'YesNoCancel'{3}; 'YesNo' {4}; 'RetryCancel' {5} }
        $IntType = switch ($IconType) { 'Critical' {16}; 'Question' {32}; 'Exclamation' {48}; 'Information'{64} }

        $Return = $null
        $WShell = New-Object -ComObject WScript.Shell
    }
    process {
        $Return = $WShell.Popup($Description, $SecondsToWait, $Title, $IntStyle + $IntType)
        $Return = switch ($Return) { 1 {'Ok'}; 2 {'Cancel'}; 3 {'Abort'}; 4 {'Retry'}; 5 {'Ignore'}; 6 {'Yes'}; 7 {'No'}; Default {$null} }
        return $Return
    }
}

function New-IntuneEventLog {
    <#
    .DESCRIPTION
    Entra Id Join 및 Intune Enrollment 관련 Tasks 및 Status들에 대하여 Application Event Log에 기록합니다.

    .EXAMPLE
        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 100 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Join 작업을 수행하였습니다. PC 재시작이 필요합니다."
    #>
    param (
        [ValidateSet('AzureADJoin','IntuneEnrollment')]
        $Source = 'IntuneEnrollment',
        [ValidateSet('Information','Warning', 'Error')]
        $EntryType = 'Information',
        [ValidateRange(0, 100)]
        $EventId = 0,
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

function Save-Tools {
    <#
    .DESCRIPTION
    $Path\$FolderName 에 PSTools 와 Logs 폴더를 생성합니다. 각 폴더의 설명은 아래와 같습니다:
        - PSTools : Sysinternal의 PSTools을 download 및 압축 해제합니다.
        - Logs : 진단 및 결과를 저장하기 위한 폴더입니다.
    #>
    param ( $Path = "C:\Temp", $FolderName = "Intune" )
    New-Item -Path $Path -Name $FolderName -ItemType Directory -Force | Out-Null
    New-Item -Path "$Path\$FolderName" -Name Logs -ItemType Directory -Force | Out-Null
    New-Item -Path "$Path\$FolderName" -Name PSTools -ItemType Directory -Force | Out-Null
    if ( !(Test-Path -Path "$Path\$FolderName\PSTools.zip") ) {
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile "$Path\$FolderName\PSTools.zip"
    }
    Expand-Archive -Path "$Path\$FolderName\PSTools.zip" -DestinationPath "$Path\$FolderName\PSTools" -Force
}

function Set-EnrollmentRegistry {
    <# TODO: $TenantId = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"; $TenantName = "XXXX.onmicrosoft.com" #>
    param (
        $TenantId = $TenantId,
        $TenantName = $TenantName
    )
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

function Join-AzureAD {
    param ( $PSToolPath = 'C:\Temp\Intune\PSTools', $LogPath = 'C:\Temp\Intune\Logs' )
    $AzureAdJoined  = if ( (C:\Windows\system32\dsregcmd.exe /status | Select-String "AzureAdJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { $true } else { $false }
    if ( $AzureAdJoined ) {
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
            New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 33 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Join 작업을 수행하였습니다. PC 재시작이 필요합니다.`n`t> Log Location: $LogPath\dsregcmd-join-debug.log"
            return $true
        }
        else {
            New-IntuneEventLog -Source AzureADJoin -EntryType Error -EventId 44 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Error : ($($Result.ToString('x'))).`n`t> Log Location: $LogPath\dsregcmd-join-debug.log"
            return $Result.ToString('x')
        }
    }
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

function Build-WinEventFilterXPath {
    param (
        $SearchString = "(EventID=71 or EventID=75 or EventID=76 or EventID=95)"
    )
    $QueryXPath = "<QueryList><Query><Select>*[System[$SearchString]]</Select></Query></QueryList>"
    return $QueryXPath
}

function Search-DeviceManagementEventLogs {
    param (
        $QueryXPath = (Build-WinEventFilterXPath),
        $MaxEvents = 100
    )
    $LogAdmin = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    $EventLogs = $null; $EventLogs = Get-WinEvent -LogName $LogAdmin -FilterXPath $QueryXPath -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    if ( $null -ne $EventLogs ) {
        return $EventLogs
    }
}

function Get-CurrentEnrollmentId {
    $EnrollmentGUID = $null; $EnrollmentGUID = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -ErrorAction SilentlyContinue).CurrentEnrollmentId
    return $EnrollmentGUID
}

function Get-EnrollmentIds {
    $EnrollmentIds = @()
    $CurrentEnrollmentId = Get-CurrentEnrollmentId
    if ( $null -ne $CurrentEnrollmentId ) { $EnrollmentIds += $CurrentEnrollmentId }
    $ScheduledTaskObject = New-Object -ComObject Schedule.Service
    $ScheduledTaskObject.Connect()
    $EnterpriseMgmt = $ScheduledTaskObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
    $FolderIds = @()
    $FolderIds += $EnterpriseMgmt.GetFolders(0) | Select-Object -ExpandProperty Name
    if ( $FolderIds.Count -gt 0 ) {
        foreach ( $Id in $FolderIds ) {
            if ( $CurrentEnrollmentId -ne $Id -and $Id -match '\w{8}-\w{4}-\w{4}-\w{4}-\w{12}' ) { $EnrollmentIds += $Id }
        }
    }
    return $EnrollmentIds
}

function Clear-EnrollmentRegistry {
    <#
    .DESCRIPTION

    #>
    param ($EnrollmentGUIDs = (Get-EnrollmentIds))
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
                # Remove registry entries
                if (Test-Path -Path $Key) {
                    # Search for and remove keys with matching GUID
                    Write-Host "`t> $Key\$EnrollmentGUID. Removing..." -ForegroundColor Red
                    Get-ChildItem -Path $Key | Where-Object { $_.Name -match $EnrollmentGUID } | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
        }
    }
    Write-Host "`t`t> HKLM:\SOFTWARE\Microsoft\Enrollments Removing..." -ForegroundColor Red
    Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Enrollments" | Where-Object { $_.Name -notmatch 'Context|Status|ValidNodePaths'} | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    $CurrentEnrollmentId = $null; $CurrentEnrollmentId = Get-CurrentEnrollmentId
    if ( $null -ne $CurrentEnrollmentId ) { Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -Force }
}

function Get-EnrollmentTask {
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
        $EnrollmentTaskName = "Schedule created by enrollment client for automatically enrolling in MDM from AAD"
    )
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
    $Folders += $EnterpriseMgmt.GetFolders(0) | Select-Object -ExpandProperty Name
    if ( $Folders.Count -gt 0 ) {
        foreach ( $Folder in $Folders ) {
            Write-Host "`t> Tasks in \Microsoft\Windows\EnterpriseMgmt\$Folder Removing..."
            Get-ScheduledTask | Where-Object { $PSItem.Taskpath -match "\\Microsoft\\Windows\\EnterpriseMgmt\\$Folder\\*" } | Unregister-ScheduledTask -Confirm:$false
            $EnterpriseMgmt.DeleteFolder($Folder.Name,0)
        }
    }
}

function New-EnrollmentScheduledTask {
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
    $TaskName = 'Schedule created by enrollment client for automatically enrolling in MDM from AAD'
    Write-Host "`t> Task: 'Schedule created by enrollment client for automatically enrolling in MDM from AAD' Creating"
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
        Write-Host "`t> Task: 'Schedule created by enrollment client for automatically enrolling in MDM from AAD' Starting"
        Start-ScheduledTask -TaskName "\Microsoft\Windows\EnterpriseMgmt\$TaskName"
        $TaskInfo = $null; $TaskInfo = Get-ScheduledTaskInfo -TaskName "\Microsoft\Windows\EnterpriseMgmt\$TaskName" -ErrorAction SilentlyContinue
        if ( $null -eq $TaskInfo ) { $LastTaskResult = $null }
        else { $LastTaskResult = $TaskInfo.LastTaskResult.ToString("x") }
        Write-Host -Object "`t> MDM Scheduled Task : Last Task Result returned: $LastTaskResult" -ForegroundColor Red
    }
}

function Clear-IntuneCertificate {
    $IntuneCerts = @()
    $Certs = Get-ChildItem -Path Cert:\LocalMachine\My
    if ($Certs.Count -gt 0 ) {
        foreach ( $Cert in $Certs ) {
            if ( $Cert.Issuer -like '*Microsoft Intune MDM Device CA*' ) { $IntuneCerts += $Cert }
        }
    }
    Write-Host "`t> Cert: Issuer '*Microsoft Intune MDM Device CA*' Removing..."
    $IntuneCerts | Remove-Item -Confirm:$false
}

function Register-EnableIntuneEnrollTask {
    $Action = New-ScheduledTaskAction -Execute PowerShell.exe -Argument {-ExecutionPolicy Bypass -File C:\Temp\Enable-IntuneEnroll.ps1}
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Settings = New-ScheduledTaskSettingsSet -Priority 4
    $Principal = New-ScheduledTaskPrincipal -UserId (whoami) -LogonType Interactive
    $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
    Register-ScheduledTask -TaskName 'Enable-IntuneEnroll' -InputObject $Task
}

function UnRegister-EnableIntuneEnrollTask {
    Get-ScheduledTask -TaskName 'Enable-IntuneEnroll' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue     
}

function Get-EnableIntuneEnrollTask {
    $Task = Get-ScheduledTask -TaskName 'Enable-IntuneEnroll' -ErrorAction SilentlyContinue
    if ( $null -ne $Task ) { return $Task }
}

function UnRegister-CurrentEnrollment {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        $EnrollmentId
    )
    begin {
        $BeginScript = "`$EnrollmentId = '$EnrollmentId'"
        $UnRegScript = [scriptblock] {
            $pinvokeType = 'using System; using System.Runtime.InteropServices; using System.Text; public static class MdmUnregister { [DllImport("mdmregistration.dll")] public static extern int UnregisterDeviceWithManagement([MarshalAs(UnmanagedType.LPWStr)] string enrollmentId); }'
            Add-Type -Language CSharp -TypeDefinition $pinvokeType -ErrorAction SilentlyContinue
            $result = [MdmUnregister]::UnregisterDeviceWithManagement($enrollmentId);
            Write-Verbose ("UnregisterDeviceWithManagement returned 0x{0:x8}" -f $result)
            if ($result -eq 0) { return }
            Write-Error "UnregisterDeviceWithManagement API returned unexpected result: 0x{0:x8}" -f $result
            throw "Could not unregister"
        }
    }
    process {
        $runspace = [runspacefactory]::CreateRunspace()
        try {
            $runspace.ApartmentState = [System.Threading.ApartmentState]::MTA
            $runspace.Open()
            $pipeline = $runspace.CreatePipeline()
            $pipeline.Commands.AddScript($BeginScript)
            $pipeline.Commands.AddScript($UnRegScript)
            $pipeline.Invoke()
            if ($pipeline.HadErrors -eq $true) {
                Write-Error "One or more errors occurred"
                $pipeline.Error.ReadToEnd()
                $return = $false
            }
            else {
                $pipeline.Output.ReadToEnd()
                $return = $true
            }
        }
        catch {
            $return = $false
        }
        $runspace.Close()
        return $return
    }
}

function Test-AzureADJoin {
    if ( (C:\Windows\system32\dsregcmd.exe /status | Select-String " AzureADJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { return $true } else { return $false }
}

function Test-ADJoin {
    if ( (C:\Windows\system32\dsregcmd.exe /status | Select-String " DomainJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { return $true } else { return $false }
}

function Get-DeviceId {
    $DeviceId = $null
    $DeviceId = (C:\Windows\system32\dsregcmd.exe /status | Select-String " DeviceId : " | Select-Object -ExpandProperty Line).Trim().Replace("DeviceId :","").Trim()
    if ( ! [String]::IsNullOrEmpty($DeviceId) ) {
        return $DeviceId
    }
    else {
        #Write-Host -ForegroundColor Cyan -Object "'dsregcmd.exe /status' 명령을 통해 DeviceId 정보를 확인합니다.`nDeviceId 값이 없는 경우는 Entra Joined 또는 Entra Hybrid Joined 환경으로 정상적으로 Device 정보를 업데이트하지 못해서 정보가 수집되지 않는 경우입니다.`nEntra Joined 또는 Entra Hybrid Joined 환경으로 Device 정보를 업데이트하고 Registration되게 수행이 필요합니다.`n필요한 과정은 아래와 같습니다:`n`n`t- dsregcmd /leave`n`t- 컴퓨터 Restart`n`t- 'psexec -s C:\Windows\System32\dsregcmd.exe /join /debug' 명령으로 다시 join 시도합니다. (system 계정으로 실행합니다.)`n`t- 컴퓨터 Restart`n"
        return $null
    }
}

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

#endregion Define Functions


Start-Transcript C:\Temp\Intune\Logs\RunTranscript.txt -Force

New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 0 -Message 'START'

New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 1 -Message "STEP : SaveTools : Downloaded the Diag & Execute Tool : $Path\$FolderName"
Save-Tools

try { $IsADJoined = [NetInterop]::IsADJoined() } catch { $IsADJoined = Test-ADJoin }
try { $IsAADJoined = [NetInterop]::IsAADJoined() } catch { $IsAADJoined = Test-AzureADJoin }
try { $IsDeviceRegisteredWithManagement = [MdmInterop]::IsDeviceRegisteredWithManagement() } catch { $IsDeviceRegisteredWithManagement = if ( (Get-DeviceInfo).ManagementType -eq "MDM" ) {$true} else {$false} }

if ( $IsADJoined ) {
    if ( $IsAADJoined ) {
        if ( ! $IsDeviceRegisteredWithManagement ) {
            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 10 -Message 'TASK : IntuneEnrollment'

            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 11 -Message 'STEP : IntuneEnrollment : UnRegister-CurrentEnrollment'
            $CurrentEnrollmentId = $null; $CurrentEnrollmentId = Get-CurrentEnrollmentId
            if ( ! [String]::IsNullOrEmpty($CurrentEnrollmentId) ) { UnRegister-CurrentEnrollment -EnrollmentId $CurrentEnrollmentId }

            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 12 -Message 'STEP : IntuneEnrollment : Clear-EnrollmentRegistry'
            Clear-EnrollmentRegistry

            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 13 -Message 'STEP : IntuneEnrollment : Clear-EnrollmentTasks'
            Clear-EnrollmentTasks
            
            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 14 -Message 'STEP : IntuneEnrollment : Clear-IntuneCertificate'
            Clear-IntuneCertificate

            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 15 -Message "STEP : IntuneEnrollment : Set-EnrollmentRegistry"
            Set-EnrollmentRegistry
        
            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 16 -Message "STEP : IntuneEnrollment : New-EnrollmentScheduledTask"
            New-EnrollmentScheduledTask -Start

            Invoke-AutoEnrollMDM -MaxCount 30           
        }
        else {
            UnRegister-EnableIntuneEnrollTask
            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 100 -Message 'END'
        }
    }
    else {
        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 2 -Message 'TASK:AzureADJoin'

        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 3 -Message 'STATUS:DOMAINJOINED'

        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 4 -Message "STEP : AzureADJoin : Set-EnrollmentRegistry"
        Set-EnrollmentRegistry        
        if ( (Join-AzureAD) ) {
            New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 5 -Message 'STATUS:AZUREADJOINED'
            New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 6 -Message 'STEP : AzureADJoin : Register-EnableIntuneEnrollTask'
            Register-EnableIntuneEnrollTask
            $IsRestart = Invoke-PopupWindow -Title "Intune Enrollment Task" -Description "Intune Enrollment Task 수행을 위하여 Computer Restart가 필요합니다.`n모든 열려있는 문서는 저장하고 닫아주세요.`n지금 재시작할까요?" -IconType Question -Style YesNo
            if ( $IsRestart -eq 'Yes' ) { Restart-Computer }
        }
    }
}

Stop-Transcript

