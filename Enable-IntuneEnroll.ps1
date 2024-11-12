
<#

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

#>


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
        $IntType = switch ($Type) { 'Critical' {16}; 'Question' {32}; 'Exclamation' {48}; 'Information'{64} }

        $Return = $null
        $WShell = New-Object -ComObject WScript.Shell
        $SecondsToWait = 0
    }
    process {
        $Return = $WShell.Popup($Description, $SecondsToWait, $Title, $IntStyle + $IntType)
    }
    end {
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
    New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 0 -Message "STEP : SaveTools : Downloaded the Diag & Execute Tool : $Path\$FolderName"
    New-Item -Path $Path -Name $FolderName -ItemType Directory -Force | Out-Null
    New-Item -Path "$Path\$FolderName" -Name Logs -ItemType Directory -Force | Out-Null
    New-Item -Path "$Path\$FolderName" -Name PSTools -ItemType Directory -Force | Out-Null
    if ( !(Test-Path -Path "$Path\$FolderName\PSTools.zip") ) {
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile "$Path\$FolderName\PSTools.zip"
    }
    Expand-Archive -Path "$Path\$FolderName\PSTools.zip" -DestinationPath "$Path\$FolderName\PSTools" -Force
}

function Set-EnrollmentRegistry {
    <# TODO: $TenantId = "2ff1913c-2506-4fc1-98e5-2e18c7333baa"; $TenantName = "hdom365.onmicrosoft.com" #>
    param (
        $TenantId = $TenantId,
        $TenantName = $TenantName
    )
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 7 -Message "STEP : IntuneEnrollment : Set-RegistryForEnrollment"

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
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 3 -Message "STEP : IntuneEnrollment : Clear-EnrollmentRegistry"
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
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 5 -Message "STEP : IntuneEnrollment : Clear-EnrollmentTasks"
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

function Clear-IntuneCertificate {
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 6 -Message "STEP : IntuneEnrollment : Clear-IntuneCertificate"
    $IntuneCerts = @()
    $Certs = Get-ChildItem -Path Cert:\LocalMachine\My
    if ($Certs.Count -gt 0 ) {
        foreach ( $Cert in $Certs ) {
            if ( $Cert.Issuer -like '*Microsoft Intune MDM Device CA*' ) { $IntuneCerts += $Cert }
        }
    }
    $IntuneCerts | Remove-Item -Confirm:$false
}

function Register-EnableIntuneEnroll {
    $Action = New-ScheduledTaskAction -Execute PowerShell.exe -Argument {-ExecutionPolicy Bypass -File C:\Temp\Enable-IntuneEnroll.ps1}
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Settings = New-ScheduledTaskSettingsSet
    $Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM'
    $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
    Register-ScheduledTask -TaskName 'Enable-IntuneEnroll' -InputObject $Task

    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 98 -Message 'STATUS:Register-EnableIntuneEnroll'
}

function UnRegister-EnableIntuneEnroll {
    Get-ScheduledTask -TaskName 'Enable-IntuneEnroll' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue 
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 99 -Message 'STATUS:UnRegister-EnableIntuneEnroll'
}

function Get-EnableIntuneEnroll {
    $Task = Get-ScheduledTask -TaskName 'Enable-IntuneEnroll' -ErrorAction SilentlyContinue
    if ( $null -ne $Task ) { return $Task }
}

#endregion Define Functions

New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 0 -Message 'IntuneEnrollment : START'

Save-Tools
$IsADJoined = [NetInterop]::IsADJoined()
$IsAADJoined = [NetInterop]::IsAADJoined()
$IsDeviceRegisteredWithManagement = [MdmInterop]::IsDeviceRegisteredWithManagement()

if ( $IsADJoined ) {
    if ( $IsAADJoined ) {
        if ( ! $IsDeviceRegisteredWithManagement ) {

            Clear-EnrollmentRegistry
            
            Clear-EnrollmentTasks
            
            Clear-IntuneCertificate

            Set-EnrollmentRegistry
        
            New-EnrollmentScheduledTask -Start        

        }
        UnRegister-ResetIntuneEnroll
        New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 100 -Message 'IntuneEnrollment : END'
    }
    else {
        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 1 -Message 'TASK:AzureADJoin'
        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 2 -Message 'STATUS:DOMAINJOINED'
        Set-EnrollmentRegistry
        if ( (Join-AzureAD) ) {
            New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 6 -Message 'STATUS:AZUREADJOINED'
            Register-ResetIntuneEnroll
        }
    }
}

