
$unregScript = [scriptblock] {
}

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

$unregScript = [scriptblock] {
    $pinvokeType = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class MdmUnregister
{
    [DllImport("mdmregistration.dll")]
    public static extern int UnregisterDeviceWithManagement([MarshalAs(UnmanagedType.LPWStr)] string enrollmentId);
}
"@

    Add-Type -Language CSharp -TypeDefinition $pinvokeType -ErrorAction SilentlyContinue
    $result = [MdmUnregister]::UnregisterDeviceWithManagement($enrollmentId);
    Write-Verbose ("UnregisterDeviceWithManagement returned 0x{0:x8}" -f $result)

    if ($result -eq 0) {
        return
    }

    # See: https://docs.microsoft.com/en-us/windows/win32/mdmreg/mdm-registration-constants for reference
    Write-Error "UnregisterDeviceWithManagement API returned unexpected result: 0x{0:x8}" -f $result
    throw "Could not unregister"
}

$regScript = [scriptblock] {
    $pinvokeType = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class MdmRegister
{
    [DllImport("mdmregistration.dll")]
    public static extern int RegisterDeviceWithManagementUsingAADDeviceCredentials();

    [DllImport("mdmregistration.dll")]
    public static extern int RegisterDeviceWithManagementUsingAADCredentials(IntPtr token);
}
"@

    Add-Type -Language CSharp -TypeDefinition $pinvokeType -ErrorAction SilentlyContinue
    $result = [MdmRegister]::RegisterDeviceWithManagementUsingAADDeviceCredentials()
    Write-Verbose ("RegisterDeviceWithManagementUsingAADDeviceCredentials returned 0x{0:x8}" -f $result)
    if ($result -eq 0) {
        Write-Output $true
        return
    }

    # See: https://docs.microsoft.com/en-us/windows/win32/mdmreg/mdm-registration-constants for reference
    Write-Warning ("RegisterDeviceWithManagementUsingAADDeviceCredentials API returned unexpected result: 0x{0:x8}. Will attempt fallback API." -f $result)

    $result = [MdmRegister]::RegisterDeviceWithManagementUsingAADCredentials([System.IntPtr]::Zero)
    if ($result -eq 0) {
        Write-Output $true
        return
    }
    else {
        Write-Warning ("Fallback: RegisterDeviceWithManagementUsingAADCredentials API returned unexpected result: 0x{0:x8}" -f $result)
    }

    throw "Could not re-register"
}

function PerformDJ() {
    Write-Verbose "Perform DJ++: dsregcmd.exe"
    dsregcmd.exe /join

    $result = $LASTEXITCODE
    Write-Verbose ("dsregcmd.exe returned 0x{0:x8}" -f $result)

    if ($result -ne 0) {
        Write-Error ("dsregcmd.exe returned unexpected result: 0x{0:x8}" -f $result)
        return $false
    }

    return $true
}

function IsReadyToRemediate() {
    $ReadyToRemediate = $true

    $isAAdJoined = [NetInterop]::IsAADJoined()
    $isAdJoined = [NetInterop]::IsADJoined()

    #Workgroup only
    if (($isAAdJoined -eq $false) -and ($isAdJoined -eq $false)) {
        #Report remediation attempt failed.
        Write-Error "Remediation attempt failed, device is neither AAD joined nor AD joined."
        $ReadyToRemediate = $false
    }

    #AAD joined only
    if (($isAAdJoined -eq $true) -and ($isAdJoined -eq $false)) {
        #Report remediation attempt failed.
        Write-Verbose "Device is AAD joined only. Ready to remediate."
        $ReadyToRemediate = $true
    }

    #Domain joined only
    if (($isAAdJoined -eq $false) -and ($isAdJoined -eq $true)) {
        #Try to perform DJ++
        $exeResult = PerformDJ

        # Check result
        if ($exeResult -eq $true) {
            $isAAdJoined = [NetInterop]::IsAADJoined()
            $isAdJoined = [NetInterop]::IsADJoined()

            if ($isAAdJoined -eq $false) {
                Write-Error "Remediation attempt failed, perform DJ++ success but device is still not AAD joined."
                $ReadyToRemediate = $false
            }

            if ($isAdJoined -eq $false) {
                Write-Error "Remediation attempt failed, perform DJ++ success but device is still not AD joined."
                $ReadyToRemediate = $false
            }
        }
        else {
            Write-Error "Remediation attempt failed, perform DJ++ failed."
            $ReadyToRemediate = $false
        }
    }

    #DJ++
    if (($isAAdJoined -eq $true) -and ($isAdJoined -eq $true)) {
        Write-Verbose "Device is DJ++, ready to remediate."
        $ReadyToRemediate = $true
    }

    return $ReadyToRemediate
}

function GetGuidAndThumbprintPairFromRegistry {
    $guidAndThumbPrintPair = @{}

    try {
        # Is there mutiple account?
        $account = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts

        foreach ($_ in $account) {
            $p = get-item -path ($_.PSPath + '\Protected')
            if ($p.GetValue("ServerId") -ne "MS DM Server") {
                continue
            }

            try {
                $guidAndThumbPrintPair.Add($_.PSChildName, $_.GetValue("SslClientCertReference"))
            }
            catch {
                $guidAndThumbPrintPair.Add($_.PSChildName, $null)
            }
        }

        return $guidAndThumbPrintPair
    }
    catch {
        Write-Error "Retrieve registry 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts' failed."
        return $null
    }
}

function GetGuidAndSubjectPairFromRegistry {
    $guidAndSubjectPair = @{}

    try {
        # Is there mutiple account?
        $account = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts

        foreach ($_ in $account) {
            $p = get-item -path ($_.PSPath + '\Protected')
            if ($p.GetValue("ServerId") -ne "MS DM Server") {
                continue
            }

            try {
                $guidAndSubjectPair.Add($_.PSChildName, $p.GetValue("SslClientCertSearchCriteria"))
            }
            catch {
                $guidAndSubjectPair.Add($_.PSChildName, $null)
            }
        }

        return $guidAndSubjectPair
    }
    catch {
        Write-Error "Retrieve registry 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts' failed."
        return $null
    }
}

function IsCertInstalled($pThumbprint) {
    try {
        Write-Verbose "Searching for certificate with thumbprint $pThumbprint"
        $installedCert = Get-ChildItem -Path "Cert:LocalMachine\MY" | Where-Object { $_.Thumbprint -eq $pThumbprint }

        if ($installedCert -ne $null) {
            Write-Verbose "Certificate $pThumbprint was found"
            return $true
        }
        else {
            Write-Verbose "Certificate $pThumbprint was NOT found"
            return $false
        }
    }
    catch {
        Write-Error "Retrieve cert store 'Cert:LocalMachine\MY' failed."
        return $false
    }
}

function IsCertInstalledSubject($pSubject) {
    try {
        Write-Verbose "Searching for certificate with Subject $pSubject"
        $installedCert = Get-ChildItem -Path "Cert:LocalMachine\MY" | Where-Object { $_.Subject -eq $pSubject }

        if ($installedCert -ne $null) {
            Write-Verbose "Certificate $pSubject was found"
            return $true
        }
        else {
            Write-Verbose "Certificate $pSubject was NOT found"
            return $false
        }
    }
    catch {
        Write-Error "Retrieve cert store 'Cert:LocalMachine\MY' failed."
        return $false
    }
}

function GetGuidAndCertConfigurationResult {
    # Get guid and thumbprint pairs from registry
    $guidAndThumbPrintPairs = GetGuidAndThumbprintPairFromRegistry
    $guidAndSubjectPairs = GetGuidAndSubjectPairFromRegistry

    if ($guidAndThumbPrintPairs -ne $null -and $guidAndThumbPrintPairs.Count -gt 0) {
        $thumbprintPrefix = "MY;System;"
        $guidAndThumbPrintAndCertInstalled = @{}

        foreach ($_ in $guidAndThumbPrintPairs.GetEnumerator()) {
            # If the thumbprint is null for the enrollment Id, try fallback to subject, otherwise say missing.
            if ($_.Value -eq $null) {

                $subjectCriteriaPrefix = "Subject=CN%3d"
                $subjectCriteriaSuffix = "&Stores=MY%5CSystem"
                $isFallback = $false
                foreach ($_sb in $guidAndSubjectPairs.GetEnumerator()) {
                    if ($_sb.Name -eq $_.Name) {
                        if (($_sb.Value -ne $null) -and ($_sb.Value.StartsWith($subjectCriteriaPrefix) -eq $true)) {

                            if ($_sb.Value.EndsWith($subjectCriteriaSuffix) -eq $true) {

                                $subject = $_sb.Value.Replace($subjectCriteriaSuffix, "")
                                $subject = $subject.Replace($subjectCriteriaPrefix, "CN=")

                                $isFallback = IsCertInstalledSubject $subject

                                if ($isFallback -eq $true) {
                                    $guidAndThumbPrintAndCertInstalled.Add($_.Name, ($_sb.Value, $true))
                                }
                            }
                            else {
                                #If is not MY;SYSTEM;, then we dont care, say not missing.
                                $isFallback = $true
                                $guidAndThumbPrintAndCertInstalled.Add($_.Name, ($_sb.Value, $true))
                            }
                        }

                        break
                    }
                }

                if ($isFallback -eq $false) {
                    $guidAndThumbPrintAndCertInstalled.Add($_.Name, ("", $false))
                }

                continue
            }

            # If the thumbprint is MY;SYSTEM;, check if cert is installed.
            if ($_.Value.StartsWith($thumbprintPrefix) -eq $true) {
                $thumbprint = $_.Value.Replace($thumbprintPrefix, "")
                $certInstalled = IsCertInstalled $thumbprint
                $guidAndThumbPrintAndCertInstalled.Add($_.Key, ($_.Value, $certInstalled))
            }
            else {
                #If is not MY;SYSTEM;, then we dont care, say not missing.
                $guidAndThumbPrintAndCertInstalled.Add($_.Key, ($_.Value, $true))
            }
        }

        return $guidAndThumbPrintAndCertInstalled
    }
    else {
        Write-Verbose "Failed to get enrollment id and thrumbpoint from registry."
    }

    return $null
}

function IsEnrollmentIdInRegistry($enrollmentId) {
    $result = Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$enrollmentId"
    return $result
}

function IsCertInstalledForEnrollmentId($enrollmentId) {
    $result = $false
    Write-Verbose "Check if the cert is installed for enrollment Id: $enrollmentId"
    $testResult = Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$enrollmentId"

    if ($testResult -eq $true) {
        try {
            $account = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$enrollmentId"
            $thumbprint = $account.GetValue("SslClientCertReference")
            $thumbprintPrefix = "MY;System;"

            if ($thumbprint -ne $null) {
                # If the thumbprint is MY;SYSTEM;, check if cert is installed.
                if ($thumbprint.StartsWith($thumbprintPrefix) -eq $true) {
                    $thumbprint = $thumbprint.Replace($thumbprintPrefix, "")
                    $result = IsCertInstalled $thumbprint

                    if ($result -eq $false) {
                        Write-Verbose "$thumbprint cert is not installed for $enrollmentId"
                    }
                    else {
                        Write-Verbose "$thumbprint cert is installed for $enrollmentId."
                    }
                }
                else {
                    Write-Verbose "$thumbprint is not MY;SYSTEM cert for $enrollmentId in registry, just return true"
                    $result = $true
                }
            }
            else {
                Write-Verbose "Thumbprint is null for $enrollmentId in registry."

                #Try to fallback to SslClientCertSearchCriteria
                Write-Verbose "Try to fallback to SslClientCertSearchCriteria."
                $testResult = Test-Path -Path ("HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$enrollmentId" + "\Protected")
                if ($testResult -eq $true) {
                    $protected = Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$enrollmentId" + "\Protected")
                    $subjectCriteria = $protected.GetValue("SslClientCertSearchCriteria")

                    if ($subjectCriteria -ne $null) {
                        $subjectCriteriaPrefix = "Subject=CN%3d"
                        $subjectCriteriaSuffix = "&Stores=MY%5CSystem"

                        # If the subject criteria ends with &Stores=MY%5CSystem
                        if ($subjectCriteria.EndsWith($subjectCriteriaSuffix) -eq $true) {
                            # If the subject criteria starts with Subject=CN%3d, check if cert is installed.
                            if ($subjectCriteria.StartsWith($subjectCriteriaPrefix) -eq $true) {
                                $subject = $subjectCriteria.Replace($subjectCriteriaSuffix, "")
                                $subject = $subject.Replace($subjectCriteriaPrefix, "CN=")

                                $result = IsCertInstalledSubject $subject

                                if ($result -eq $false) {
                                    Write-Verbose "$subjectCriteria cert is not installed for $enrollmentId"
                                }
                                else {
                                    Write-Verbose "$subjectCriteria cert is installed for $enrollmentId."
                                }
                            }
                            else {
                                Write-Verbose "$subjectCriteria is not search by subject."
                                $result = $false
                            }
                        }
                        else {
                            Write-Verbose "$subjectCriteria is not MY;SYSTEM cert for $enrollmentId in registry, just return true"
                            $result = $true
                        }
                    }
                    else {
                        Write-Verbose "SslClientCertSearchCriteria was not found for $enrollmentId in registry."
                        $result = $false
                    }
                }
                else {
                    Write-Verbose "The fallback entry 'Protected' key was not found in registry."
                    $result = $false
                }
            }
        }
        catch [System.Exception] {
            Write-Error "Failed to get thumbprint for $enrollmentId from registry. Error message: $($_.Exception.Message)"
            $result = $false
        }
    }
    else {
        Write-Verbose "Enrollment Id was not found in registry."
    }

    return $result
}

function CheckEnrollResult {
    Write-Verbose "Check enroll result..."

    # Get cert status for all enrollment Ids by validate registry and cert store
    $guidAndCertConfigurationResult = GetGuidAndCertConfigurationResult

    if ($guidAndCertConfigurationResult -ne $null) {
        $thumbprintPrefix = "MY;System;"
        $subjectCriteriaSuffix = "&Stores=MY%5CSystem"
        $hasMYSystem = $false

        # Check cert status for each enrollment Id
        foreach ($_ in $guidAndCertConfigurationResult.GetEnumerator()) {
            $enrollmentId = $_.Name
            $certThumbprint = $_.Value[0]
            $certConfigurationResult = $_.Value[1]

            # Check if the cert is configured/installed correctly for the current enrollment Id
            if ($certConfigurationResult -eq $false) {
                Write-Verbose "Cert '$certThumbprint' for enrollment Id $enrollmentId is not installed."
                return $false
            }
            else {
                # Check if the cert thumbprint starts with MY;System;
                if ($certThumbprint.StartsWith($thumbprintPrefix) -eq $true -or $certThumbprint.EndsWith($subjectCriteriaSuffix)) {
                    $hasMYSystem = $true
                }

                Write-Verbose "Cert $certThumbprint for enrollment Id $enrollmentId is installed/configured correctly."
            }
        }

        if ($hasMYSystem -eq $true) {
            Write-Verbose "All certs are configured correctly."
            return $true
        }
        else {
            Write-Verbose "All existing certs are configured correctly, but still not found MY;System; cert after re-enrollment."
            return $false
        }
    }
    else {
        Write-Warning "Enrollment Id/Certificates are Not Found."
        return $false
    }
}

# Check if it's MDM enrolled device
$isMgmt = [MdmInterop]::IsDeviceRegisteredWithManagement()
if ($isMgmt -eq $false) {

    # Get cert status for all enrollment Ids by validate registry and cert store
    $guidAndCertConfigurationResult = GetGuidAndCertConfigurationResult

    if ($guidAndCertConfigurationResult -ne $null) {

        # Check cert status for each enrollment Id
        foreach ($_ in $guidAndCertConfigurationResult.GetEnumerator()) { 
            $enrollmentId = $_.Name
            $certThumbprint = $_.Value[0]
            $certConfigurationResult = $_.Value[1]


            $readyToRemediate = IsReadyToRemediate

            if ($readyToRemediate -eq $true) {
                Write-Host "Call unregister device for enrollment Id: $enrollmentId"

                # This must run in MTA and PowerShell is STA by default. We will force it to run in MTA by creating a separate runspace.
                $runspace = [runspacefactory]::CreateRunspace()
                try {
                    $runspace.ApartmentState = [System.Threading.ApartmentState]::MTA
                    $runspace.Open()
                    $pipeline = $runspace.CreatePipeline()
                    $pipeline.Commands.AddScript("`$enrollmentId = '$enrollmentId'")
                    $pipeline.Commands.AddScript($unregScript)

                    $pipeline.Invoke()

                    if ($pipeline.HadErrors -eq $true) {
                        Write-Error "One or more errors occurred"
                        $pipeline.Error.ReadToEnd()
                        $callUnregister = $false
                    }
                    else {
                        $pipeline.Output.ReadToEnd()
                        $callUnregister = $true
                    }
                }
                catch {
                    $callRegister = $false
                }
                finally {
                    $runspace.Close()
                }

                if ($callUnregister -eq $true) {
                    $remediationExecuted = $true
                    Write-Host "Unregister completed, start to register MDM Using AAD device credentials."

                    # This must run in MTA and PowerShell is STA by default. We will force it to run in MTA by creating a separate runspace.
                    $runspace = [runspacefactory]::CreateRunspace()
                    try {
                        $runspace.ApartmentState = [System.Threading.ApartmentState]::MTA
                        $runspace.Open()
                        $pipeline = $runspace.CreatePipeline()
                        $pipeline.Commands.AddScript($regScript)
                        $pipeline.Invoke()
                        if ($pipeline.HadErrors -eq $true) {
                            Write-Error "One or more errors occurred"
                            $pipeline.Error.ReadToEnd()
                            $callRegister = $false
                        }
                        else {
                            $pipeline.Output.ReadToEnd()
                            $callRegister = $true
                        }
                    }
                    catch {
                        $callRegister = $false
                    }
                    finally {
                        $runspace.Close()
                    }

                    if ($callRegister -eq $true) {
                        Write-Host "Register MDM completed."
                    }
                    else {
                        Write-Error "Call register MDM failed, leave the work to ccmexec to do on its own schedule."
                    }
                }
                else {
                    Write-Error "Call unregister failed for enrollment Id: $enrollmentId"
                }
            }
            else {
                Write-Error "Device is not ready for remediate."
            }
        }
    }
}