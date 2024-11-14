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