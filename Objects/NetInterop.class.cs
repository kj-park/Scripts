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
            else if (hr != 0)
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
            if (pPtr != IntPtr.Zero)
            {
                NetFreeAadJoinInformation(pPtr);
            }
        }

        return result;
    }
}