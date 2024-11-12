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

    private enum DEVICEREGISTRATIONTYPE
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