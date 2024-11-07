

<#
# System 계정으로 실행:

    C:\Temp\Intune\PSTools\PsExec64.exe -accepteula -i -s powershell.exe
    C:\Temp\Intune\PSTools\PsExec64.exe -accepteula -i -s powershell_ise.exe

    C:\Temp\Intune\PSTools\PsExec64.exe -accepteula -i -s powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Disable-SharedPC.ps1

#>
Set-ExecutionPolicy -ExecutionPolicy Bypass

#region Script for disabling Shared PC


    $namespaceName = "root\cimv2\mdm\dmmap"
    $parentID="./Vendor/MSFT/Policy/Config"
    $className = "MDM_SharedPC"
    $cimObject = Get-CimInstance -Namespace $namespaceName -ClassName $className


    $cimObject.EnableSharedPCMode = $False


    Set-CimInstance -CimInstance $cimObject

#endregion Script for disabling Shared PC

