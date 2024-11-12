

<#
# System 계정으로 실행:

    C:\Temp\Intune\PSTools\PsExec64.exe -i -s powershell.exe
    C:\Temp\Intune\PSTools\PsExec64.exe -i -s powershell_ise.exe

    C:\Temp\Intune\PSTools\PsExec64.exe -accepteula -i -s powershell.exe -ExecutionPolicy Bypass -File C:\Temp\Enable-SharedPC.ps1

#>


#region Script for Config Shared PC


$namespaceName = "root\cimv2\mdm\dmmap"
$parentID="./Vendor/MSFT/Policy/Config"
$className = "MDM_SharedPC"
$cimObject = Get-CimInstance -Namespace $namespaceName -ClassName $className


<# EnableSharedPCMode

    $false (Default)
    $true
#>
$cimObject.EnableSharedPCMode = $true


<# AccountModel

    0 (Default) : Only guest accounts are allowed.
    1 : Only domain-joined accounts are allowed.
    2 : Domain-joined and guest accounts are allowed.
#>
$cimObject.AccountModel = 2


<# DeletionPolicy

    0 : Delete immediately.
    1 (Default) : Delete at disk space threshold.
    2 : Delete at disk space threshold and inactive threshold.
#>
$cimObject.DeletionPolicy = 2


<# DiskLevelCaching

Stop deleting accounts when available disk space reaches this threshold,
given as percent of total disk capacity.
#>
$cimObject.DiskLevelCaching = 50


<# DiskLevelDeletion

Accounts will start being deleted when available disk space falls below this threshold,
given as percent of total disk capacity.
#>
$cimObject.DiskLevelDeletion = 25


<# EnableAccountManager

Enable the account manager for shared PC mode.

    $false (Default)
    $true
#>
$cimObject.EnableAccountManager = $true


<# InactiveThreshold

Accounts will start being deleted when they haven't been logged-on during the specified period,
given as number of days.

    Range: [0-4294967295]
    30 (Default)
#>
$cimObject.InactiveThreshold = 30


<# InactiveThreshold

Daily start time of maintenance hour. Given in minutes from midnight.
Default is 0 (12am)

    Example: 1am > 60, 2am > 120
#>
$cimObject.MaintenanceStartTime = 720


<# RestrictLocalStorage

Restricts the user from using local storage.

    $false (Default)
    $true
#>
$cimObject.RestrictLocalStorage = $false


<# SignInOnResume

Require signing in on waking up from sleep.

    $false (Default)
    $true
#>
$cimObject.SignInOnResume = $true


<# SleepTimeout

The amount of time before the PC sleeps,
giving in seconds. 0 means the PC never sleeps.
Default is 5 minutes (300).
#>
$cimObject.SleepTimeout = 0


Set-CimInstance -CimInstance $cimObject


#endregion Script for Config Shared PC

