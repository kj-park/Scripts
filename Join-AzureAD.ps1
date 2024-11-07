
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

    New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 1 -Message "STEP : Set Registries for AzureAD Join & Intune Enrollment"

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

    $AzureAdJoined  = if ( (C:\Windows\system32\dsregcmd.exe /status | Select-String "AzureAdJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { $true } else { $false }

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

#endregion

New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 99 -Message "STEP : AzureADJoin : START"

Save-Tools

Set-RegistryForEnrollment

Join-AzureAD 

New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 100 -Message "STEP : AzureADJoin : END"
