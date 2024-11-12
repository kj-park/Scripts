function Get-DeviceId {
    <#
    .DESCRIPTION
    "dsregcmd.exe /status" 명령을 통해 DeviceId 정보를 확인합니다.
    DeviceId 값이 없는 경우는 Entra Joined 또는 Entra Hybrid Joined 환경으로 정상적으로 Device 정보를 업데이트하지 못해서 정보가 수집되지 않는 경우입니다.
    Entra Joined 또는 Entra Hybrid Joined 환경으로 Device 정보를 업데이트하고 Registration되게 수행이 필요합니다.
    필요한 과정은 아래와 같습니다:

        - dsregcmd /leave
        - 컴퓨터 Restart
        - "psexec -s C:\Windows\System32\dsregcmd.exe /join /debug" 명령으로 다시 join 시도합니다. (system 계정으로 실행합니다.)
        - 컴퓨터 Restart
    #>
    $DeviceId = $null
    $DeviceId = (C:\Windows\system32\dsregcmd.exe /status | Select-String " DeviceId : " | Select-Object -ExpandProperty Line).Trim().Replace("DeviceId :","").Trim()
    if ( ! [String]::IsNullOrEmpty($DeviceId) ) {
        return $DeviceId
    }
    else {
        Write-Host -ForegroundColor Cyan -Object "'dsregcmd.exe /status' 명령을 통해 DeviceId 정보를 확인합니다.`nDeviceId 값이 없는 경우는 Entra Joined 또는 Entra Hybrid Joined 환경으로 정상적으로 Device 정보를 업데이트하지 못해서 정보가 수집되지 않는 경우입니다.`nEntra Joined 또는 Entra Hybrid Joined 환경으로 Device 정보를 업데이트하고 Registration되게 수행이 필요합니다.`n필요한 과정은 아래와 같습니다:`n`n`t- dsregcmd /leave`n`t- 컴퓨터 Restart`n`t- 'psexec -s C:\Windows\System32\dsregcmd.exe /join /debug' 명령으로 다시 join 시도합니다. (system 계정으로 실행합니다.)`n`t- 컴퓨터 Restart`n"
        return $null
    }
}