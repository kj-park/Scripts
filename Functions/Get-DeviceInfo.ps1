function Get-DeviceInfo {
    <#
    .DESCRIPTION
    Microsoft Graph API 기반 Web Request로 Entra Directory에서 Device의 아래 속성들을 확인합니다:
        - DisplayName
        - RegistrationDateTime
        - TrustType
        - ManagementType

    이 function이 정상적으로 동작하기 위해서는 Entra Id로 App Registration이 필요하며, Client Secret을 등록해야 하며, Microsoft Graph API의 다음 Application Permission들이 있어야 합니다:
        - Device.Read.All
        - DeviceManagementManagedDevices.Read.All
        - Directory.Read.All

    또한, function 정의에서 아래의 변수에 대하여 수정해야 합니다:
        - ClientId
        - ClientSecret
        - TenantId

    .EXAMPLE
        Get-DeviceInfo -DeviceId 5114c21c-cb15-4bbd-8991-7711512ac556
    #>
    param (
        $DeviceId = (Get-DeviceId),
        $ClientId = $ClientId,
        $ClientSecret = $ClientSecret,
        $TenantId = $TenantId
    )
    begin {
        $Body = @{
            client_id = $ClientId
            scope = "https://graph.microsoft.com/.default";
            client_secret = $ClientSecret
            grant_type = "client_credentials"
        }
        try {
            $TokenRequest = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $Body -UseBasicParsing -ErrorAction SilentlyContinue
            $Token = $TokenRequest.access_token
            $authHeader = @{"Authorization"="Bearer $token"}
        }
        catch { $authHeader = $null }
    }
    process {
        if ( !([String]::IsNullOrEmpty($DeviceId)) -and $null -ne $authHeader ){
            $QueryUrl = "https://graph.microsoft.com/v1.0/Devices(deviceId='{$DeviceId}')"
            $Response = $null
            try {
                $Response = Invoke-RestMethod -Method Get -Uri $QueryUrl -Headers $authHeader -ErrorAction SilentlyContinue
                $DeviceInfo = [PSCustomObject]@{
                    DisplayName          = $Response.displayName
                    RegistrationDateTime = [Convert]::ToDateTime($Response.registrationDateTime)
                    TrustType            = $Response.trustType
                    ManagementType       = $Response.managementType
                }
                return $DeviceInfo
            }
            catch {
                return $null
            }
        }
    }
}