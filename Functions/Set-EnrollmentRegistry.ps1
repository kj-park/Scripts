function Set-EnrollmentRegistry {
    <# TODO: $TenantId = "2ff1913c-2506-4fc1-98e5-2e18c7333baa"; $TenantName = "hdom365.onmicrosoft.com" #>
    param (
        $TenantId = $TenantId,
        $TenantName = $TenantName
    )
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