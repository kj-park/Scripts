function Clear-EnrollmentRegistry {
    <#
    .DESCRIPTION

    #>
    param ($EnrollmentGUIDs = (Get-EnrollmentIds))
    $RegistryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments"
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status"
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked"
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled"
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions"
    )
    if ( $null -ne $EnrollmentGUIDs ) {
        foreach ( $EnrollmentGUID in $EnrollmentGUIDs ) {
            foreach ($Key in $RegistryKeys) {
                # Remove registry entries
                if (Test-Path -Path $Key) {
                    # Search for and remove keys with matching GUID
                    Write-Host "`t> $Key\$EnrollmentGUID. Removing..." -ForegroundColor Red
                    Get-ChildItem -Path $Key | Where-Object { $_.Name -match $EnrollmentGUID } | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
        }
    }
    Write-Host "`t`t> HKLM:\SOFTWARE\Microsoft\Enrollments Removing..." -ForegroundColor Red
    Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Enrollments" | Where-Object { $_.Name -notmatch 'Context|Status|ValidNodePaths'} | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    $CurrentEnrollmentId = $null; $CurrentEnrollmentId = Get-CurrentEnrollmentId
    if ( $null -ne $CurrentEnrollmentId ) { Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -Force }
}