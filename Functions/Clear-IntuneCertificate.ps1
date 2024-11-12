function Clear-IntuneCertificate {
    $IntuneCerts = @()
    $Certs = Get-ChildItem -Path Cert:\LocalMachine\My
    if ($Certs.Count -gt 0 ) {
        foreach ( $Cert in $Certs ) {
            if ( $Cert.Issuer -like '*Microsoft Intune MDM Device CA*' ) { $IntuneCerts += $Cert }
        }
    }
    Write-Host "`t> Cert: Issuer '*Microsoft Intune MDM Device CA*' Removing..."
    $IntuneCerts | Remove-Item -Confirm:$false
}