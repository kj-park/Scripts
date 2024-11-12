function Clear-IntuneCertificate {
    New-IntuneEventLog -Source IntuneEnrollment -EntryType Information -EventId 6 -Message "STEP : IntuneEnrollment : Clear-IntuneCertificate"
    $IntuneCerts = @()
    $Certs = Get-ChildItem -Path Cert:\LocalMachine\My
    if ($Certs.Count -gt 0 ) {
        foreach ( $Cert in $Certs ) {
            if ( $Cert.Issuer -like '*Microsoft Intune MDM Device CA*' ) { $IntuneCerts += $Cert }
        }
    }
    $IntuneCerts | Remove-Item -Confirm:$false
}