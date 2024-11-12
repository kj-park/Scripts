function Get-CurrentEnrollmentId {
    $EnrollmentGUID = $null; $EnrollmentGUID = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger -Name CurrentEnrollmentId -ErrorAction SilentlyContinue).CurrentEnrollmentId
    return $EnrollmentGUID
}