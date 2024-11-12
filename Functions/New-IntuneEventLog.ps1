function New-IntuneEventLog {
    <#
    .DESCRIPTION
    Entra Id Join 및 Intune Enrollment 관련 Tasks 및 Status들에 대하여 Application Event Log에 기록합니다.

    .EXAMPLE
        New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 100 -Message "STEP : AzureADJoin : dsregcmd.exe /join /debug : Join 작업을 수행하였습니다. PC 재시작이 필요합니다."
    #>
    param (
        [ValidateSet('AzureADJoin','IntuneEnrollment')]
        $Source = 'IntuneEnrollment',
        [ValidateSet('Information','Warning', 'Error')]
        $EntryType = 'Information',
        [ValidateRange(0, 100)]
        $EventId = 0,
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