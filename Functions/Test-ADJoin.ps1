function Test-ADJoin {
    if ( (C:\Windows\system32\dsregcmd.exe /status | Select-String " DomainJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { return $true } else { return $false }
}