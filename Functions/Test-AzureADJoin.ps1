function Test-AzureADJoin {
    if ( (C:\Windows\system32\dsregcmd.exe /status | Select-String " AzureADJoined : " | Select-Object -ExpandProperty Line) -match "YES" ) { return $true } else { return $false }
}