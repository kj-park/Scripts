
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2196106' -OutFile C:\Temp\MSTeams-x64.msix
Add-AppxPackage -Path C:\Temp\MSTeams-x64.msix

#Get-AppxPackage | where { $_.Name -like 'MSTeams'} | Remove-AppxPackage