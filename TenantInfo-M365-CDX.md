
#region Set Variable for M365 CDX

<#
Remove-Variable ClientId -Force
Remove-Variable ClientSecret -Force
Remove-Variable TenantId -Force
Remove-Variable TenantName -Force
#>

New-Variable -Name ClientId     -Value "8153f0d4-2c61-49d2-8891-d3491f4c1a94"     -Option ReadOnly -Force
New-Variable -Name ClientSecret -Value "nur8Q~K.eIRyMsmDdnRpX4in11Bi9A72gnQSAawJ" -Option ReadOnly -Force
New-Variable -Name TenantId     -Value "ad12601a-7684-499a-8214-91f1a1d5ffbb"     -Option ReadOnly -Force
New-Variable -Name TenantName   -Value "M365x68919772.onmicrosoft.com"                  -Option ReadOnly -Force

#endregion Set Variable for M365 CDX

Device.Read.All
Device.ReadWrite.All
Directory.Read.All
Directory.ReadWrite.All
DeviceManagementManagedDevices.Read.All
DeviceManagementManagedDevices.ReadWrite.All
User.Read.All