$namespaceName = "root\cimv2\mdm\dmmap"
$parentID="./Vendor/MSFT/Policy/Config"
$className = "MDM_SharedPC"
$cimObject = Get-CimInstance -Namespace $namespaceName -ClassName $className
$cimObject.EnableSharedPCMode = $True
$cimObject.AccountModel = 1
$cimObject.RestrictLocalStorage = $False
Set-CimInstance -CimInstance $cimObject