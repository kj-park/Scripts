$namespaceName = "root\cimv2\mdm\dmmap"
$parentID="./Vendor/MSFT/Policy/Config"
$className = "MDM_SharedPC"
$cimObject = Get-CimInstance -Namespace $namespaceName -ClassName $className
$cimObject.EnableSharedPCMode = $False
Set-CimInstance -CimInstance $cimObject