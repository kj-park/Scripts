function Build-WinEventFilterXPath {
    param (
        $SearchString = "(EventID=71 or EventID=75 or EventID=76 or EventID=95)"
    )
    $QueryXPath = "<QueryList><Query><Select>*[System[$SearchString]]</Select></Query></QueryList>"
    return $QueryXPath
}