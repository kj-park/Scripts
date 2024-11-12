function Save-Tools {
    <#
    .DESCRIPTION
    $Path\$FolderName 에 PSTools 와 Logs 폴더를 생성합니다. 각 폴더의 설명은 아래와 같습니다:
        - PSTools : Sysinternal의 PSTools을 download 및 압축 해제합니다.
        - Logs : 진단 및 결과를 저장하기 위한 폴더입니다.
    #>
    param ( $Path = "C:\Temp", $FolderName = "Intune" )
    New-IntuneEventLog -Source AzureADJoin -EntryType Information -EventId 0 -Message "STEP : SaveTools : Downloaded the Diag & Execute Tool : $Path\$FolderName"
    New-Item -Path $Path -Name $FolderName -ItemType Directory -Force | Out-Null
    New-Item -Path "$Path\$FolderName" -Name Logs -ItemType Directory -Force | Out-Null
    New-Item -Path "$Path\$FolderName" -Name PSTools -ItemType Directory -Force | Out-Null
    if ( !(Test-Path -Path "$Path\$FolderName\PSTools.zip") ) {
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile "$Path\$FolderName\PSTools.zip"
    }
    Expand-Archive -Path "$Path\$FolderName\PSTools.zip" -DestinationPath "$Path\$FolderName\PSTools" -Force
}