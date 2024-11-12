function Invoke-PopupWindow {
    <#
    .DESCRIPTION
    Script에서 사용자의 선택을 확인하기 위해 Window를 popup하고 선택을 확인합니다.

    .EXAMPLE
        Invoke-PopupWindow -Title "STEP: AzureAD Join" -Description "PC를 재시작하고 다음 과정을 진행해주세요." -Style OkCancel -IconType Exclamation
    #>
    param (
        $Title = 'Windows Title',
        $Description = 'Detailed Description',
        $SecondsToWait = 0,
        [ValidateSet('OkOnly', 'OkCancel', 'AbortRetryIgnore', 'YesNoCancel', 'YesNo', 'RetryCancel')]
        $Style = 'OkCancel',
        [ValidateSet('Critical', 'Question', 'Exclamation', 'Information' )]
        $IconType = 'Information'
    )
    begin {
        $IntStyle = switch ($Style) { 'OkOnly' {0}; 'OkCancel' {1}; 'AbortRetryIgnore' {2}; 'YesNoCancel'{3}; 'YesNo' {4}; 'RetryCancel' {5} }
        $IntType = switch ($IconType) { 'Critical' {16}; 'Question' {32}; 'Exclamation' {48}; 'Information'{64} }

        $Return = $null
        $WShell = New-Object -ComObject WScript.Shell
    }
    process {
        $Return = $WShell.Popup($Description, $SecondsToWait, $Title, $IntStyle + $IntType)
    }
    end {
        $Return = switch ($Return) { 1 {'Ok'}; 2 {'Cancel'}; 3 {'Abort'}; 4 {'Retry'}; 5 {'Ignore'}; 6 {'Yes'}; 7 {'No'}; Default {$null} }
        return $Return
    }
}