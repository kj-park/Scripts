
Application ID      : 8153f0d4-2c61-49d2-8891-d3491f4c1a94
Client Secret ID    : 1ac6bc5e-77e3-472b-8915-9e8c6f4a26db
Client Secret Value : nur8Q~K.eIRyMsmDdnRpX4in11Bi9A72gnQSAawJ

Tenant ID           : ad12601a-7684-499a-8214-91f1a1d5ffbb
Tenant Name         : M365x68919772.onmicrosoft.com



Device.Read.All
Device.ReadWrite.All
Directory.Read.All
Directory.ReadWrite.All
DeviceManagementManagedDevices.Read.All
DeviceManagementManagedDevices.ReadWrite.All
User.Read.All

## Exchange Mailbox Server:
 
- C:\Tasks 폴더 생성
 
- New-AREs.ps1 script file 복사
 
- Edge 서버에 연결하기 위한 Credentail의 password의 SecureString 파일 생성:
  ConvertTo-SecureString -String ")Okm(Ijn*Uhb" -AsPlainText -Force | ConvertFrom-SecureString | Out-File 'C:\Tasks\EdgeConnectorPwd.txt'
 
- Remote PowerShell 연결을 위한 WSMan의 TrustedHosts 설정
  set-Item WSMan:\localhost\Client\TrustedHosts -Value 'hdo-edge-n01.oilbank.co.kr,hdo-edge-n02.oilbank.co.kr'
 
- Exchange 관리자 계정으로 실행되는 Task Schedule 생성
  powershell.exe -ExecutionPolicy Bypass -File C:\Tasks\New-AREs.ps1
 
## Exchange Edge Server:
 
- Remote PowerShell enable 
  Enable-PSRemoting -Force
  Restart-Service WinRM
 
- Windows Firewall에서 Windows Remote Management 항목에 대한 public 프로파일의 RemoteAddress를 local network에서 Any로 변경
  Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any
 
- System의 LocalAccountTokenFilterPolicy 설정 추가
  $newItemProperty = @{
    Name = 'LocalAccountTokenFilterPolicy'
    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    PropertyType = 'DWord'
    Value = 1
  }
  New-ItemProperty @newItemProperty
 
- Local User 생성 및 Administrators 그룹에 추가
  New-LocalUser -Name edgeconnector -Password (ConvertTo-SecureString -String ")Okm(Ijn*Uhb" -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
  Add-LocalGroupMember -Group Administrators -Member edgeconnector
 
- C:\Tasks 폴더 생성 및 공유 폴더 생성, 권한 추가
 