# Install updates
Write-Output "Installing updates..."
Install-WindowsUpdate -AcceptAll -Install -AutoReboot

# Enable firewall
Write-Output "Enabling firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Enable Advanced Auditing
Write-Output "Enabling advanced auditing..."
Enable-NetFirewallRule -DisplayGroup "Advanced Auditing"

# Enable Windows Defender
Write-Output "Enabling Windows Defender..."
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable AppLocker
Write-Output "Enabling AppLocker..."
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine
Install-Module AppLocker
Set-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective) -RuleCollection @{EnforcementMode="AuditOnly"}
Set-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective) -RuleCollection @{EnforcementMode="Enforce"}

# Enable Virtualization-Based Security (VBS)
Write-Output "Enabling Virtualization-Based Security (VBS)..."
Enable-VmSecureBoot -SecureBootTemplate Default
Enable-VmDynamicMemory -MemoryWeight 100

# Enable Remote Credential Guard
Write-Output "Enabling Remote Credential Guard..."
Set-Vm -Name "*" -RmGuardedHostOn $true

# Enable Network Level Authentication (NLA)
Write-Output "Enabling Network Level Authentication (NLA)..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

# Enable Credential Guard
Write-Output "Enabling Credential Guard..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value "0x20000004"

# Enable Secure Boot
Write-Output "Enabling Secure Boot..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -Value 1

# Enable BitLocker
Write-Output "Enabling BitLocker..."
Set-BitLockerEncryption -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -RecoveryKeyProtector
Set-BitLockerEncryption -MountPoint "D:" -EncryptionMethod Aes256 -UsedSpaceOnly -RecoveryKeyProtector

# Enable Remote Desktop
Write-Output "Enabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

# Enable auditing
Write-Output "Enabling auditing..."
Set-ItemProperty -Path "HKLM:\SECURITY\Policy\PolAdtEv" -Name "AuditBaseObjects" -Value 1
Set-ItemProperty -Path "HKLM:\SECURITY\Policy\PolAdtEv" -Name "AuditBasePolicy" -Value 1
Set-ItemProperty -Path "HKLM:\SECURITY\Policy\
