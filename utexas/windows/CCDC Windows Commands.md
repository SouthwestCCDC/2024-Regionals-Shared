# Bypass Execution policy

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\YOUR_SCRIPT.ps1
```

# AD & Local Management
## Managing passwords
### Local users
You can easily set local user passwords with:
`net user [username] [password]`
This has the downside of revealing the password in plaintext to command history. You can get around this with:
`$passwd = Read-Host -AsSecureString`
`$useracc = Get-LocalUser -Name [username]`
`$useracc | Set-LocalUser -Password $passwd`
### Domain users
Running as administrator, you can prompt for a new password:
`Get-ADUser -Identity [username] | Set-ADAccountPassword -Reset`
With a secure string stored in `$passwd`:
`Get-ADUser -Identity [username] | Set-ADAccountPassword -NewPassword $passwd -Reset`
You can convert a string to a secure string (for use in scripts):
`$plainstr = "password"`
`$securestr = ConvertTo-SecureString -String $plainstr -AsPlainText -Force`
Shortcut:
`Set-ADAccountPassword -Identity [username] -NewPassword $passwd`

## Creating / managing users
### Local users
List local users:
`net user`
List local administrators:
`net localgroup Administrators`
To create a local user with no password:
`New-LocalUser -Name [username] -NoPassword`
To specify a password:
`New-LocalUser -Name [username] -Password $securestr`
### Domain Users
List AD users:
`Get-ADUser -Filter *`
To create a domain user:
`New-ADUser -Name [username] -AccountPassword $passwd -Enabled [0/1]`
Note that if the password doesn't meet complexity requirements, the account is created without a password and is left disabled


## Managing computers
List computers in current domain:
`Get-ADComputer -Filter *`
List sessions connected to this machine (or another machine):
`net session [\\ComputerName]`
Disconnect sessions from a given machine:
`net session [\\ComputerName] /delete`
Add computer to domain with optionally specifying DC (requires restart):
`Add-Computer -DomainName [DomainName] -Server [DomainName]\[DCName] -Credential [DomainName]\[DomainAdmin] -PassThru -Verbose`
Get general system properties:
`Get-ComputerInfo`

## Group Policy
Backup all GPOs:
`Backup-Gpo -All -Path [BackupPath]`
Backup specific GPO:
`Backup-Gpo -Name [GPOName] -Path [BackupPath]`
Restore all GPOs:
`Restore-GPO -All -Domain [DomainName] -Path [BackupPath]`
Restore specific GPO:
`Restore-GPO -Name [GPOName] -Path [BackupPath]`

# Services
## Enumeration
`netstat -abno`
## SMB
Detect SMBv1:
`Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
Disable/Enable:
`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
`Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
