# based off of CIS Microsoft Windows 10 Enterprise Benchmark v3.0.0

# USER MANAGEMENT
##Asks for user input to change passwords##
$passwd = Read-Host "Enter a password for ALL users...use PurpleTruck70! as the password" -AsSecureString

##Gets list of all local users by Name##
$users = Get-LocalUser | Select Name


##Changes Password for ALL users##
ForEach ($entry in $users) {
    $username = ($entry.Name)
    
    Set-LocalUser -Name $username -Password $passwd
    Write-output "$username Password Updated!"

}


##Asks if you want to delete each user in the list##

Write-output " "
Write-output "BE CAREFUL WITH THIS NEXT SECTION, IT IS ASKING ABOUT DELETING ACCOUNTS!"
Write-output "DO NOT DELETE LOCAL DEFAULT/SYSTEM ACCOUNTS!!! EX. Administrator, defaultuser, WDAGUtilityAccount, etc."
Write-output " "
ForEach ($entry in $users) {
    $username = ($entry.Name)

    Write-Output " "

    $deleteUser = Read-Host "Delete $username account: Y/N"

    if ($deleteUser -eq "Y") {
        ##Confirms user deletion##
        $confirmDelete = Read-Host "Are you sure you want to delete $username ? Y/N"
        if ($confirmDelete -eq "Y"){
            Remove-LocalUser -Name $username
            Write-output "Account deleted"
        }
    }

}


##Gets a list of current admin users and asks if they should be local users instead##
Write-Output " "
Write-output "DO NOT REMOVE ADMIN PRIVILAGES FOR LOCAL DEFUALT/SYSTEM ACCOUNTS!!! Ex. Administrator"
Write-output " "
$adminUsers = Get-LocalGroupMember -Group "Administrators" | Select Name
ForEach ($entry in $adminUsers) {
    $username = ($entry.Name)

    Write-Output " "

    $makeLocalAdmin = Read-Host "Make $username a local account: Y/N"

    if ($makeLocalAdmin -eq "Y"){
    Remove-LocalGroupMember -Group "Administrators" -Member $username
    Write-output "$username is not an Admin"
    }

}

Write-output " "




# PASSWORD POLICIES
Write-Output "Setting password and account lockout policies..."
# set 'enforce password history' to 24
net accounts /uniquepw:24

# set 'max password age' to 30
net accounts /maxpwage:30

# set 'min password age' to 1
net accounts /minpwage:1

# set 'min password length' to 14
net accounts /minpwlen:14

# set 'password meets complexity requirements' to enabled

# set 'relax min password length limit' to enabled

# set 'store passwords with reverible encryption' to disabled


# ACCOUNT LOCKOUT POLICY
# set 'account lockout duration' to 15+ minutes
net accounts /lockoutduration:60

# set 'account lockout threshold' to 3
net accounts /lockoutthreshold:5

# set 'allow admin account lockout' to enabled
# set 'reset account lockout counter after' to 15+ minutes

# USER RIGHTS ASSIGMENT


# SECURITY OPTIONS


# SERVICES
Write-Output "Disabling services..."
Write-Output "Don't panic if there's lots of errors here, some of these services might not be installed on your computer"

Get-Service BTAGService | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service bthserv | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service Browser | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service MapsBroker | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service ifsvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service IISADMIN | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service irmon | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service ICS | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service lltdsvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service LxssManager | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service FTPSVC | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service MSiSCSI | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service sshd | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service PNRPsvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service p2psvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service p2pimsvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service PNRPAutoReg | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service Spooler | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service wercplsupport | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service RasAuto | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service SessionEnv | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service TermService | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service UmRdpService | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service RpcLocator | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service RemoteRegistry | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service RemoteAccess | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service LanmanServer | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service simptcp | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service SNMP | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service sacsvr | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service SSDPSRV | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service upnphost | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WMSvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WerSvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service Wecsvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WMPNetworkSvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service icssvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WpnService | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service PushToInstall | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WS-Management | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service WinRM | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service W3SVC | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service XboxGipSvc | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service XblAuthManager | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service XblGameSave | Stop-Service -PassThru | Set-Service -StartupType Disabled
Get-Service XboxNetApiSvc | Stop-Service -PassThru | Set-Service -StartupType Disabled

# FIREWALL THINGS
# Check for Firewall profiles...will probably be Domain, Private, Public##
Write-Output "Checking current status of Firewalls..."
Get-NetFirewallProfile | Format-Table Name, Enabled

# Enable Firewall for Domain, Private, and Public profiles##
Set-NetFirewallProfile -All -Enabled True
Write-output "Firewalls enabled"

# Confirm Firewall is enabled...everything should have Enabled set to true##
Write-output "Double check Firewall status...all Enabled should be true"
Get-NetFirewallProfile | Format-Table Name, Enabled

# Block inbound connections for all profiles (public, private, and domain)
Set-NetFirewallProfile -All -DefaultInboundAction Block

# set logging settings
Set-NetFirewallProfile -All -LogMaxSizeKilobytes 16384 -LogAllowed true -LogBlocked true -LogFileName "%systemroot%\system32\LogFiles\Firewall\fw.log"


# AUDIT POLICY
Write-Output "Changing audit policy..."

# Enable auditing of account logon events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditAccountLogon" -Value 2

# Enable auditing of account management events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditAccountManage" -Value 2

# Enable auditing of directory service access events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditDSAccess" -Value 2

# Enable auditing of logon events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditLogonEvents" -Value 2

# Enable auditing of object access events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditObjectAccess" -Value 2

# Enable auditing of policy change events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditPolicyChange" -Value 2

# Enable auditing of privilege use events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditPrivilegeUse" -Value 2

# Enable auditing of process tracking events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditProcessTracking" -Value 2

# Enable auditing of system events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSystemEvents" -Value 2

# Enable auditing of kernel object events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditKernelObject" -Value 2

# Enable auditing of SAM and security system extension events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSAM" -Value 2
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSecuritySystemExtension" -Value 2

# Enable auditing of registry events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditRegistry" -Value 2

Write-Output "Changing advanced audit policies..."
# enable advanced auditing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "SCENoApplyLegacyAuditPolicy" -Value 1
# Account Logon
Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
Auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable
Auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
# Account Management
Auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
# Detailed Tracking
Auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable
Auditpol /set /subcategory:"Plug and Play Events" /success:enable 
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Termination" /success:disable /failure:disable
Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable
# DS Access
Auditpol /set /subcategory:"Detailed Directory Service Replication" /success:disable /failure:disable
Auditpol /set /subcategory:"Directory Service Access" /success:disable /failure:disable
Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
Auditpol /set /subcategory:"Directory Service Replication" /success:disable /failure:disable
# Logon/Logoff
Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
Auditpol /set /subcategory:"Group Membership" /success:enable 
Auditpol /set /subcategory:"IPsec Extended Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Main Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Quick Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"Logoff" /success:enable 
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"User / Device Claims" /success:disable /failure:disable
# Object Access
Auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
Auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
Auditpol /set /subcategory:"Central Policy Staging" /success:disable /failure:disable
Auditpol /set /subcategory:"Detailed File Share" /success:enable 
Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
Auditpol /set /subcategory:"File System" /success:enable 
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
Auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
Auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable
Auditpol /set /subcategory:"Kernel Object" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"Registry" /success:enable
Auditpol /set /subcategory:"SAM" /success:enable
# Policy Change
Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable
Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:disable
# Privilege Use
Auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Privilege Use Events" /success:disable /failure:disable
Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
# System
Auditpol /set /subcategory:"IPsec Driver" /success:enable
Auditpol /set /subcategory:"Other System Events" /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable