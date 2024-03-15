#!/bin/bash

backup_dir="$HOME/Desktop/sysconfig_backup"

# Function to create a backup of a file
backup_file() {
    local file=$1
    local backup_file="$backup_dir/$(basename $file).backup"

    if [ -f $file ]; then
        cp $file $backup_file
        echo "Backup created: $backup_file"
    else
        echo "File not found: $file"
    fi
}

# Create backup directory if it doesn't exist
if [ ! -d "$backup_dir" ]; then
    mkdir -p $backup_dir
    echo "Backup directory created: $backup_dir"
fi


if command -v apt >/dev/null 2>&1; then
	apt install libpam-pwquality
	apt install auditd
    apt install neofetch
elif command -v yum >/dev/null 2>&1; then
	yum install libpam-pwquality
	yum install auditd
    yum install neofetch
else
    #may or may not work so uncomment the line if this comes up 
    #cat /etc/os-release
    echo "Unknown package manager"
fi

# Backup original files
backup_file "/etc/login.defs"
backup_file "/etc/ssh/sshd_config"
backup_file "/etc/apache2/conf-enabled/security.conf"
backup_file "/etc/security/pwquality.conf"
backup_file "/etc/fstab"
backup_file "/etc/sudoers"
backup_file "/etc/audit/rules.d/audit.rules"
backup_file "/etc/sysctl.conf"

# Update PASS_MAX_DAYS
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs 
# Update PASS_MIN_DAYS
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t30/' /etc/login.defs 
# Update PASS_MIN_LEN
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t7/' /etc/login.defs 
# Update FAILLOG_ENAB
sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB\tyes/' /etc/login.defs 
# Update LOG_OK_LOGINS
sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS\tno/' /etc/login.defs 
# Update LOGIN_RETIES
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES\t3/' /etc/login.defs 
# Update LOGIN_TIMEOUT
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT\t3600/' /etc/login.defs 
# Update Default_home
sed -i 's/^DEFAULT_HOME.*/DEFAULT_HOME\tno/' /etc/login.defs 
# Update USERGROUPS_ENAB
sed -i 's/^USERGROUPS_ENAB.*/USERGROUPS_ENAB\tyes/' /etc/login.defs 
# Update ENCRYPT_METHOD
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD\tSHA512/' /etc/login.defs 
echo "Login definitions updated successfully."



#SSH CONFIG
# Use sed to perform the search and replace operation
sudo sed -i "/^#*PermitRootLogin/c\PermitRootLogin no" /etc/ssh/sshd_config
sudo sed -i "/^#*Protocol/c\Protocol 2" /etc/ssh/sshd_config
sudo sed -i "/^#*X11Forwarding/c\X11Forwarding no" /etc/ssh/sshd_config
sudo sed -i "/^#*MaxAuthTries/c\MaxAuthTries 2" /etc/ssh/sshd_config
sudo sed -i "/^#*Ciphers/c\Ciphers aes128-ctr,aes192-ctr,aes256-ctr" /etc/ssh/sshd_config
sudo sed -i "/^#*ClientAliveInterval/c\ClientAliveInterval 900" /etc/ssh/sshd_config
sudo sed -i "/^#*PermitEmptyPassword/c\PermitEmptyPassword no" /etc/ssh/sshd_config
sudo sed -i "/^#*PermitTunnel/c\PermitTunnel no" /etc/ssh/sshd_config
sudo sed -i "/^#*MaxSessions/c\MaxSessions 3" /etc/ssh/sshd_config
# Print a message to indicate the operation is complete
echo "The values have been changed in /etc/ssh/sshd_config."



#APACHE@ BASIC
# Use sed to perform the search and replace operation in security.conf
sudo sed -i "/^#*ServerTokens/c\ServerTokens Prod" /etc/apache2/conf-enabled/security.conf
sudo sed -i "/^#*ServerSignature/c\ServerSignature Off" /etc/apache2/conf-enabled/security.conf
sudo sed -i "/^#*TraceEnable/c\TraceEnable Off" /etc/apache2/conf-enabled/security.conf

sudo sed -i "/^#*Header unset ETag/c\Header unset ETag" /etc/apache2/conf-enabled/security.conf
sudo sed -i "/^#*Header always unset X-Powered-By/c\Header always unset X-Powered-By" /etc/apache2/conf-enabled/security.conf
sudo sed -i "/^#*FileETag/c\FileETag None" /etc/apache2/conf-enabled/security.conf
systemctl restart apache2
echo "APACHE 2 DONE"


#PWQUALITY
# Use sed to perform the search and replace operation in pwquality.conf
sudo sed -i "/^#\s*difok/c\difok = 5" /etc/security/pwquality.conf
sudo sed -i "/^#\s*minlen/c\minlen = 7" /etc/security/pwquality.conf
sudo sed -i "/^#\s*dcredit/c\dcredit = -1" /etc/security/pwquality.conf
sudo sed -i "/^#\s*ucredit/c\ucredit = -1" /etc/security/pwquality.conf
sudo sed -i "/^#\s*lcredit/c\lcredit = -1" /etc/security/pwquality.conf
sudo sed -i "/^#\s*ocredit/c\ocredit = -1" /etc/security/pwquality.conf
sudo sed -i "/^#\s*minclass/c\minclass = 3" /etc/security/pwquality.conf
sudo sed -i "/^#\s*maxrepeat/c\maxrepeat = 3" /etc/security/pwquality.conf
sudo sed -i "/^#\s*maxsequence/c\maxsequence = 3" /etc/security/pwquality.conf
sudo sed -i "/^#\s*gecoscheck/c\gecoscheck = 1" /etc/security/pwquality.conf
sudo sed -i "/^#\s*enforce_for_root/c\enforce_for_root" /etc/security/pwquality.conf
sudo sed -i "/^#\s*enforcing/c\enforcing = 1" /etc/security/pwquality.conf
sudo sed -i "/^#\s*dictcheck/c\dictcheck = 1" /etc/security/pwquality.conf
sudo sed -i "/^#\s*retry/c\retry = 3" /etc/security/pwquality.conf
sed -i "/^#\s*usercheck = 1/c\usercheck = 1" /etc/security/pwquality.conf
sed -i "/^#\s*usersubstr = 0/c\usersubstr = 1" /etc/security/pwquality.conf
sudo sed -i "/^#\s*maxclassrepeat/c\maxclassrepeat = 3" /etc/security/pwquality.conf
echo "PASSWORD POLICY DONE"




#FSTAB
cat << EOF >> /etc/fstab
proc /proc proc remount,rw,nosuid,nodev,noexec,hidepid=2,relatime 0 0
none /run/shm tmpfs defaults,ro 0 0
EOF
echo "FSTAB DONE. HIDEPID ENABLED"



#RECON
#VISUDO
if grep -q '(!authenticate)' /etc/sudoers; then
    echo "\n\nThe phrase '(!authenticate)' exists in the sudoers file."
else
    echo "\n\nThe phrase '(!authenticate)' does not exist in the sudoers file."
fi



#AUDID RULES
cat << EOF >> /etc/audit/rules.d/audit.rules
-D
-i
-a exclude,never -F msgtype=CRED_REFR
-a exclude,never -F msgtype=SYSCALL
-a exclude,never -F msgtype=CRED_DISP
-a exclude,never -F msgtype=CRED_ACQ
-a exclude,never -F msgtype=CRED_ACCT
-a exclude,never -F msgtype=PATH
-a always,exclude -F msgtype=CWD
-a always,exclude -F msgtype=CWD
-a never,user -F subj_type=crond_t
-a never,exit -F subj_type=crond_t
-a never,exit -F arch=b32 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t
-a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t
-a always,exclude -F msgtype=CRYPTO_KEY_USER

-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# User, group, password
-w /etc/group -p wa -k group
-w /etc/passwd -p wa -k passwd
-w /etc/gshadow -k sgroup
-w /etc/shadow -k spasswd
-w /etc/security/opasswd -k opasswd

# Sudoers file changes
-w /etc/sudoers -p wa -k sudos
-w /etc/sudoers.d/ -p wa -k sudos

# Passwd used
-w /usr/bin/passwd -p x -k passwd_used


# Group/User changed
-w /usr/sbin/groupadd -p x -k group_change
-w /usr/sbin/groupmod -p x -k group_change
-w /usr/sbin/addgroup -p x -k group_change
-w /usr/sbin/useradd -p x -k user_change
-w /usr/sbin/userdel -p x -k user_change
-w /usr/sbin/usermod -p x -k user_change
-w /usr/sbin/adduser -p x -k user_change

# Login Info
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login

# Detect Remote Shell Use
-a always,exit -F arch=b32 -F exe=/bin/bash -F success=1 -S connect -k "remote_shell"
-a always,exit -F arch=b64 -F exe=/bin/bash -F success=1 -S connect -k "remote_shell"
-a always,exit -F arch=b32 -F exe=/usr/bin/bash -F success=1 -S connect -k "remote_shell"
-a always,exit -F arch=b64 -F exe=/usr/bin/bash -F success=1 -S connect -k "remote_shell"

# Remote Connections
-a always,exit -F arch=b64 -S connect -F a2=16 -F success=1 -F key=network_connect
-a always,exit -F arch=b32 -S connect -F a2=16 -F success=1 -F key=network_connect

# Root Key Change
-w /root/.ssh -p wa -k rootkey

#Attempt to read
-a always,exit -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileaccess
-a always,exit -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileaccess
-a always,exit -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileaccess
-a always,exit -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileaccess
-a always,exit -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileaccess
-a always,exit -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileaccess
-a always,exit -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileaccess
-a always,exit -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileaccess

#Processes switching account (PID CHANGE)
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p rw -k priv_esc
-w /etc/sudoers.d -p rw -k priv_esc

#File attribute Changes
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chmod  -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=-1 -k perm_mod

#New Sockets
-a always,exit -F arch=b32 -S socket -F a0=2  -k new_socket
-a always,exit -F arch=b64 -S socket -F a0=2  -k new_socket

#Recon + Usage of tools:
## Reconnaissance
-w /usr/bin/whoami -p x -k recon
-w /usr/bin/id -p x -k recon
-w /bin/hostname -p x -k recon
-w /bin/uname -p x -k recon
-w /etc/issue -p r -k recon
-w /etc/hostname -p r -k recon

-w /usr/bin/wget -p x -k susp_activity
-w /usr/bin/curl -p x -k susp_activity
-w /usr/bin/base64 -p x -k susp_activity
-w /bin/nc -p x -k susp_activity
-w /bin/netcat -p x -k susp_activity
-w /usr/bin/ncat -p x -k susp_activity
-w /usr/bin/ss -p x -k susp_activity
-w /usr/bin/netstat -p x -k susp_activity
-w /usr/bin/ssh -p x -k susp_activity
-w /usr/bin/scp -p x -k susp_activity
-w /usr/bin/sftp -p x -k susp_activity
-w /usr/bin/ftp -p x -k susp_activity
-w /usr/bin/socat -p x -k susp_activity
-w /usr/bin/wireshark -p x -k susp_activity
-w /usr/bin/tshark -p x -k susp_activity
-w /usr/bin/rawshark -p x -k susp_activity
-w /usr/bin/rdesktop -p x -k T1219_Remote_Access_Tools
-w /usr/local/bin/rdesktop -p x -k T1219_Remote_Access_Tools
-w /usr/bin/wlfreerdp -p x -k susp_activity
-w /usr/bin/xfreerdp -p x -k T1219_Remote_Access_Tools
-w /usr/local/bin/xfreerdp -p x -k T1219_Remote_Access_Tools
-w /usr/bin/nmap -p x -k susp_activity

#Random Shell Usage
-w /bin/ash -p x -k susp_shell
-w /bin/csh -p x -k susp_shell
-w /bin/fish -p x -k susp_shell
-w /bin/tcsh -p x -k susp_shell
-w /bin/tclsh -p x -k susp_shell
-w /bin/xonsh -p x -k susp_shell
-w /usr/local/bin/xonsh -p x -k susp_shell
-w /bin/open -p x -k susp_shell
-w /bin/rbash -p x -k susp_shell

#Memory File creations
-a always,exit -F arch=b64 -S memfd_create -F key=anon_file_create
-a always,exit -F arch=b32 -S memfd_create -F key=anon_file_create
EOF
systemctl restart auditd
echo "\nAuditd Rules are setup"

#SYSCTL.CONF
cat << EOF >> /etc/sysctl.conf
fs.protected_fifos=2
fs.protected_regular=2
fs.protected_symlinks=1
fs.protected_hardlinks=1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict=1
kernel.kexec_load_disabled = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.forwarding = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 16384 65535
net.ipv4.tcp_fin_timeout = 7
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 15
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
kernel.perf_event_paranoid=3
kernel.panic_on_oops = 60
kernel.panic = 60
vm.swappiness=1
EOF
#sysctl -p
echo "SYSCTL CONFIG DONE"