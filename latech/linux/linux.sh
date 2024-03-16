# sudo
# backup files
UNSET HISTFILE
IMPORTANT_FILES=(
    "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers" "/etc/ssh/sshd_config"
)

mkdir -p output

for important_file in "${IMPORTANT_FILES[@]}"; do
    cp ${important_file} ${important_file}.pre
    mv ${important_file}.pre output
    if [ $? -ne 0 ]; then
        echo "[!] did not back up ${important_file} succesfully "
    else
        echo "[-] backed up ${important_file}"
    fi
done

useradd -s /bin/bash -m -d /var/sysadmin sysadmin
chmod -R 750 /var/sysadmin
addgroup sysadmin
usermod -aG $USER sysadmin
echo 'sysadmin:SuperSecure69' | chpasswd

if test -f "/etc/sudoers"; then
    grep -v '^[[:blank:]]*#' /etc/sudoers.d/* | sort -u >oldsudoersd
    grep -v '^[[:blank:]]*#' /etc/sudoers | sort -u >oldsudoers
    defaults=$(grep '^Defaults' /etc/sudoers)
    rm /etc/sudoers
    rm /etc/sudoers.d/*

    cat <<EOF >/etc/sudoers
$defaults
%sysadmin ALL=NOPASSWD:ALL
blackteam ALL=NOPASSWD:ALL
EOF

fi

passwd -l root 

sed -i "s/#PermitTunnel.*/PermitTunnel no/" /etc/ssh/sshd_config
sed -i "s/#MaxAuthTries.*/MaxAuthTries 2/" /etc/ssh/sshd_config
sed -i "s/#PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
sed -i "s/#MaxSessions.*/MaxSessions 3/" /etc/ssh/sshd_config
sed -i "s/#PermitEmptyPassword.*/PermitEmptyPasswords no/" /etc/ssh/sshd_config
sed -i "s/PermitTunnel.*/PermitTunnel no/" /etc/ssh/sshd_config
sed -i "s/MaxAuthTries.*/MaxAuthTries 2/" /etc/ssh/sshd_config
sed -i "s/PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
sed -i "s/MaxSessions.*/MaxSessions 3/" /etc/ssh/sshd_config
sed -i "s/PermitEmptyPassword.*/PermitEmptyPasswords no/" /etc/ssh/sshd_config


for u in $( getent passwd | tr ':' ' ' | awk '{printf $1 "\n"}' | grep -vP "sysadmin|blackteam" ); do passwd="$(date +"%T.%N" | md5sum | cut -c -16)"; echo "$u:$passwd" | tee -a test | chpasswd ; done

# SSH_Config cannot be modified
chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow -R
# No group & other rwx perms in root folder
chmod -Rv go-rwx /root   
# No group & other w perms in all files/directories in home
chmod -Rv go-w /home/*
# make immutable
chattr +i /etc/ssh/ssh_config /etc/ssh/sshd_config 
chattr +i /etc/passwd /etc/shadow


for u in $( getent passwd | tr ':' ' ' | awk '{printf $1 "\n"}' | grep -vP "sysadmin|blackteam" ) ; do if [ -d "$(getent passwd "$u" | cut -d: -f6)/.ssh" ]; then mkdir -p ~/$u ; mv $(getent passwd "$u" | cut -d: -f6)/.ssh/ ~/$u/ ; chmod -R 700 ~/$u; chown -R $USER ~/$u; fi; done

find / 2>/dev/null | grep authorized_keys | xargs -I {} ls {}

mkdir -p output

for important_file in "${IMPORTANT_FILES[@]}"; do
    cp ${important_file} ${important_file}.post
    mv ${important_file}.post output
    if [ $? -ne 0 ]; then
        echo "[!] did not back up ${important_file} succesfully "
    else
        echo "[-] backed up ${important_file}"
    fi
done

groupadd blackteam
usermod -aG blackteam blackteam

echo "proc     /proc     proc     defaults,hidepid=2     0     0" >> /etc/fstab
mount -o remount,rw,gid=sysadmin,gid=blackteam,hidepid=2 /proc

# paranoid shit
if [ $(command -v sysctl) ]; then 
    # disable new kernel modules
    sysctl -w kernel.modules_disabled=1
    echo 'kernel.modules_disabled=1' > /etc/sysctl.conf
else echo "no sysctl"
fi

# iptables -A INPUT --proto icmp -j DROP
# echo “1” > /proc/sys/net/ipv4/icmp_echo_ignore_all



