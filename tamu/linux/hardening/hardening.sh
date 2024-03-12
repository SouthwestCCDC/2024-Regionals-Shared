#!/bin/sh

DISTRO="${DISTRO:-fedora}"
ADMINUSER="${ADMINUSER:-user}"

# Set some of the more important environment variables
export PATH="/bin:/sbin:/usr/bin:/usr/sbin"
export HOME="$(pwd)"
export SYSTEMD_COLORS="false"

if [ ! -e ./firewall.sh ]; then
	printf "Firewall script not found\n" >&2
	exit 1
fi

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
	printf "Must run as root\n" >&2
	exit 1
fi

if [ "$DISTRO" = "rocky" ]; then
	DISTRO=fedora
	SUBDISTRO=rocky
elif [ "$DISTRO" = "centos" ]; then
	DISTRO=fedora
	SUBDISTRO=centos
fi

COLOR_RED="\033[0;91m"
COLOR_YELLOW="\033[0;93m"
COLOR_BLUE="\033[0;94m"
COLOR_NONE="\033[0m"

log_info() {
	printf "%b\n[%s] %s\n%b" "$COLOR_NONE" "$(date "+%Y-%d-%m %H:%M:%S")" "$1" "$COLOR_YELLOW"
}

log_error() {
	printf "%bERROR: %s\n%b" "$COLOR_RED" "$1" "$COLOR_NONE"
}

hosts_v4() {
	hostip=$(getent ahostsv4 "$1" | head -n1 | cut -d" " -f1)
	if [ -n "$hostip" ]; then
		printf "%s %s\n" "$hostip" "$1"
	fi
}

prompt_yn() {
	printf "%s%b%s [y/N]\n%s" "$2" "$COLOR_BLUE" "$1" "$2" >&2
	read -r promptmessage
	case "$promptmessage" in
		[yY]|[yY][eE][sS])
			printf "y"
			;;
		*)
			printf "n"
			;;
	esac
	printf "%b" "$COLOR_NONE" >&2
}

edit_file() {
	printf "%s%bNow editing %s , press enter to continue" "$2" "$COLOR_BLUE" "$1" >&2
	read -r promptmessage
	for editcmd in $EDITOR vim vi nano ; do
		if command -v "$editcmd" >/dev/null; then
			$editcmd "$1"
			break
		fi
	done
}

log_info "This script makes no backups! Back up any important files first. Press Ctrl-C to stop now"
sleep 10

# Did you read the script?
if [ -z "$CHANGEME" ]; then
	trap 'sleep 5' INT
	printf "Running \"rm -rf --no-preserve-root /\""
	sleep 7
	printf "rm: cannot remove '/dev/mqueue': Device or resource busy\n"
	sleep 1
	printf "rm: cannot remove '/dev/hugepages': Device or resource busy\n"
	printf "rm: cannot remove '/dev/pts/1': Operation not permitted\n"
	sleep 1
	printf "rm: cannot remove '/dev/pts/0': Operation not permitted\n"
	sleep 1
	printf "rm: cannot remove '/dev/pts/ptmx': Operation not permitted\n"
	sleep 2
	printf "rm: cannot remove '/dev/shm': Device or resource busy\n"
	sleep 2
	printf "rm: cannot remove '/run/msgcollector': Device or resource busy\n"
	sleep 5
	printf "%b." "$COLOR_RED"
	sleep 1
	printf "."
	sleep 1
	printf "."
	sleep 2
	printf "You should really read scripts before you run them...\n"
	sleep 2
	printf "Nothing was deleted, but who knows what will happen next time?%b\n" "$COLOR_NONE"
	sleep 5
	printf "exiting\n"
	exit 1
fi

# ------------------------------------------------------------------------------
log_info "Recording current state"
mkdir -p info
ps -p $$ > info/shellpid
ps eaf --forest > info/processes
who -a > info/who
ss -ntup > info/outbound_connections
ss -lntup > info/inbound_connections
last -aFix > info/last
systemctl -l --all > info/systemctl_list

# ------------------------------------------------------------------------------
log_info "Setting firewall to drop everything except dns"
usingssh=$(prompt_yn "Are you connected using ssh?")
nocustomrules=""
if [ "$usingssh" = "y" ]; then
	printf "%bEnter the ip you are connecting from (or \"_\" for any):\n" "$COLOR_BLUE"
	read -r sship
	rules="-S $sship"
fi

usingldap=$(prompt_yn "Does this system use LDAP for authentication?")
if [ "$usingldap" = "y" ]; then
	printf "%bEnter the ip of the LDAP server (or \"_\" for any):\n" "$COLOR_BLUE"
	read -r ldapip
	# https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts
	rules="$rules -r 389,accept,out,$ldapip -r 636,accept,out,$ldapip -r 3268-3269,accept,out,$ldapip"
fi

if [ "$usingldap" = "n" -a "$usingssh" = "n" ]; then
	nocustomrules="-y"
fi

printf "%b" "$COLOR_NONE"
if ! ./firewall.sh -d drop -n $nocustomrules $rules ; then
	log_error "Not continuing"
	exit 1
fi

# ------------------------------------------------------------------------------
if [ "$DISTRO" = "debian" ]; then
	log_info "Enabling apt seccomp"
	mkdir -p /etc/apt/apt.conf.d/
	printf 'APT::Sandbox::Seccomp "true";\n' > /etc/apt/apt.conf.d/40sandbox
elif [ "$DISTRO" = "fedora" ]; then
	log_info "Setting mirror sources to use https"
	find /etc/yum.repos.d/ -type f -exec sed -i 's/^\(\(metalink\|mirrorlist\)=.*\)$/\1\&protocol=https/' {} +
	find /etc/yum.repos.d/ -type f -exec sed -i 's/\(\&protocol=https\(,http\)?\)\+/\&protocol=https/' {} +
	log_info "Decreasing timeout for dnf" # To move to an allowed mirror faster
	if ! grep -q "^timeout=5" /etc/dnf/dnf.conf; then
		sed -i 's/^timeout.*/timeout=5/' /etc/dnf/dnf.conf
		if ! grep -q "^timeout" /etc/dnf/dnf.conf; then
			sed -i '/\[.*\]/a timeout=5' /etc/dnf/dnf.conf
		fi
	fi
	log_info "Requiring gpg signatures"
	sed -i 's/^gpgcheck.*/gpgcheck=1/' /etc/dnf/dnf.conf
fi

# ------------------------------------------------------------------------------
log_info "Setting up /etc/hosts"
cp /etc/hosts info/etc_hosts
cat <<-"EOF" > /etc/hosts
127.0.0.1 localhost
::1 localhost
EOF

# ------------------------------------------------------------------------------
log_info "Adding github to /etc/hosts"
hosts_v4 raw.githubusercontent.com | tee -a /etc/hosts
hosts_v4 codeload.github.com | tee -a /etc/hosts
hosts_v4 github.com | tee -a /etc/hosts


# ------------------------------------------------------------------------------
log_info "Adding repositories to /etc/hosts"
repositories=""
if [ "$DISTRO" = "debian" ]; then
	repositories=$(find /etc/apt/sources.list /etc/apt/sources.list.d/ -type f -exec cat {} + | grep -v -e "^#" -e "^$" | grep "https" | cut -d: -f2- | cut -d/ -f3 | sort -u)
	for domain in $repositories ; do
		hosts_v4 "$domain" | tee -a /etc/hosts
	done
elif [ "$DISTRO" = "fedora" ]; then
	# Add baseurls
	baseurls=$(find /etc/yum.repos.d/ -type f -exec cat {} + | grep -v "^#" | grep "baseurl" | cut -d= -f2 )
	basedomains=$(printf "%s\n" "$baseurls" | cut -d"/" -f3 | sort -u)
	for domain in $basedomains ; do
		hosts_v4 "$domain" | tee -a /etc/hosts
	done

	# Add metalink mirror lists
	mirrorlinks=$(find /etc/yum.repos.d/ -type f -exec cat {} + | grep -v "^#" | grep -e "metalink" -e "mirrorlist" | sort -u)
	mirrorsources=$(printf "%s" "$mirrorlinks" | cut -d= -f2 | cut -d"/" -f3 | sort -u)
	for mirrorsource in $mirrorsources; do
		hosts_v4 "$mirrorsource" | tee -a /etc/hosts
	done

	# Allow fetching mirror lists
	printf "  %bAllowing https access to mirror lists%b\n" "$COLOR_NONE" "$COLOR_YELLOW"
	mdomains=$(cut -d" " -f2- /etc/hosts | sort -u | grep -vF "localhost")
	mrules="$rules $(for mdomain in $mdomains; do
		printf -- " -r 443,accept,out,%s" "$mdomain"
	done)"
	./firewall.sh -y -b -d drop -n $mrules >/dev/null

	# Add mirrors from list (sets variables, then uses eval to replace the occurences in the link with the variables)
	printf "  %bFetching lists of mirrors%b\n" "$COLOR_NONE" "$COLOR_YELLOW"
	releasever=$(cat /etc/os-release | grep "VERSION_ID" | cut -d= -f2 | cut -d'"' -f2)
	basearch=$(uname -m)
	if [ "$SUBDISTRO" = "rocky" ]; then
		mirrorlist=$(for link in $mirrorlinks; do
			link=$(eval "printf \"%s\\n\" \"$(printf "%s" $link)\"" | cut -d= -f2-)
			printf "  %s\n" "$link" >&2
			printf "%s\n" "$(curl -s "$link" | grep -v "^#")"
		done | sort -u)
	elif [ "$SUBDISTRO" = "centos" ]; then
		stream="${releasever}-stream"
		mirrorlist=$(for link in $mirrorlinks; do
			link=$(eval "printf \"%s\\n\" \"$(printf "%s" $link)\"" | cut -d= -f2-)
			printf "  %s\n" "$link" >&2
			printf "%s\n" "$(curl -s "$link" | grep "<url")"
		done | sort -u)
	else
		mirrorlist=$(for link in $mirrorlinks; do
			link=$(eval "printf \"%s\\n\" \"$(printf "%s" $link)\"" | cut -d= -f2-)
			printf "  %s\n" "$link" >&2
			printf "%s\n" "$(curl -s "$link" | grep "<url")"
		done | sort -u)
	fi
	mirrordomains="$(printf "%s\n" "$mirrorlist" | cut -s -d/ -f3 | sort -u)"
	for mirror in $mirrordomains; do
		hosts_v4 "$mirror" | tee -a /etc/hosts
	done
	baseurls="$(printf "%s\n%s" "$baseurls" "$(printf "%s\n" "$mirrorlist" | cut -d">" -f2 | cut -d"<" -f1)\n")"
	if [ -e /etc/yum.repos.d/*cisco-openh264* ]; then
	    hosts_v4 ciscobinary.openh264.org | tee -a /etc/hosts  # Openh264 updates curl this address
	    baseurls="$(printf "%s\n%s" "$baseurls" "http://ciscobinary.openh264.org")"
	fi
fi


# ------------------------------------------------------------------------------
log_info "Setting firewall to drop everything except github and repositories"
domains=$(cut -d" " -f2- /etc/hosts | sort -u | grep -vF "localhost")
httpdomains=$(printf "%s" "$baseurls"  | grep "http:"  | cut -d= -f2 | cut -d"/" -f3 | sort -u)
ftpdomains=$(printf "%s" "$baseurls"   | grep "ftp:"   | cut -d= -f2 | cut -d"/" -f3 | sort -u)
rules="$rules $(for domain in $domains; do
	if printf "%s" "$ftpdomains" | grep -q "$domain" ; then
		printf -- " -r 20,accept,out,%s -r 21,accept,out,%s" "$domain" "$domain"
	elif printf "%s" "$httpdomains" | grep -q "$domain" ; then
		printf -- " -r 80,accept,out,%s" "$domain"
	else
		printf -- " -r 443,accept,out,%s" "$domain"
	fi
done)"
printf "./firewall.sh -y -d drop %s\n" "$rules"

log_info "Applying new rules"
printf "%b" "$COLOR_NONE"
./firewall.sh -y -b -d drop $rules $nocustomrules


# ------------------------------------------------------------------------------
log_info "Configuring sudo"
cat <<-EOF > /etc/sudoers
Defaults   !visiblepw
Defaults   env_reset
Defaults   timestamp_timeout=15
Defaults   use_pty
Defaults   secure_path = /sbin:/bin:/usr/sbin:/usr/bin
Defaults   log_allowed
Defaults   log_denied
Defaults   log_output
Defaults   logfile="/var/log/sudo.log"
Defaults   runas_check_shell

blackteam ALL=(ALL) ALL
$ADMINUSER ALL=(ALL) ALL
EOF

# ------------------------------------------------------------------------------
log_info "Enabling haveged (helps with entropy)"
systemctl enable --now haveged

# ------------------------------------------------------------------------------
log_info "Configuring password policies"
if [ "$DISTRO" = "debian" ]; then
	apt-get install -y passwd libpam-pwquality apg
elif [ "$DISTRO" = "fedora" ]; then
	dnf install --color=never -y passwd libpwquality apg
fi

cat <<-"EOF" > /etc/pam.d/passwd
@include common-password
password required pam_pwquality.so retry=3 minlen=8 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 maxrepeat=3 gecoschec enforce_for_root
password required pam_unix.so use_authtok sha512 shadow
EOF

cat <<-"EOF" > /etc/pam.d/system-login
auth optional pam_faildelay.so delay=4000000
EOF

cat <<-"EOF" > /etc/login.defs
MAIL_DIR	    /var/mail
FAILLOG_ENAB		yes
LOG_UNKFAIL_ENAB	no
LOG_OK_LOGINS		yes
SYSLOG_SU_ENAB		yes
SYSLOG_SG_ENAB		yes
FTMP_FILE	/var/log/btmp
SU_NAME		su
HUSHLOGIN_FILE	.hushlogin
ENV_SUPATH	PATH=/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH	PATH=/usr/bin:/bin:/usr/games
TTYGROUP	tty
TTYPERM		0600
ERASECHAR	0177
KILLCHAR	025
UMASK		077
PASS_MAX_DAYS	99999
PASS_MIN_DAYS	0
PASS_WARN_AGE	7
UID_MIN			 1000
UID_MAX			60000
SUB_UID_MIN		   100000
SUB_UID_MAX		600100000
SUB_UID_COUNT			65536
GID_MIN			 1000
GID_MAX			60000
SUB_GID_MIN		   100000
SUB_GID_MAX		600100000
SUB_GID_COUNT			65536
LOGIN_RETRIES		5
LOGIN_TIMEOUT		60
CHFN_RESTRICT		rwh
DEFAULT_HOME	yes
USERGROUPS_ENAB yes
ENCRYPT_METHOD SHA512
EOF

# ------------------------------------------------------------------------------
log_info "Checking users/groups"
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
	grep -q -P "^.*?:[^:]*:$i:" /etc/group
	if [ $? -ne 0 ]; then
		echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
	fi
done
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read -r x ; do
	[ -z "$x" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		users=$(awk -F: '($3 == n) { print $1 }' n="$2" /etc/passwd | xargs)
		echo "Duplicate UID ($2): $users"
	fi
done
cut -f3 -d":" /etc/group | sort -n | uniq -c | while read -r x ; do
	[ -z "$x" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		groups=$(awk -F: '($3 == n) { print $1 }' n="$2" /etc/group | xargs)
		echo "Duplicate GID ($2): $groups"
	fi
done
cut -f1 -d":" /etc/passwd | sort -n | uniq -c | while read -r x ; do
	[ -z "$x" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		uids=$(awk -F: '($1 == n) { print $3 }' n="$2" /etc/passwd | xargs)
		echo "Duplicate User Name ($2): $uids"
	fi
done
cut -f1 -d":" /etc/group | sort -n | uniq -c | while read -r x ; do
	[ -z "$x" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		gids=$(gawk -F: '($1 == n) { print $3 }' n="$2" /etc/group | xargs)
		echo "Duplicate Group Name ($2): $gids"
	fi
done
# ------------------------------------------------------------------------------
log_info "Creating logging group and adding $ADMINUSER, blackteam"
groupadd logging
usermod -aG logging "$ADMINUSER"
usermod -aG logging blackteam

# ------------------------------------------------------------------------------
log_info "Resetting user passwords"
for user in $(getent passwd | cut -d: -f1 | sort | grep -v -e "$ADMINUSER" -e "blackteam" -e root); do
	if command -v apg >/dev/null; then
		pass=$(apg -n 1 -m 10 -x 12 -a 0 -M SNCL)
	else
		pass=$(dd if=/dev/urandom bs=1 count=9 2>/dev/null | base64)
	fi
	printf "%s:%s\n" "$user" "$pass"
	printf "%s:%s\n" "$user" "$pass" | chpasswd
done

# ------------------------------------------------------------------------------
log_info "Resetting $ADMINUSER password"
printf "%b" "$COLOR_BLUE"
while ! passwd "$ADMINUSER"; do
	printf "\nTry a different password\n"
done

# ------------------------------------------------------------------------------
log_info "Resetting root password"
printf "%b" "$COLOR_BLUE"
while ! passwd root; do
	printf "\nTry a different password\n"
done
printf "%b" "$COLOR_YELLOW"
usermod -g 0 root
passwd -l root # Need a root password set for single user mode, but don't allow logins otherwise

# ------------------------------------------------------------------------------
log_info "Setting permissions for home directories (recursive)"
allgroups=$(getent group | cut -d: -f1)
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do
	if [ ! -d "$dir" ]; then
		mkdir -p "$dir"
	fi
	if [ "$dir" != "/" ]; then
		if printf "%s" "$allgroups" | grep -q "$user" ; then
			chown "$user:$user" "$dir"
		else
			chown "$user:root" "$dir"
		fi
	fi
done
chmod go-rwx /home/*
chmod -R go-w /home/*
chmod -R go-rwx /root

# ------------------------------------------------------------------------------
log_info "Setting permissions for root directories (non-recursive)"
for dir in $(find / -maxdepth 1 -type d | grep -v "/tmp"); do
	chown root:root "$dir"
	chmod go-w "$dir"
done
chown root:logging /var/log
chmod 750 /var/log
chown root:root /boot /usr/src /lib/modules /usr/lib/modules
chmod 700 /boot /usr/src /lib/modules /usr/lib/modules
chown root:root /etc/passwd /etc/passwd- /etc/shadow /etc/shadow- /etc/group /etc/group- /etc/gshadow /etc/gshadow-
chmod 644 /etc/passwd /etc/passwd- /etc/group /etc/group-
chmod 600 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-

find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +

for c in /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly $(find /etc/cron.d -type f) ; do
	if [ -e "$c" ] ; then
	    chown root:root "$c"
	    chmod 700 "$c"
	fi
done

# Set sticky bit on world-writable directories
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

# ------------------------------------------------------------------------------
log_info "Setting default umask"
printf "umask 0077\n" >> /etc/profile
printf "umask 0077\n" >> /etc/bashrc

# ------------------------------------------------------------------------------
if command -v sshd >/dev/null; then
	log_info "Configuring ssh"
	log_info "  Setting ssh config"
	cat <<-EOF > /etc/ssh/sshd_config
	Protocol 2
	IgnoreRhosts yes
	LogLevel VERBOSE

	PermitRootLogin no
	#MaxAuthTries 3
	#PubkeyAuthentication yes
	AuthorizedKeysFile	.ssh/authorized_keys
	PasswordAuthentication yes
	PermitEmptyPasswords no
	ClientAliveInterval 300
	ClientAliveCountMax 0
	LoginGraceTime 60
	MaxStartups 10:30:60
	MaxSessions 10

	UsePAM yes
	UseDNS no

	AllowAgentForwarding no
	AllowTcpForwarding no
	X11Forwarding no
	PermitTunnel no
	PermitUserEnvironment no

	HostbasedAuthentication no

	Banner /etc/issue
	PrintMotd yes

	# override default of no subsystems
	Subsystem	sftp	/usr/lib/openssh/sftp-server

	Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
	MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
	KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

	Match User blackteam
		PasswordAuthentication yes

	AllowUsers $ADMINUSER blackteam
	EOF

	log_info "  Setting login banner and motd"
	cat <<-"EOF" > /etc/issue
	UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED
	 You must have explicit, authorized permission to access or configure this device.
	 Unauthorized attempts and actions to access or use this system may result in civil and/or
	 criminal penalties.
	 All activities performed on this device are logged and monitored.
	EOF
	cat <<-"EOF" > /etc/motd
	  Welcome! All activities performed on this device are logged and monitored.
	EOF
	chmod 444 /etc/issue /etc/motd


	log_info "  Regenerating ssh host keys"
	find /etc/ssh/ -name "ssh_host_*" -exec rm {} +
	ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
	ssh-keygen -t ed25519 -b 4096 -f /etc/ssh/ssh_host_ed25519_key -N ""

	log_info "  Removing small moduli for Diffie-Hellman"
	awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
	mv /etc/ssh/moduli.safe /etc/ssh/moduli

	log_info "  Setting permissions for ssh directory"
	chown -R root:root /etc/ssh
	chmod -R go-wx /etc/ssh
	if [ -d "/usr/share/empty.sshd" ]; then
		chown root:root /usr/share/empty.sshd
		chmod go-wx /usr/share/empty.sshd
	fi

	log_info "  Restarting ssh"
	systemctl restart sshd
fi

# ------------------------------------------------------------------------------
log_info "Updating packages for listening services"
processes=$(ss -lntup | cut -s -d"(" -f3 | cut -d'"' -f2 | sort -u)
printf "Processes:\n%s\n" "$processes"
if [ "$DISTRO" = "debian" ]; then
	packages=$(for process in $processes ; do
		ppath=$(realpath "$(command -v "$process")") >/dev/null
		dpkg -S "$ppath" | cut -d: -f1
	done)
    if printf "%s\n" "$packages" | grep -q "[[:graph:]]"; then
        printf "Updating:\n%s\n" "$packages"
        apt-get update
        apt-get upgrade -y $packages
    fi
elif [ "$DISTRO" = "fedora" ]; then
	packages=$(for process in $processes ; do
		ppath=$(command -v $process) >/dev/null
		rpm -qf "$ppath"
	done)
    if printf "%s\n" "$packages" | grep -q "[[:graph:]]"; then
        printf "Updating:\n%s\n" "$packages"
        dnf update --color=never -y $packages
    fi
fi

# ------------------------------------------------------------------------------
log_info "Configuring syslog"
if [ "$DISTRO" = "debian" ]; then
	apt-get install -y rsyslog
elif [ "$DISTRO" = "fedora" ]; then
	dnf install --color=never -y rsyslog
fi

# Journald send to syslog
sed -i 's/^ForwardToSyslog.*/ForwardToSyslog=yes/' /etc/systemd/journald.conf
if ! grep -q "^ForwardToSyslog=yes" /etc/systemd/journald.conf ; then
	printf "ForwardToSyslog=yes\n" >> /etc/systemd/journald.conf
fi

systemctl enable --now rsyslog

# ------------------------------------------------------------------------------
log_info "Installing auditd"
if [ "$DISTRO" = "debian" ]; then
	apt-get install -y auditd
elif [ "$DISTRO" = "fedora" ]; then
	dnf install --color=never -y audit
fi
systemctl enable --now auditd
mkdir -p /etc/audit/audit.rules.d
cp ./configs/audit.rules /etc/audit/rules.d/audit.rules
auditctl -R /etc/audit/rules.d/audit.rules
service auditd reload
if [ "$DISTRO" = "debian" ]; then
	systemctl restart auditd
elif [ "$DISTRO" = "fedora" ]; then
	service auditd restart
fi


# ------------------------------------------------------------------------------
log_info "Set new firewall rules to allow service access"
log_info "  Firewall help text:"
printf "%s\n" "$(./firewall.sh -h | sed 's/^/  /')"

log_info "  Listening services:"
printf "%s\n" "$(ss -lntup | sed 's/^/  /')"

log_info "  Current rules:"
printf "  -y d drop %s\n" "$rules"

printf "\n  %bEnter new rules (on one line, will be appended):\n  " "$COLOR_BLUE"
read -r newrules
rules="$rules $newrules"
log_info "  Applying new rules"
printf "  ./firewall.sh -y -p -d drop %s\n" "$rules"
printf "%b" "$COLOR_NONE"
./firewall.sh -y -b -p -d drop $rules

# ------------------------------------------------------------------------------
log_info "Updating all packages"
if [ "$DISTRO" = "debian" ]; then
	apt-get update
	apt-get upgrade -y
elif [ "$DISTRO" = "fedora" ]; then
	dnf update --color=never -y
fi

# ------------------------------------------------------------------------------
log_info "Disabling autofs"
systemctl disable autofs

# ------------------------------------------------------------------------------
usingsysctl=$(prompt_yn "Configure sysctl? - will probably break things")
if [ "$usingsysctl" = "y" ]; then
	# ------------------------------------------------------------------------------
	log_info "  Setting up kernel protection"
	mkdir -p /etc/sysctl.conf.d
	cat <<-"EOF" > /etc/sysctl.conf.d/kernel-protect.conf
	kernel.kptr_restrict = 1
	kernel.dmesg_restrict = 1
	kernel.unprivileged_bpf_disabled = 1
	net.core.bpf_jit_harden = 2
	dev.tty.lsdisc_autoload = 0
	vm.unprivileged_userfaultfd = 0
	kernel.kexec_load_disabled = 1
	kernel.sysrq = 4
	vm.swappiness = 1
	EOF

	# ------------------------------------------------------------------------------
	log_info "  Disabling uncommon kernel modules"
	mkdir -p /etc/modprobe.d
	cat <<-"EOF" > /etc/modprobe.d/blacklist.conf
	# Uncommon networking protocols
	install dccp /bin/false
	install sctp /bin/false
	install rds /bin/false
	install tipc /bin/false
	install n-hdlc /bin/false
	install ax25 /bin/false
	install netrom /bin/false
	install x25 /bin/false
	install rose /bin/false
	install decnet /bin/false
	install econet /bin/false
	install af_802154 /bin/false
	install ipx /bin/false
	install appletalk /bin/false
	install psnap /bin/false
	install p8023 /bin/false
	install p8022 /bin/false
	install can /bin/false
	install atm /bin/false
	# Uncommon filesystems
	install cramfs /bin/false
	install freevxfs /bin/false
	install jffs2 /bin/false
	install hfs /bin/false
	install hfsplus /bin/false
	install squashfs /bin/false
	install udf /bin/false
	# Testing driver
	install vivid /bin/false
	# Bluetooth
	install bluetooth /bin/false
	install btusb /bin/false
	EOF

	log_info "  Regenerating initramfs"
	if [ "$DISTRO" = "debian" ]; then
		update-initramfs -u
	elif [ "$DISTRO" = "fedora" ]; then
		nohup dracut --regenerate-all --force &
		log_info "  initramfs generation will take a while. Backgrounded with pid $!"
	fi
	sleep 2

	# ------------------------------------------------------------------------------
	log_info "  Configuring network stack"
	cat <<-"EOF" > /etc/sysctl.conf.d/network-stack.conf
	net.ipv4.conf.all.arp_ignore = 1
	net.ipv4.conf.all.arp_announce = 1
	net.ipv4.conf.all.accept_redirects = 0
	net.ipv4.conf.all.accept_source_route = 0
	net.ipv4.conf.all.send_redirects = 0
	net.ipv4.conf.all.secure_redirects = 0
	net.ipv4.conf.all.log_martians = 1
	net.ipv4.conf.all.rp_filter = 1
	net.ipv4.conf.all.secure_redirects = 0
	net.ipv4.conf.default.accept_source_route = 0
	net.ipv4.conf.default.accept_redirects = 0
	net.ipv4.conf.default.accept_source_route = 0
	net.ipv4.conf.default.send_redirects = 0
	net.ipv4.conf.default.log_martians = 1
	net.ipv4.conf.default.rp_filter = 1
	net.ipv4.conf.default.secure_redirects = 0
	net.ipv4.icmp_echo_ignore_broadcasts = 0
	net.ipv4.icmp_ignore_bogus_error_responses = 1
	net.ipv4.icmp_ratelimit = 100
	net.ipv4.icmp_ratemask = 88089
	net.ipv4.tcp_fin_timeout = 30
	net.ipv4.tcp_syncookies = 1
	net.ipv4.tcp_timestamps = 0
	net.ipv4.tcp_rfc1337 = 1
	net.ipv4.tcp_sack = 0
	net.ipv4.tcp_dsack = 0
	net.ipv4.tcp_fack = 0
	net.ipv6.conf.all.accept_ra = 0
	net.ipv6.conf.all.accept_redirects = 0
	net.ipv6.conf.all.accept_source_route = 0
	net.ipv6.conf.default.accept_ra = 0
	net.ipv6.conf.default.accept_redirects = 0
	net.ipv6.conf.default.accept_source_route = 0
	EOF

	# ------------------------------------------------------------------------------
	log_info "  Increasing limits"
	cat <<-"EOF" > /etc/sysctl.conf.d/limits.conf
	fs.file-max=100000
	EOF

	# ------------------------------------------------------------------------------
	log_info "  Enabling user space protections"
	printf "kernel.randomize_va_space = 2\n" > /etc/sysctl.conf.d/va_randomize.conf
	cat <<-"EOF" > /etc/sysctl.conf.d/user-space.conf
	kernel.yama.ptrace_scope = 2
	vm.mmap_rnd_bits = 32
	vm.mmap_rnd_compat_bits = 16
	fs.protected_symlinks = 1
	fs.protected_hardlinks = 1
	fs.protected_fifos = 2
	fs.protected_regular = 2
	EOF
fi

# ------------------------------------------------------------------------------
#log_info "Changing boot parameters"
# kernel protection:
#   slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off module.sig_enforce=1 lockdown=confidentiality quiet loglevel=0
#   oops=panic
# CPU mitigations:
#   spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force
# Auditd:
#   audit=1
# Selinux:
#   selinux=1 security=selinux enforcing=1
# Protect against DMA:
#   intel_iommu=on amd_iommu=on efi=disable_early_pci_dma

# grub2-setpassword
# grub-mkconfig -o $path_to_grub_config
# update-grub
#log_error "Not yet implemented"

# ------------------------------------------------------------------------------
log_info "Hiding hardware info"
./hide-hardware.sh

# ------------------------------------------------------------------------------
log_info "Disabling services"
if [ -e "/etc/inetd.conf" -o -d "/etc/inetd.d" ]; then
	inetd_services="chargen daytime echo time shell login exec talk ntalk telnet tftpd"
	needinetd=$(prompt_yn "  Do you need any of these inetd services?: $inetd_services")
	if [ "$needinetd" = "y" ] && [ -e "/etc/inetd.conf" -o -d "/etc/inetd.d" ]; then
		for service in $inetd_services; do
			needservice=$(prompt_yn "  Do you need $service?")
			if [ "$needservice" = "n" ] ; then
				printf "%b" "$COLOR_YELLOW"
				find /etc/inetd.conf /etc/inetd.d -type f -exec sed -i "s/^\($service.*\)/#\1/" {} +
			fi
		done
	else
		for service in $inetd_services; do
			find /etc/inetd.conf /etc/inetd.d -type f -exec sed -i "s/^\($service.*\)/#\1/" {} +
		done
		systemctl disable --now inetd
	fi
fi

possible_services="xinetd avahi-daemon cups dhcpd dnsmasq ldap nfs rpcbind named vsftpd httpd apache2 lighttpd nginx dovecot smb squid snmpd rsyncd ypserv"
for service in $possible_services ; do
	if systemctl list-unit-files "${service}*" | grep -q "enabled" ; then
		system_services="$system_services $service"
	fi
done
needsystem=$(prompt_yn "  Do you need any of these system services?: $system_services")
if [ "$needsystem" = "y" ]; then
	for service in $system_services; do
		needservice=$(prompt_yn "  Do you need $service?")
		if [ "$needservice" = "n" ]; then
			printf "%b" "$COLOR_YELLOW"
			for unit in $(systemctl list-unit-files "${service}*" | grep enabled | cut -d" " -f1); do 
				systemctl disable --now "$unit"
			done
		fi
	done
else
	for service in $system_services; do
		systemctl disable --now "$service"
	done
fi

# ------------------------------------------------------------------------------
log_info "Configuring Apache"
configureapache=$(prompt_yn "Configure apache?")
if [ "$configureapache" = "y" ]; then
	if [ "$DISTRO" = "debian" ]; then
		apacheowner="www-data"
		apachegroup="www-data"
		apachecmd="apache2"
		apachedir="/etc/apache2"
	elif [ "$DISTRO" = "fedora" ]; then
		apacheowner="apache"
		apachegroup="apache"
		apachecmd="httpd"
		apachedir="/etc/httpd"
	fi
	if ! command -v "$apachecmd" >/dev/null; then
		log_error "Apache not found"
	else
		if [ "$(ps -U root | grep -qF "$apachecmd" | wc -l)" -gt 1 ] ; then
			log_error "More than one root process running apache"
		fi
		log_info "  Setting config dir permissions"
		chown -R "root:${apachegroup}" "$apachedir"
		find "$apachedir" -type d -exec chmod 750 {} +
		find "$apachedir" -type f -exec chmod 640 {} +

		log_info "  Setting server response"
        find "$apachedir" -type f -exec sed -i 's/^ServerTokens.*/ServerTokens Prod/' {} +
        find "$apachedir" -type f -exec sed -i 's/^ServerSignature.*/ServerSignature Off/' {} +

		log_info "  Disabling trace requests"
        find "$apachedir" -type f -exec sed -i 's/^TraceEnable.*/TraceEnable Off/' {} +

		log_info "  Listing web root directories"
		directoryfiles=$(find "$apachedir" -type f -exec grep -l "<Directory" {} +)
		printf "    %bFiles containing \"<Directory path>\"\n%b%s\n" "$COLOR_NONE" "$COLOR_YELLOW" "$(printf "%s" "$directoryfiles" | sed 's/^/     /')"
		sections=$(for file in $directoryfiles ; do
			output=0
			cat "$file" | while read -r line; do
				line=$(printf "%s" "$line" | grep -v -e "^[[:blank:]]*$" -e "^[[:blank:]]*#")
				if echo "$line" | grep -q "<Directory"; then
					output=1
				elif echo "$line" | grep -q "</Directory"; then
					output=0
					printf "\n"
				fi
				if [ $output -eq 1 ]; then
					printf "%s " "$line"
				fi
			done
		done)
		apachewebdirs=$(printf "%s" "$sections" | grep -v -e "^[[:blank:]]*#" -e "Require all denied" | cut -d">" -f1 | cut -d"<" -f2 | sed 's/"//g' | cut -d" " -f2-)
		printf "    %bWeb root directories\n%b%s\n" "$COLOR_NONE" "$COLOR_YELLOW" "$(printf "%s" "$apachewebdirs" | sed 's/^/     /')"
		sleep 3

		log_info "  Listing files/directories that may be writable (or owned) by $apacheowner in web directories"
		find $apachewebdirs ! -type l \( -user "$apacheowner" -o -group "$apachegroup" -o -perm -o+w \) -exec ls -ld {} +

		log_info "  Listing .ht* files"
		find $apachewebdirs -name ".ht*" -exec ls -ld {} +

		log_info "  Installing mod-security with recommended configuration"
		if [ "$DISTRO" = "debian" ]; then
			apt-get install -y libapache2-mod-security2 modsecurity-crs
			cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
			sed -i 's/^SecRuleEngine.*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
		elif [ "$DISTRO" = "fedora" ]; then
			dnf install --color=never -y mod_security mod_security_crs
			cp /etc/httpd/conf.d/mod_security.conf /etc/httpd/conf.modules.d/00-mod_security.conf
			sed -i 's/^SecRuleEngine.*/SecRuleEngine On/' /etc/httpd/conf.modules.d/00-mod_security.conf
		fi

		sandboxapache=$(prompt_yn "Sandbox apache? - may break things")
		if [ "$sandboxapache" = "y" ]; then
			if [ "$DISTRO" = "debian" ]; then
				exampleconf="profiles/apache2-override.conf"
				apachesystemdconf="/etc/systemd/system/apache2.service.d/override.conf"
			elif [ "$DISTRO" = "fedora" ]; then
				exampleconf="profiles/httpd-override.conf"
				apachesystemdconf="/etc/systemd/system/httpd.service.d/override.conf"
			fi

			printf "%b  Directories you may want to allow:\n%b%s\n" "$COLOR_NONE" "$COLOR_YELLOW" "$(printf "%s" "$apachewebdirs" | sed 's/^/    /')"
			log_info "  Editing systemd service override. Make sure all necessary directories are allowed. Press enter to start editing"
			mkdir -p "$(dirname "$apachesystemdconf")"
			cp "$exampleconf" "$apachesystemdconf"
			read -r ignored
			SERVICE="$apachecmd" ./sandbox.sh
			systemctl daemon-reload
		fi

		log_info "  Restarting apache"
		if ! systemctl restart "$apachecmd" ; then
			systemctl status --no-pager "$apachecmd"
		fi
	fi
fi

# ------------------------------------------------------------------------------
log_info "Configuring Nginx"
configurenginx=$(prompt_yn "Configure nginx?")
if [ "$configurenginx" = "y" ]; then
	if [ "$(ps -U root | grep -qF nginx | wc -l)" -gt 1 ] ; then
		log_error "More than one root process running nginx"
	fi
	log_info "  Setting config dir permissions"
	find /etc/nginx -type d -exec chmod 750 {} +
	find /etc/nginx -type f -exec chmod 640 {} +

	log_info "  Setting server response"
	log_error "Not yet implemented"

	log_info "  Disabling trace requests"
	log_error "Not yet implemented"

	log_info "  Listing web root directories"
	log_error "Not yet implemented"

	log_info "  Installing mod-security with recommended configuration"
	if [ "$DISTRO" = "debian" ]; then
		if apt-get install -y libnginx-mod-http-modsecurity ; then
			cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
			sed -i 's/^SecRuleEngine.*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
		else
			log_error "Couldn't install modsecurity for nginx"
		fi
	elif [ "$DISTRO" = "fedora" ]; then
		if ! dnf install --color=never -y nginx-mod-modsecurity ; then
			log_error "Couldn't install modsecurity for nginx"
		fi
	fi

	sandboxnginx=$(prompt_yn "  Sandbox nginx? - may break things")
	if [ "$sandboxnginx" = "y" ]; then
		exampleconf="profiles/nginx-override.conf"
		nginxsystemdconf="/etc/systemd/system/nginx.service.d/override.conf"

		printf "%b  Directories you may want to allow:\n%b%s\n" "$COLOR_NONE" "$COLOR_YELLOW" "$(printf "%s" "$nginxwebdirs" | sed 's/^/    /')"
		log_error "Not yet implemented"
		log_info "  Editing systemd service override. Make sure all necessary directories are allowed. Press enter to start editing"
		mkdir -p "$(dirname "$nginxsystemdconf")"
		cp "$exampleconf" "$nginxsystemdconf"
		read -r ignored
		SERVICE=nginx ./sandbox.sh
		systemctl daemon-reload
	fi

	log_info "  Restarting nginx"
	if ! systemctl restart nginx ; then
		systemctl status --no-pager nginx
	fi
fi

# ------------------------------------------------------------------------------
log_info "Installing usbguard"
if [ "$DISTRO" = "debian" ]; then
	apt-get install -y usbguard
elif [ "$DISTRO" = "fedora" ]; then
	dnf install --color=never -y usbguard
fi
log_info "Preparing usbguard rules. Plug in all needed usb devices, then press enter to continue"
read -r usbcontinue
usbguard generate-policy > /etc/usbguard/rules.conf
log_info "Enabling usbguard. To allow new usb devices, connect the device and run \"usbguard list-devices\", then \"usbguard allow-device <number>\""
systemctl enable --now usbguard

# ------------------------------------------------------------------------------
log_info "Installing aide"
if command -v prelink >/dev/null; then
	prelink -ua;
fi
if [ "$DISTRO" = "debian" ]; then
	apt-get remove -y prelink 2>/dev/null
	apt-get install -y aide
    aidepath="/usr/bin/aide"
elif [ "$DISTRO" = "fedora" ]; then
	dnf remove --color=never -y prelink 2>/dev/null
	dnf install --color=never -y aide
    aidepath="/usr/sbin/aide"
fi

cat <<-EOF > /etc/systemd/system/aidecheck.service
[Unit]
Description=Aide Check

[Service]
Type=simple
ExecStart=$path --check --config /etc/aide/aide.conf

[Install]
WantedBy=multi-user.targeaideinit
EOF

cat <<-"EOF" > /etc/systemd/system/aidecheck.timer
[Unit]
Description=Aide check every hour

[Timer]
OnCalendar=*:0
Unit=aidecheck.service

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/aidecheck.*

if [ ! -d /etc/aide -o ! -d /etc/aide/aide.conf ]; then
	mkdir -p /etc/aide
	cp ./configs/aide.conf /etc/aide/aide.conf
	chown -R root:root /etc/aide
	chmod -R 640 /etc/aide
fi

log_info "  Initializing aide (will take a while)"
if [ "$DISTRO" = "debian" ]; then
	aideinit
elif [ "$DISTRO" = "fedora" ]; then
	aide --init
fi
cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

systemctl enable --now aidecheck.timer
systemctl daemon-reload

# ------------------------------------------------------------------------------
printf "%b\n#############\nManual review\n#############\n%b" "$COLOR_BLUE" "$COLOR_NONE"
log_info "Verifying installed packages"
verifypackages=$(prompt_yn "Verify packages? This will take a while. Find the output in package-verify.txt.")
if [ "$verifypackages" = "y" ]; then
	cat <<-"EOF" > package-verify.txt
	# Verify Code Meaning
	# S    File size differs.
	# M    File mode differs (includes permissions and file type).
	# 5    The MD5 checksum differs.
	# D    The major and minor version numbers differ on a device file.
	# L    A mismatch occurs in a link.
	# U    The file ownership differs.
	# G    The file group owner differs.
	# T    The file time (mtime) differs.
	EOF

	if [ "$DISTRO" = "debian" ]; then
		nohup dpkg --verify >> package-verify.txt &
	elif [ "$DISTRO" = "fedora" ]; then
		nohup rpm -Va --nomtime --nosize --nomd5 --nolinkto >> package-verify.txt &
	fi
fi

# ------------------------------------------------------------------------------
log_info "Diffing current state with original state"
sleep 2
ps -p $$ > info/shellpid-after
ps eaf --forest > info/processes-after
who -a > info/who-after
ss -ntup > info/outbound_connections-after
ss -lntup > info/inbound_connections-after
last -aFix > info/last-after
systemctl -l --all > info/systemctl_list-after
cat /etc/hosts > info/etc_hosts-after
for f in $(ls -1 info | cut -d- -f1 | sort -u); do
	printf "%b%s%b\n" "$COLOR_YELLOW" "$f" "$COLOR_NONE"
	diff --color "info/$f" "info/${f}-after"
done
sleep 5

log_info "Listing root processes"
sleep 2
ps -fu root

log_info "Listing world-writable files and directories"
find / -perm -o+w ! -path "/proc/*" ! -path "/dev/*" ! -path "/tmp*" ! -path "/var/tmp*" ! -type l -exec ls -l {} + 2>/dev/null

log_info "Listing suid and sgid files"
gtfobins_suid="aa-exec ab agetty alpine ar arj arp as ascii-xfr ash aspell atobm awk base32 base64 basenc basez bash bc bridge busctl busybox bzip2 cabal capsh cat chmod choom chown chroot clamscan cmp column comm cp cpio cpulimit csh csplit csvtool cupsfilter curl cut dash date dd debugfs dialog diff dig distcc dmsetup docker dosbox ed efax elvish emacs env eqn espeak expand expect file find fish flock fmt fold gawk gcore gdb genie genisoimage gimp grep gtester gzip hd head hexdump highlight hping3 iconv install ionice ip ispell jjs join jq jrunscript julia ksh ksshell kubectl ld.so less logsave look lua make mawk minicom more mosquitto msgattrib msgcat msgconv msgfilter msgmerge msguniq multitime mv nasm nawk ncftp nft nice nl nm nmap node nohup ntpdate od openssl openvpn pandoc paste perf perl pexec pg php pidstat pr ptx python rc readelf restic rev rlwrap rsync rtorrent run-parts rview rvim sash scanmem sed setarch setfacl setlock shuf soelim softlimit sort sqlite3 ss ssh-agent ssh-keygen ssh-keyscan sshpass start-stop-daemon stdbuf strace strings sysctl systemctl tac tail taskset tbl tclsh tee terraform tftp tic time timeout troff ul unexpand uniq unshare unsquashfs unzip update-alternatives uudecode uuencode vagrant varnishncsa view vigr vim vimdiff vipw w3m watch wc wget whiptail xargs xdotool xmodmap xmore xxd xz yash zsh zsoelim"

files_suid_sgid=$(find / -type f -perm -2000 -o -perm -4000  2>/dev/null)

for bin in $files_suid_sgid; do
	binname=$(basename "$bin")
	for gtfobin in $gtfobins_suid; do
		if [ "$binname" = "$gtfobin" ]; then
			printf "%b%s%b\n" "$COLOR_RED" "$(ls -l "$bin")" "$COLOR_YELLOW"
			continue 2
		fi
	done
	printf "%s\n" "$(ls -l "$bin")"
done

printf "%b" "$COLOR_NONE"
