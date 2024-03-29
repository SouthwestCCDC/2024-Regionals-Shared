#!/bin/bash
# Competitions:
#	- Hivestorm 2020-2021 
#	- Southwest CCDC Regionals 2022-2024

# Text Colors
HEADER='\e[1m'
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PURPLE='\033[1;35m'

# Prettify output
function notify() { echo -e "${YELLOW}[!]${NC} $1" ; }
function error() { echo -e "${RED}[-]${NC} $1" ; }
function success() { echo -e "${GREEN}[+]${NC} $1" ; }
function header() { echo -e "${HEADER}$1${NC}" ; }
function heart() { echo -e "${PURPLE}[<3]${NC} $1" ; }

if [ "$EUID" -ne 0 ]
    then echo "Please run as root!"
    exit 1
fi

CURRENT_USER=$(whoami)
echo
header "Linux Lockdown Script"
echo "Authors.......: TNAR5, colonket, ferdinand"
echo "Version.......: 1.3"
echo "OS............: $(cat /etc/os-release | awk -F= '/PRETTY_NAME/ {print $2}')"
echo "Executing as user: $CURRENT_USER"

function command_exists() {
    command -v "$1" >/dev/null 2>&1
}

if command_exists apt-get; then
    DISTRIBUTION="debian"
elif command_exists yum; then
    DISTRIBUTION="redhat"
elif command_exists apk; then
	DISTRIBUTION="alpine"
elif command_exists pkg; then
	DISTRIBUTION="freebsd"
else
    DISTRIBUTION="unsupported"
fi

echo -n "Detected Linux distribution flavor: "
case $DISTRIBUTION in
    "debian")
        echo "Debian"
        ;;
    "redhat")
        echo "Red Hat"
        ;;
	"alpine")
		echo "Alpine"
		;;
	"freebsd")
		echo "FreeBSD"
		;;
    "unsupported")
        echo "Unsupported or unknown distribution flavor."
		read -p "[?] Are you sure you want to continue? [y/N]" -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]];then
			success "Continuing at your own risk."
		else
			error "Exiting."
			exit 1
		fi	
        ;;
esac

printf "\n\n"

function readme_prompt()
{
    read -p "[?] Have you read the README and the Forensics Questions? (Hivestorm) [y/N]" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]];then
        heart "Thank you for your compliance!" 
        echo
    else
        error "Please read the files on the desktop to make sure that the script is not messing with anything essential."
        exit 1
	fi
}

function choose_editor()
{
	#TODO - compatibility issues
	header "\nChoose Text Editor"
	read -p "[?] Do you want to choose your text editor? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		update-alternatives --config editor
	fi
}

# Offline - Modify SSH config
function ssh_lockdown()
{
	header "\nSSH Lockdown"
	# TODO - dropbear compatibility?
	if ps aux | grep "[s]shd"; then
		success "OpenSSH server is running."
		    read -p "[?] Secure SSH config? (Warning: do not run if this SSH service is scored) [y/N]" -n 1 -r
    		echo
			if [[ $REPLY =~ ^[Yy]$ ]]
			then
				cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
				printf "Port 22\nPermitRootLogin prohibit-password\nListenAddress 0.0.0.0\nAuthorizedKeysFile\t.ssh/authorized_keys\nMaxAuthTries 3\nPubkeyAuthentication yes\nPasswordAuthentication yes\nPermitEmptyPasswords no\nUsePAM yes\nPrintMotd yes\nAcceptEnv LANG LC_*\nSubsystem\tsftp\tinternal-sftp" > /etc/ssh/sshd_config
				echo "Restarting SSH service..."
				service sshd restart
			fi
	else
		error "OpenSSH server is not running? (could be Dropbear SSH or other)"
	fi
}

# Offline - Modify kernel
function kernel_lockdown()
{
	header "\nKernel Lockdown"
	if [[ $DISTRIBUTION == "freebsd" ]]
	then
		error "Skipping - FreeBSD kernel parameters unsupported" # TODO
	else
	read -p "[?] Secure kernel config? [y/N] " -n 1 -r
	echo 
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			success "Enabling secure kernel options."
			cp -n /etc/sysctl.conf /etc/sysctl.conf.bak
			printf "kernel.core_uses_pid=1\nkernel.randomize_va_space=2\nkernel.sysrq=0\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\nnet.ipv4.conf.all.log_martians=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.default.rp_filter=1\nnet.ipv4.icmp_echo_ignore_broadcasts=1\nnet.ipv4.ip_forward=0\nnet.ipv4.tcp_syncookies=1\nnet.ipv6.conf.all.accept_redirects=0\nnet.ipv6.conf.all.accept_source_route=0\nnet.ipv6.conf.all.disable_ipv6=0\nnet.ipv6.conf.default.disable_ipv6=0\nnet.ipv6.conf.lo.disable_ipv6=1" > /etc/sysctl.conf
			#sysctl -w kernel.randomize_va_space=2 >/dev/null;sysctl -w net.ipv4.conf.default.rp_filter=1>/dev/null;sysctl -w net.ipv4.conf.all.rp_filter=1>/dev/null;sysctl -w net.ipv4.tcp_syncookies=1>/dev/null;sysctl -w net.ipv4.ip_forward=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.send_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv4.conf.all.log_martians=1>/dev/null;
			sysctl -p 
		fi
	fi
}

# Offline - Modify users and sudoers
function user_lockdown()
{
	header "\nUser Lockdown"
	read -p "[?] Do you want to create a c6 admin user (CCDC)? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		success "Creating c6 admin user."
		if [[ $DISTRIBUTION == "alpine" ]]
		then
			addgroup "wheel"
			addgroup "sudo"
			adduser "c6" # already includes passwd (set password)
			adduser "c6" "wheel"
			adduser "c6" "sudo"
			notify "Confirm groups for c6:"
			groups "c6"
		elif [[ $DISTRIBUTION == "freebsd" ]]
		then
			pw group add "wheel"
			pw group add "sudo"
			pw user add "c6"
			pw usermod "c6" -G "wheel,sudo"
			notify "Confirm groups for c6:"
			groups "c6"
			passwd "c6"
		elif [[ $DISTRIBUTION == "redhat" ]]
		then
			groupadd "wheel"
			groupadd "sudo" # not necessary?
			adduser "c6"
			usermod -aG wheel c6
			usermod -aG sudo c6 # not necessary?
			notify "Confirm groups for c6:"
			groups "c6"
			passwd "c6"
		elif [[ $DISTRIBUTION == "debian" ]]
		then
			groupadd "admin"
			groupadd "sudo"
			adduser "c6"  # already includes passwd (set password)
			adduser "c6" "admin"
			adduser "c6" "sudo"
			notify "Confirm groups for c6:"
			groups "c6"
		else
			error "Unsupported for now. Please add the user manually after script execution."
		fi
	fi

	read -p "[?] Do you want to lockdown human users? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		notify "Starting interactive user lockdown."
		success "Backup user list $HOME/users.txt"
		users=($(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd))
		
		printf "%s\n" "${users[@]}" > "$HOME/users.txt"
		success "Found ${#users[@]} human users."
		echo

		#password="changeMe!123"
		#read -p "[?] HIVESTORM COMPETITION ONLY Do you want to set every users password to '$password'? [y/N]" -n 1 -r
		#echo
		#if [[ $REPLY =~ ^[Yy]$ ]]
		#then
		#	for u in "${users[@]}"
		#	do
		#		# passwd asks to enter new password twice
		#		echo -e "$password\n$password" | passwd $u
		#		success "Changed user $u's password to $password"
		#		echo
		#	done
		#fi

		for u in "${users[@]}"
		do
			read -p "[?] Modify user $u ? [y/N]" -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ ]]
			then
				header "$u"
				read -p "[?] DELETE user $u ? [y/N] " -n 1 -r
				echo
				if [[ $REPLY =~ ^[Yy]$ ]]
				then
                    if [[ $u == "$SUDO_USER" ]]
					then
                        error "You are $u, cannot remove yourself!"
					else
						if [[ $DISTRIBUTION == "alpine" ]]
						then
							deluser "$u"
							delgroup "$u"
						elif [[ $DISTRIBUTION == "freebsd" ]]
						then
							pw user del "$u"
							pw group del "$u"
						else
							userdel "$u"
							groupdel "$u"
						fi
						success "$u has been removed."
					fi
				else
					read -p "[?] CHANGE $u's password? [y/N]" -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]
					then
						passwd "$u"
					else
						success "Did not change $u's password"
					fi
					
					read -p "[?] LOCK $u's account to prevent login? [y/N]" -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]
					then
						if [[ $DISTRIBUTION == "freebsd" ]]
						then
							pw lock "$u"
						else
							passwd -l "$u"
						fi
					else
						success "Did not lock $u's account"
					fi
				fi
			fi
		done
	fi
	header "\nSudoers lockdown"
	echo -e " - Delete 'ALL ALL=(ALL) NOPASSWD: ALL' and 'ALL ALL=(ALL) ALL' \n - Keep 'root ALL=(ALL) ALL' \n - Uncomment (remove #) lines with sudo, admin, wheel groups that DON'T have NOPASSWD \n - NOPASSWD IS BAD!"
	read -p "[?] Do you want to check the sudoers file? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		if [[ $DISTRIBUTION == "freebsd" ]]
		then
			cp -n /usr/local/etc/sudoers /usr/local/etc/sudoers.bak
		else
        	cp -n /etc/sudoers /etc/sudoers.bak
		fi
		read -p "[?] Press any key to check sudoers." -n 1 -r
		echo
		visudo
	fi
	printf "\n"
}

# Offline - Modify Configs
function check_configs()
{
	header "\nCheck Configs"
	read -p "[?] Would you like to secure config files? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		if ! grep -qF "nospoof on" "/etc/hosts"; then
			echo "nospoof on" >> "/etc/hosts"
		fi
		sudoedit /etc/hosts
		sudoedit /etc/crontab
		echo "The following users have active crontabs:"
		ls /var/spool/cron/crontabs
		echo
		echo "[!] Make sure to set lightdm guest to false and if asked to, disable auto-login. (allow-guest=False)"
		read -p "[?] Press any key to check /etc/lightdm/lightdm.conf" -n 1 -r
		echo
		if ! grep -qF "allow-guest=False" "/etc/lightdm/lightdm.conf"; then
			echo "allow-guest=False" >> "/etc/lightdm/lightdm.conf"
		fi
		sudoedit /etc/lightdm/lightdm.conf
		printf "\n"
		success "Finish config editing."
	fi
}

# Offline - Remove packages
function check_bad_programs()
{
	header  "\nChecking for 'bad' programs."

	declare -a bad=(
		"nmap"
		"john"
		"rainbowcrack"
		"ophcrack"
		"nc"
		"netcat"
		"hashcat"
		"telnet"
		"wireshark"
	)

	declare -a possibly_bad=(
		"samba"
		"bind9"
		"vsftpd"
		"apache2"
		"nginx"
		"telnet"
	)

	# Remove bad programs
	for b in "${bad[@]}"
	do
		if dpkg --get-selections | grep -q "^${b}[[:space:]]*install$" >/dev/null;then
			notify "${b} is installed, removing."
			apt-get purge -y "$b"
		fi
	done
	apt-get purge netcat*   # Removes any alternative netcat packages

	# Notify of any bad programs that may be a required service
	for pb in "${possibly_bad[@]}"
	do
		if dpkg --get-selections | grep -q "^$pb[[:space:]]*install$" >/dev/null;then
			notify "$pb is installed, remove/disable if not a required service."
		fi
	done
}

function check_services()
{
	header "\nChecking Services and Ports"
	read -p "[?] List enabled services? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		success "Displaying enabled services:"
		if [[ $DISTRIBUTION == "alpine" ]]
		then
			rc-status
		elif [[ $DISTRIBUTION == "freebsd" ]]
		then
			service -e
		else
			systemctl list-units --type=service --state=running
		fi
	fi
	echo

	read -p "[?] List active listening ports [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		success "Displaying active listening ports:"
		if [[ $DISTRIBUTION == "alpine" ]]
		then
			netstat -tulnp
		elif [[ $DISTRIBUTION == "freebsd" ]]
		then
			sockstat -l
		else
			ss -tulnp
		fi
	fi
	echo

	# read -p "[?] List active network connections? [y/N] " -n 1 -r
	# echo
	# if [[ $REPLY =~ ^[Yy]$ ]]
	# then
	# 	success "Displaying active network connections:"
	# 	lsof -nP -i +c0
	# fi
	# echo
}

# Forensics / Hivestorm
function find_media()
{
	chkdir="/home/"
	dmpfile="$HOME/media_files.txt"
	sarray=()
	header "Checking for media files in ${chkdir}"
	success "Checking txt files."
	echo "">$dmpfile
	declare -a extensions=(
		"txt"
		"mp4"
		"mp3"
		"ogg"
		"wav"
		"png"
		"jpg"
		"jpeg"
		"gif"
		"mov"
		"m4a"
		"m4b"
	)
	for i in "${extensions[@]}"
	do
		sarray=($(find $chkdir -type f -name "*.$i" | tee -a $dmpfile))
		echo "Found ${#sarray[@]}"
		success "Checking $i files."
	done
	printf "\n"
	notify "Saving file paths to ${dmpfile}"
}

# Online - Updating packages
function ask_to_install_updates()
{
	header "\nInstalling Updates"
	read -p "[?] Would you like to install updates? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		apt-get update
		apt-get upgrade -y
		apt-get dist-upgrade -y
	fi
}

# Online - Installing antivirus
function enable_av()
{
	header "\nAnti-Virus lockdown"
	command -v clamscan >/dev/null
	if [ $? -eq 0 ];then
		success "ClamAV found."
		freshclam
		success "Updated definitions."
	else
		error "ClamAV not installed."
		read -p "[?] Would you like to install ClamAV and chkrootkit? [y/N] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y clamav chkrootkit
			ufw enable > /dev/null
			freshclam
			success "ClamAV is now enabled and updated."
		fi
	fi
}

# Online - Installing ufw
function enable_ufw()
{
	header "\nFirewall Lockdown"
	command -v ufw >/dev/null
	if [ $? -eq 0 ];then
		success "UFW found enabling firewall."
		ufw enable > /dev/null
	else
		error "UFW not installed."
		read -p "[?] Would you like to install ufw? [y/N] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y ufw
			ufw enable > /dev/null
			success "UFW is now enabled."
		fi
	fi
}



# Modes - Different Ways to Run this Script
function mode_default(){
	# sudo ./lockdown.sh
	success "RUNNING WITH DEFAULT MODE - CCDC-compatible"
    #choose_editor
	check_services
    ssh_lockdown
	kernel_lockdown
	user_lockdown
	check_configs
	#enable_ufw
	#ask_to_install_updates
}
function mode_auto(){
	# sudo ./lockdown.sh -a
	success "RUN MODE: AUTOMATIC (NOT for CCDC)"
    readme_prompt
	#choose_editor
	ssh_lockdown
	kernel_lockdown
	#user_lockdown
	#check_configs
	check_bad_programs
	check_services
	enable_ufw
	#enable_av		# Disabled for time
	ask_to_install_updates
	#find_media 	# Disabled for CCDC
}
function mode_autoOffline(){
	# sudo ./lockdown.sh -o
	success "RUN MODE: OFFLINE (NOT for CCDC)"
    readme_prompt
	#choose_editor
	ssh_lockdown
	kernel_lockdown
	#user_lockdown
	#check_configs
	check_bad_programs
	check_services
	#enable_ufw
	#enable_av		# Disabled for time
	#ask_to_install_updates
	#find_media 	# Disabled for CCDC
}
function mode_userLockdown(){
	# sudo ./lockdown.sh -u
	success "RUN MODE: USER LOCKDOWN ONLY"
	user_lockdown
}

case $1 in
	"-a") 	mode_auto;;
	"-o") 	mode_autoOffline;;
	"-u") 	mode_userLockdown;;
	*)	mode_default;;
esac

header "\nThings left to do:"
notify "Secure Root - Change root password and disable if allowed!"
notify "Update kernel"
notify "Update the APT Package Manager Source (Settings > Software and Updates > Download From)"
notify "Pam cracklib password requirements/logging"
notify "Discover rootkits/backdoors"
notify "Check file permissions"
notify "Check init scripts"
notify "Web browser updates and security"
notify "ADD USERS NOT IN THE LIST"
notify "Win - Good Luck! :D"

success "Script finished exiting."
exit 0

