# update packages
packages="sudo nmap tmux tree vim hostname htop clamav lynis wget curl"

printf "this function will be used to install important/essential packages on barebones systems"
if [ $(command -v apt-get) ]; then # Debian based
    apt-get update -y && apt-get upgrade -y
    apt-get install $packages auditd audispd-plugins -y -q
    #debian only packages
    apt-get install debsums -y
elif [ $(command -v yum) ]; then
    yum -y update
    yum -y install $packages audit
elif [ $(command -v pacman) ]; then
    yes | pacman -S $packages
elif [ $(command -v apk) ]; then # Alpine
    apk update
    apk upgrade
    apk add bash vim man-pages mdocml-apropos bash-doc bash-completion util-linux pciutils usbutils coreutils binutils findutils attr dialog dialog-doc grep grep-doc util-linux-doc pciutils usbutils binutils findutils readline lsof lsof-doc less less-doc nano nano-doc curl-doc
    apk add $packages
fi

for com in $(echo "addgroup ufw iptables sysctl chattr chmod chown echo grep passwd rm useradd ss usermod"); do
    if ! [ $(command -v $com) ]; then
        echo $com not found
    fi
done

systemctl start auditd 
