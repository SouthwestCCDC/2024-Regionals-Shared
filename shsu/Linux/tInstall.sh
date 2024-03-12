#!/bin/bash
# Custom things I may or may not use

BASH_ALIASES_FILE="$HOME/.bash_aliases"
BASHRC_FILE="$HOME/.bashrc"

# Function to create an alias
create_alias() {
    local alias_name=$1
    local command=$2

    echo "alias $alias_name='$command'" >> "$BASH_ALIASES_FILE"
    source "$BASH_ALIASES_FILE"
    echo "Alias $alias_name created."
}

# Check if .bash_aliases file exists, create it if not
if [ ! -f "$BASH_ALIASES_FILE" ]; then
    touch "$BASH_ALIASES_FILE"
    echo "if [ -f $BASH_ALIASES_FILE ]; then" >> "$BASHRC_FILE"
    echo "    . $BASH_ALIASES_FILE" >> "$BASHRC_FILE"
    echo "fi" >> "$BASHRC_FILE"
fi
# install sublime
if command -v apt >/dev/null 2>&1; then

    wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null
    echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
elif command -v yum >/dev/null 2>&1; then
    sudo rpm -v --import https://download.sublimetext.com/sublimehq-rpm-pub.gpg
    sudo yum-config-manager --add-repo https://download.sublimetext.com/rpm/stable/x86_64/sublime-text.repo
else
    echo "unknown package manager"
fi

# Install nmap
sudo apt-get update
sudo apt-get install -y nmap

# Install Wireshark
sudo apt-get install -y wireshark

# Install Burp Suite (Assuming you have the JRE installed)
echo "Downloading Burp Suite..."
wget -O burp-suite.sh "https://portswigger.net/burp/releases/download?product=community&version=latest&type=linux"
chmod +x burp-suite.sh
sudo ./burp-suite.sh

# Install sqlmap
sudo apt-get install -y sqlmap

# Install net-tools
sudo apt-get isntall -y net-tools

if command -v apt >/dev/null 2>&1; then
    apt install -y nmap
    apt install -y wireshark
    apt install -y sqlmap
    apt install -y net-tools
    apt install -y sublime-text
elif command -v yum >/dev/null 2>&1; then
    yum install -y nmap
    yum install -y wireshark
    yum install -y sqlmap
    yum install -y net-tools
    yum install -y sublime-text

else
    echo "Unknown package manager"
fi

# Create aliases
create_alias "cls" "clear"
create_alias "editals" "sudo subl ~/.bash_aliases"
create_alias "editrc" "sudo subl ~/.bashrc"

echo "Tools and aliases setup complete."