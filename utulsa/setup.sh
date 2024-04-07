#!/bin/sh

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root!"
    exit 1
fi

# Update package repositories and install essential tools
echo "Installing bash, vim, nano, sudo"

# Debian
if command -v apt-get >/dev/null 2>&1; then
    echo "Debian detected."
    apt-get update
    apt-get install -y bash vim nano sudo
fi

# Red Hat-based
if command -v yum >/dev/null 2>&1; then
    echo "Red Hat detected."
    yum install -y bash vim nano sudo
fi

# FreeBSD
if command -v pkg >/dev/null 2>&1; then
    echo "FreeBSD detected."
    pkg update
    pkg install -y bash vim nano sudo
fi

# Alpine Linux
if command -v apk >/dev/null 2>&1; then
    echo "Alpine detected."
    sed -i 's/#\(.*\/community\)/\1/' /etc/apk/repositories # enable community repo
    apk update
    apk add bash vim nano sudo

    # extra: for gpasswd groups management
    apk add shadow
fi
