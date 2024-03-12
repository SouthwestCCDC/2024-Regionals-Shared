#!/bin/bash

unset HISTFILE

ssh-keygen -C "" -f sysadminkey -N $(cat newpass)
ssh-keyscan ${HOST} > ~/.ssh/known_hosts
sshpass -f ipass scp deps.sh ${IUSER}@${HOST}:~/
sshpass -f ipass scp user.sh ${IUSER}@${HOST}:~/
sshpass -f ipass ssh ${IUSER}@${HOST} '~/deps.sh'
sshpass -f ipass ssh ${IUSER}@${HOST} '~/user.sh'
sshpass -f newpass ssh-copy-id -i sysadminkey sysadmin@${HOST}

sshpass -f newpass -P assphrase ssh -i sysadminkey sysadmin@${HOST} 'sudo -ln'
read -p "Check account for login and permissions, enter when done"

sshpass -f newpass -P assphrase scp -i sysadminkey hard.sh sysadmin@${HOST}:~/
sshpass -f newpass -P assphrase ssh -i sysadminkey sysadmin@${HOST} 'sudo ~/hard.sh'
