#!/bin/bash

#Change uidNum to what works in the environment
uidNum=101
while IFS=, read -r userName first last title groups password;
do
echo $userName
echo $first
echo $last
echo $title
echo $groups
echo $password

#Change password and admin account used as well as the dn to what is utilized in environment
ldapadd -x -w password -D cn=admin,dc=wizworld,dc=us<<EOF
dn: uid=$userName,ou=users,dc=wizworld,dc=us
objectClass: inetOrgPerson
objectClass: posixAccount
gidNumber: 100
uid: $userName
sn: $last
givenName: $first
cn: $userName
title: $title
uidNumber: $uidNum
homeDirectory: /home/$username
userpassword: $password
EOF

echo "$userName has been added"
echo $uid
((uid+=1))
done < usernamefirstlasttitlegroupspa.txt
