# Fail2Ban
*Made this into a markdown from a 3-piece script.*
[Wiki](https://github.com/fail2ban/fail2ban/wiki)

## Installing (from Package Manager)
```
apt-get update
apt-get install -y fail2ban
```
```
yum update -y
yum install -y fail2ban
```
```
dnf update
dnf install fail2ban
```

## Enabling
Note: Not needed on Debian/Ubuntu as those install scripts already enable F2B.
```
systemctl enable fail2ban
systemctl start fail2ban
```

## Relevant Modules
- sshd
- apache-auth
- apache-overflows
- apache-nohome
- apache-botsearch
- nginx-http-auth
- nginx-botsearch
- nginx-bad-request
- nginx-forbidden
- php-url-fopen
- pure-ftpd
- mysqld-auth
- mssql-auth
- mongodb-auth
- pam-generic
- grafana
- pass2allow-ftp
- slapd
- phpmyadmin-syslog
