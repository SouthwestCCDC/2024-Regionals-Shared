#!/bin/vbash

source /opt/vyatta/etc/functions/script-template

configure


export OUR_NETWORKS="10.0.1.0/24 10.0.2.0/24 172.31.80.0/24 172.31.255.17/32 172.31.255.18/32 172.69.1.0/24 172.20.224.0/24"
export BLUE_NETWORK="10.0.1.0/24 10.0.2.0/24 172.31.255.17/32 172.69.1.0/24"
export ROUTER_NETWORKS="172.31.255.17/32 172.31.255.18/32"

for network in $OUR_NETWORKS; 
do set firewall group network-group OurNetworks network $network
done
for network in $BLUE_NETWORK; 
do set firewall group network-group BlueTeam network $network
done
for network in $ROUTER_NETWORKS; 
do set firewall group network-group INNetworks network $network
done

set firewall group network-group RFC1918CIDRS network 10.0.0.0/8
set firewall group network-group RFC1918CIDRS network 172.16.0.0/12
set firewall group network-group RFC1918CIDRS network 192.168.0.0/16
set firewall group network-group RFC1918CIDRS network 127.0.0.0/8
set firewall group network-group RFC1918CIDRS network 169.254.0.0/16
set firewall group network-group RFC1918CIDRS network 224.0.0.0/4

for port in 22 137 3389 5985 5986
do
set firewall group port-group MGMT port $port
done

for port in 53 88 135 137 138 139 389 443 445 464 636 3268 3269 49443
do
set firewall group port-group AD port ${port}
done

export KEYS="NOAH:AAAAB3NzaC1yc2EAAAADAQABAAABgQDqS6DJReDwFFDUdWs2v60k92+5mNzETUpKIlGNDV5nMeo5Fy6n8F8MGR9+DFdkXXewhFAf596t4bRByGK7ulGhcax1+cI7LS1DhEn3ljyFSiBgLrq371V5Q5AILmOPcT5mXWqvvFkatw9S5hPnJzXzIPJWHNgpIpoouMHLQyudWiDAFnl5nvVlkBkDGWmQrJQ/vp1/XytDUKfa3uf+JaHoFwRnI96URxcGUgTEffx+L5DLaaDrHqK7CDaGBMNkGNJUBUCi0P4WLLWNF1fuF1n6MZDW2Q6zq7TXy77VkFTuWZ+c62jlmeBiFN+CVttbl77JX8yF+P445y4oZd2pZIhk3FVcM0UWobdPfBGCHj0HYntMNcCgM9zeOd0Z0lKFdJsaMJaGMRkoThq64CDYWqAVdIdeb9ENHdth4+EVV2eaMq0If4G2+lDpioYUXTTvvY4ng1xWChPcv2fZaiCiVxHQCwPSCWv/ZYKL5jmVD9zAn3gzR6Em6vjYZ1nPCEOvvBE= 
SAM:AAAAB3NzaC1yc2EAAAADAQABAAABgQDg3GtorcGwLx0UKacWQatEUDhfTB4axGW4k/5Tb98kYg4uVGCez0qwYJTWXvBEEe0d0OFo0+fu+fMDNga4h+GK0YUHmdSE8HgZZa+gl3lOhmpt16FneArIAo/o81LsTtqqJc6FtbfMlBslKM57DoF6wGQlADghhExjaGmtbMbwdMp9U1fz5h3L7RfW5oBlfqKTnaDfzgKuj8lfUEgw9+eXZxgh2961NCo5d2veRl0mks0XX6Bs3Xgb9ZPHDeDkLkQBRpPZIjl6WbakaFms7jDqNFEZ0HPCIdsZVxqZEyYXg34YqLnomj20fysU9JeXEj/1mXHV91c70EMcrJ5yQQ2Bwcdvk0OIVHW4mWhq4tMEKDDwRVAowGDe/UKVHywXlu1x9clkb/Y+oleV6sY8UAvECL82MSPcUjMANLf/AWtWpyXiP3ryq4PjsQrq+V0ZZi4VZCwI/4qet+uXktmG0y1/9g2mwvwoPaCSrAlRxxoRGUtHXbHDH9fYKvRuh8WqHvM="

for sshconf in $KEYS:
do 
    name=$(echo -n $sshconf | cut -d ':' -f 1)
    key=$(echo -n $sshconf | cut -d ':' -f 2)
    set system login user vyos authentication public-keys $name type ssh-rsa
    set system login user vyos authentication public-keys $name key $key
done

set service ssh disable-password-authentication
set service ssh dynamic-protection allow-from Blue_Team
set service ssh dynamic-protection block-time '120'
set service ssh dynamic-protection detect-time '1800'
set service ssh dynamic-protection threshold '30'
set service ssh port '22'

set firewall name FLOATING default-action accept

set firewall name FLOATING rule 5 action accept
set firewall name FLOATING rule 5 state established enable
set firewall name FLOATING rule 5 state related enable

set firewall name FLOATING rule 10 description 'Block ICMP not from BlueTeam'
set firewall name FLOATING rule 10 action drop
set firewall name FLOATING rule 10 log enable
set firewall name FLOATING rule 10 protocol ICMP
set firewall name FLOATING rule 10 destination group network-group OurNetworks
set firewall name FLOATING rule 10 source group network-group !BlueTeam

set firewall name FLOATING rule 15 description 'Allow ICMP from Blueteam'
set firewall name FLOATING rule 15 action accept
set firewall name FLOATING rule 15 protocol ICMP
set firewall name FLOATING rule 15 destination group network-group OurNetworks
set firewall name FLOATING rule 15 source group network-group BlueTeam

set firewall name FLOATING rule 20 description 'Block all not from our network range'
set firewall name FLOATING rule 20 action drop
set firewall name FLOATING rule 20 log enable
set firewall name FLOATING rule 20 protocol tcp_udp
set firewall name FLOATING rule 20 destination group port-group MGMT
set firewall name FLOATING rule 20 source group network-group !BlueTeam

set firewall name FLOATING rule 25 description 'Allow all from blueteam range to management ports'
set firewall name FLOATING rule 25 action accept
set firewall name FLOATING rule 25 log enable
set firewall name FLOATING rule 25 protocol tcp_udp
set firewall name FLOATING rule 25 destination group port-group MGMT
set firewall name FLOATING rule 25 source group network-group BlueTeam

set firewall name FLOATING rule 30 description 'Block all not from our network range'
set firewall name FLOATING rule 30 action drop
set firewall name FLOATING rule 30 log enable
set firewall name FLOATING rule 30 protocol tcp_udp
set firewall name FLOATING rule 30 destination group port-group AD
set firewall name FLOATING rule 30 destination group network-group OurNetworks
set firewall name FLOATING rule 30 source group network-group !OurNetworks

set firewall name FLOATING rule 35 description 'Allow all from our network range to our network range'
set firewall name FLOATING rule 35 action accept
set firewall name FLOATING rule 35 protocol tcp_udp
set firewall name FLOATING rule 35 destination group port-group AD
set firewall name FLOATING rule 35 destination group network-group OurNetworks
set firewall name FLOATING rule 35 source group network-group OurNetworks



set firewall name INGRESS default-action accept

set firewall name INGRESS rule 5 action accept
set firewall name INGRESS rule 5 state established enable
set firewall name INGRESS rule 5 state related enable

set firewall name INGRESS rule 10 description 'Block ICMP not from Our Networks'
set firewall name INGRESS rule 10 action drop
set firewall name INGRESS rule 10 log enable
set firewall name INGRESS rule 10 protocol ICMP
set firewall name INGRESS rule 10 destination group network-group INNetworks
set firewall name INGRESS rule 10 source group network-group !INNetworks

set firewall name INGRESS rule 20 description 'Block all not from our network range'
set firewall name INGRESS rule 20 action drop
set firewall name INGRESS rule 20 log enable
set firewall name INGRESS rule 20 protocol tcp_udp
set firewall name INGRESS rule 20 destination group port-group MGMT
set firewall name INGRESS rule 20 source group network-group !INNetworks

set firewall name INGRESS rule 30 description 'Block all not from our network range'
set firewall name INGRESS rule 30 action drop
set firewall name INGRESS rule 30 log enable
set firewall name INGRESS rule 30 protocol tcp_udp
set firewall name INGRESS rule 30 destination group port-group AD
set firewall name INGRESS rule 30 destination group network-group OurNetworks
set firewall name INGRESS rule 30 source group network-group !OurNetworks


set firewall name LOCAL default-action accept

set firewall name LOCAL rule 5 action accept
set firewall name LOCAL rule 5 state established enable
set firewall name LOCAL rule 5 state related enable

set firewall name LOCAL rule 10 description 'Block ssh not from Blueteam'
set firewall name LOCAL rule 10 action drop
set firewall name LOCAL rule 10 log enable
set firewall name LOCAL rule 10 protocol tcp
set firewall name LOCAL rule 10 destination port 22
set firewall name LOCAL rule 10 source group network-group !BlueTeam

set firewall name LOCAL rule 20 description 'Block DNS not from OurNetworks'
set firewall name LOCAL rule 20 action drop
set firewall name LOCAL rule 20 log enable
set firewall name LOCAL rule 20 protocol tcp_udp
set firewall name LOCAL rule 20 destination port 53
set firewall name LOCAL rule 20 source group network-group !OurNetworks

set firewall name LOCAL rule 30 description 'Block all not from Blueteam'
set firewall name LOCAL rule 30 action drop
set firewall name LOCAL rule 30 log enable
set firewall name LOCAL rule 30 protocol tcp_udp
set firewall name LOCAL rule 30 source group network-group !BlueTeam

commit
save
