#!/bin/vbash

source /opt/vyatta/etc/functions/script-template

configure

healthchecks="WEBSITE:192.168.1.1:8888 THING1:192.168.1.1:9999 THING2:192.168.1.1:8888 THING3:192.168.1.2:8888 THING4:192.168.2.1:88"
counter=100
for service in $healthchecks;
do
name=$(echo -n $service | cut -d ':' -f 1)
ip=$(echo -n $service | cut -d ':' -f 2)
port=$(echo -n $service | cut -d ':' -f 3)
set firewall name FLOATING rule $counter description  "Allow monitoring for $name service"
set firewall name FLOATING rule $counter action accept
set firewall name FLOATING rule $counter protocol tcp_udp
set firewall name FLOATING rule $counter destination address $ip
set firewall name FLOATING rule $counter destination port $port
set firewall name INGRESS rule $counter description  "Allow monitoring for $name service"
set firewall name INGRESS rule $counter action accept
set firewall name INGRESS rule $counter protocol tcp_udp
set firewall name INGRESS rule $counter destination address $ip
set firewall name INGRESS rule $counter destination port $port
((counter+=10))
done

set firewall name FLOATING rule 500 description 'Block all not from our networks going to our networks'
set firewall name FLOATING rule 500 action drop
set firewall name FLOATING rule 500 log enable
set firewall name FLOATING rule 500 protocol tcp_udp
set firewall name FLOATING rule 500 destination group network-group OurNetworks
set firewall name FLOATING rule 500 source group network-group !OurNetworks

set firewall name FLOATING rule 505 description 'Allow all from our networks going to our networks'
set firewall name FLOATING rule 505 action accept
set firewall name FLOATING rule 505 protocol tcp_udp
set firewall name FLOATING rule 505 destination group network-group OurNetworks
set firewall name FLOATING rule 505 source group network-group OurNetworks

set firewall name FLOATING rule 1000 description 'Block all from our networks going to private cidrs'
set firewall name FLOATING rule 1000 action drop
set firewall name FLOATING rule 1000 log enable
set firewall name FLOATING rule 1000 protocol tcp_udp
set firewall name FLOATING rule 1000 destination group network-group RFC1918CIDRS
set firewall name FLOATING rule 1000 source group network-group OurNetworks

set firewall name INGRESS rule 500 description 'Block all not from our networks going to our networks'
set firewall name INGRESS rule 500 action drop
set firewall name INGRESS rule 500 log enable
set firewall name INGRESS rule 500 protocol tcp_udp
set firewall name INGRESS rule 500 destination group network-group INNetworks
set firewall name INGRESS rule 500 source group network-group !INNetworks

set firewall name INGRESS rule 505 description 'Allow all from our networks going to our networks'
set firewall name INGRESS rule 505 action accept
set firewall name INGRESS rule 505 protocol tcp_udp
set firewall name INGRESS rule 505 destination group network-group OurNetworks
set firewall name INGRESS rule 505 source group network-group OurNetworks

set firewall name INGRESS rule 1000 description 'Block all from our networks going to private cidrs'
set firewall name INGRESS rule 1000 action drop
set firewall name INGRESS rule 1000 log enable
set firewall name INGRESS rule 1000 protocol tcp_udp
set firewall name INGRESS rule 1000 destination group network-group RFC1918CIDRS
set firewall name INGRESS rule 1000 source group network-group OurNetworks

commit
save