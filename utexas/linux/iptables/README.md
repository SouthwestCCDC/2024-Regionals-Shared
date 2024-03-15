# Iptables

## Making Rules Persistent

```
apt-get install -y iptables-persistent
netfilter-persistent save
```

## Reset

```
iptables -X
```

## Forward (Unless Acting as a Firewall)

```
iptables -P FORWARD DROP
```

## Ingress

```
iptables -P INPUT DROP

iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

iptables -A INPUT -p udp --dport 68 --sport 67 -j ACCEPT

iptables -A INPUT -p tcp -s X.X.X.X/Y --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dports 80,443 -j ACCEPT

iptables -A INPUT -p tcp -s X.X.X.X/Y --dport 3306 -j ACCEPT

```

## Egress

```
iptables -P OUTPUT DROP

iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A OUTPUT -p udp --dport 67 --sport 68 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 123 -j ACCEPT

iptables -A OUTPUT -p tcp --dports 80,443 -m -j ACCEPT
iptables -A OUTPUT -p udp --dport 443 -m -j ACCEPT
```

## Flush

```
iptables -F
iptables -Z
```

## IPv6

```
ip6tables -P FORWARD DROP
ip6tables -P FORWARD DROP
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -F
ip6tables -Z
```
