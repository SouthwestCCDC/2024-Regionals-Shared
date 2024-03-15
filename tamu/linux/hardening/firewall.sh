#!/bin/sh
export PATH="/bin:/sbin:/usr/bin:/usr/sbin"

FIREWALL=""
RULES=""
POLICY="accept"

ALLOW_DNS_ALL=0
ALLOW_DNS_IPS=""

ALLOW_PING=0

PERSIST=0

SKIP_CONNECTIVITY_CHECK=0

SKIP_BACKUP=0

BACKUP_FILE=firewall-backup


COLOR_RED="\033[0;91m"
COLOR_GREEN="\033[0;92m"
COLOR_NONE="\033[0m"

help() {
    printf "Usage: %s [-p] [-d policy] [-f firewall] [-r port,action,direction[,ip[,protocol]]] [-s] [-S ip] [-n] [-N ip] [-i] [-y] [-b]\n" "$0"
    printf "  -r\tRule to set, with the actions: \"accept\" or \"drop\", the directions: \"in\" or \"out\", and the protocols: \"tcp\", \"udp\".\n    \tIf the port is \"_\", then the rule applies to all ports\n"
    printf "  -p\tSave rules persistently (restore after reboot)\n"
    printf "  -d\tSet default firewall policy to actions: \"accept\" or \"drop\"\n"
    printf "  -f\tUse specific firewall instead of attempting autodetection\n"
    printf "  -S\tAllow incoming ssh from specific ip\n"
    printf "  -s\tAllow incoming ssh from any ip\n"
    printf "  -N\tAllow dns to specific ip\n"
    printf "  -n\tAllow dns to any ip\n"
    printf "  -i\tAllow icmp pings\n"
    printf "  -y\tDon't confirm connectivity\n"
    printf "  -b\tDon't back up previous rules\n"
    printf "\n"
    printf "Examples:\n"
    printf "  %s -f iptables -r 80,accept,in -r 443,accept,in -r 22,drop,out\n" "$0"
    printf "  %s -f nftables -d drop -S 192.168.1.2 -N 8.8.8.8\n" "$0"
    printf "  %s -r 1234,accept,in,192.168.1.2\n" "$0"
}

detect_firewall() {
    iptables=0
    nftables=0
    if command -v iptables >/dev/null ; then
        iptables=1
    fi
    if command -v nft >/dev/null ; then
        nftables=1
    fi

    if [ $iptables -eq 0 ] && [ $nftables -eq 0 ]; then
        printf "none"
    elif [ $iptables -eq 1 ] && [ $nftables -eq 0 ]; then # If only iptables installed
        printf "iptables"
    elif [ $iptables -eq 0 ] && [ $nftables -eq 1 ]; then # If only nftables installed
        printf "nftables"
    elif iptables -V | grep -q '(nf_tables)$'; then       # If both installed and iptables uses nftables, use nftables directly
        printf "nftables"
    else                                                  # Otherwise error, user must choose firewall explicitly
        printf "%bWarning: both iptables (legacy) and nftables are installed%b\n" "$COLOR_RED" "$COLOR_NONE" >&2
        exit 1
    fi
}

# Deactivate firewall frontends and ensure the firewall service is running
deactivate_frontends() {
    printf "Disabling firewalld service\n"
    systemctl disable --now firewalld 2>&1
    printf "Disabling ufw service\n"
    systemctl disable --now ufw 2>&1

    if [ "$FIREWALL" = "iptables" ]; then
        printf "Enabling iptables service\n"
        systemctl enable --now iptables
    elif [ "$FIREWALL" = "nftables" ]; then
        printf "Enabling nftables service\n"
        systemctl enable --now nftables
    fi
}

print_rules() {
    if [ "$FIREWALL" = "iptables" ]; then
        iptables-save
    elif [ "$FIREWALL" = "nftables" ]; then
        nft list ruleset
    fi
}

backup_rules() {
    if [ "$FIREWALL" = "iptables" ]; then
        if [ -e "${BACKUP_FILE}-ip.txt" ]; then
            BACKUP_FILE="${BACKUP_FILE}-$(date +%Y-%m-%d_%H:%M)"
        fi
        iptables-save > "${BACKUP_FILE}-ip.txt"
        ip6tables-save > "${BACKUP_FILE}-ip6.txt"
    elif [ "$FIREWALL" = "nftables" ]; then
        if [ -e "${BACKUP_FILE}-nft.txt" ]; then
            BACKUP_FILE="${BACKUP_FILE}-$(date +%Y-%m-%d_%H:%M)"
        fi
        nft list ruleset > "${BACKUP_FILE}-nft.txt"
    fi
}

restore_rules() {
    if [ "$FIREWALL" = "iptables" ]; then
        iptables-restore < "${BACKUP_FILE}-ip.txt"
        ip6tables-restore < "${BACKUP_FILE}-ip6.txt"
    elif [ "$FIREWALL" = "nftables" ]; then
        nft flush ruleset
        nft --file "${BACKUP_FILE}-nft.txt"
    fi
}

clear_rules() {
    if [ "$FIREWALL" = "iptables" ]; then
        # Remove existing rules and set policy for all existing chains
        ip_policy=$(printf "%s" "$POLICY" | tr "[:lower:]" "[:upper:]")
        iptables-save  | awk '/^[*]/ { print $1 } /^:[A-Z]+ [^-]/ { print $1 " '"$ip_policy"'" ; } /COMMIT/ { print $0; }' | iptables-restore
        ip6tables-save | awk '/^[*]/ { print $1 } /^:[A-Z]+ [^-]/ { print $1 " '"$ip_policy"'" ; } /COMMIT/ { print $0; }' | ip6tables-restore
    elif [ "$FIREWALL" = "nftables" ]; then
        nf_policy=$(printf "%s" "$POLICY" | tr "[:upper:]" "[:lower:]")
        nft flush ruleset
        nft add table inet filter
        nft add chain inet filter input \{ type filter hook input priority 0 \; policy "$nf_policy" \; \}
        nft add chain inet filter output \{ type filter hook output priority 0 \; policy "$nf_policy" \; \}
        nft add chain inet filter forward \{ type filter hook forward priority 0 \; policy "$nf_policy" \; \}
    fi
}

persist_rules() {
    printf "Saving rules persistently\n"
    if [ "$FIREWALL" = "iptables" ]; then
        printf "#!/bin/sh\n" > /etc/network/if-pre-up.d/iptables
        printf "/sbin/iptables-restore < /etc/iptables.up.rules\n" >> /etc/network/if-pre-up.d/iptables
        printf "/sbin/ip6tables-restore < /etc/ip6tables.up.rules\n" >> /etc/network/if-pre-up.d/iptables
        chmod +x /etc/network/if-pre-up.d/iptables
        iptables-save > /etc/iptables.up.rules
        ip6tables-save > /etc/ip6tables.up.rules

    elif [ "$FIREWALL" = "nftables" ]; then
        printf "#!/usr/sbin/nft -f\n" > /etc/nftables.conf
        printf "flush ruleset\n" >> /etc/nftables.conf
        nft list ruleset >> /etc/nftables.conf
        if [ -d /etc/sysconfig ]; then
            cp /etc/nftables.conf /etc/sysconfig/nftables.conf
        fi
    fi

}

hosts_v4() {
    hostip=$(getent ahostsv4 "$1" | head -n1 | cut -d" " -f1)
    if [ -n "$hostip" ]; then
       printf "%s %s\n" "$hostip" "$1"
    fi
}

set_rule() {
    # Split input into variables on ","
    oIFS="$IFS"
    IFS=","
    set $1
    IFS="$oIFS"

    port="$1"
    action="$2"
    direction="$3"
    other_ip="$4"
    protocol="$5"

    if [ -z "$protocol" ]; then
        protocol="tcp"
    fi

    # Check if a domain was provided instead of an ip 
    iptype="ip"
    domain=0
    case "$other_ip" in
        *[a-z]*)
            domain=1
            #iphost=$(getent hosts "$other_ip" | cut -d" " -f1)
            iphost=$(hosts_v4 "$other_ip" | cut -d" " -f1)
            ;;
        *)
            iphost="$other_ip"
    esac
    case "$iphost" in
        *:*)
            iptype="ip6";
            ;;
    esac

    port_1=""
    port_2=""
    other_match1=""
    other_match2=""

    printf "Applying rule: %s,%s,%s,%s,%s\n" "$port" "$action" "$direction" "${other_ip:-_}" "$protocol"

    if [ "$FIREWALL" = "iptables" ]; then
        if [ "$port" != "_" ]; then
            port_1="-p $protocol --dport $port"
            port_2="-p $protocol --sport $port"
        elif [ -z "$other_ip" ]; then
            printf "Invalid rule\n"
            return
        fi

        if [ "$direction" = "in" ]; then
            direction_1="INPUT"
            direction_2="OUTPUT"
        elif [ "$direction" = "out" ]; then
            direction_1="OUTPUT"
            direction_2="INPUT"
        fi

        if [ -n "$other_ip" ] && [ "$other_ip" != "_" ]; then
            if [ "$direction" = "in" ]; then
                other_match1="-s $other_ip"
                other_match2="-d $other_ip"
            elif [ "$direction" = "out" ]; then
                other_match1="-d $other_ip"
                other_match2="-s $other_ip"
            fi
        fi

        comment=""
        if [ $domain -eq 1 ]; then
            comment="-m comment --comment \"$other_ip\""
        fi

        iptables="iptables"
        if [ $iptype = "ip6" ]; then
            iptables="ip6tables"
        fi

        ip_action=$(printf "%s" "$action" | tr "[:lower:]" "[:upper:]")
        $iptables -A $direction_1 $port_1 $other_match1 -j $ip_action $comment
        if [ "$ip_action" = "ACCEPT" ]; then
            $iptables -A $direction_2 $port_2 --state ESTABLISHED,RELATED $other_match2 -j $ip_action $comment
        fi

    elif [ "$FIREWALL" = "nftables" ]; then
        if [ "$port" != "_" ]; then
            port_1="$protocol dport $port"
            port_2="$protocol sport $port"
        elif [ -z "$other_ip" ]; then
            printf "Invalid rule\n"
            return
        fi

        if [ "$direction" = "in" ]; then
            direction_1="input"
            direction_2="output"
        elif [ "$direction" = "out" ]; then
            direction_1="output"
            direction_2="input"
        fi

        if [ -n "$other_ip" ] && [ "$other_ip" != "_" ]; then
            if [ "$direction" = "in" ]; then
                other_match1="$iptype saddr $other_ip"
                other_match2="$iptype daddr $other_ip"
            elif [ "$direction" = "out" ]; then
                other_match1="$iptype daddr $other_ip"
                other_match2="$iptype saddr $other_ip"
            fi
        fi

        comment=""
        if [ $domain -eq 1 ]; then
            comment="comment \"$other_ip\""
        fi

        action=$(printf "%s" "$action" | tr "[:upper:]" "[:lower:]")
        nft add rule inet filter $direction_1 $port_1 $other_match1 $action $comment
        if [ "$action" = "accept" ]; then
            nft add rule inet filter $direction_2 $port_2 ct state established,related $other_match2 $action $comment
        fi
    fi
}

allow_ssh() {
    other_ip="$1"

    if [ -n "$other_ip" ]; then
        set_rule "22,accept,in,$other_ip"
    else
        set_rule "22,accept,in"
    fi
}

allow_dns() {
    other_ip="$1"

    if [ -n "$other_ip" ]; then
        set_rule "53,accept,out,$other_ip,udp"
    else
        set_rule "53,accept,out,_,udp"
    fi
}

allow_ping() {
    printf "Allowing icmp pings\n"
    if [ "$FIREWALL" = "iptables" ]; then
        iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
        iptables -A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT
    elif [ "$FIREWALL" = "nftables" ]; then
        nft add rule inet filter input icmp type echo-request accept
        nft add rule inet filter input icmpv6 type echo-request accept
    fi
}


if [ $# -eq 0 ]; then
    help
    exit 1
fi

while getopts f:d:N:r:S:bhinpsy ARG
do
    case "$ARG" in
        f)
            FIREWALL="$OPTARG"
            if [ "$FIREWALL" != "iptables" ] && [ "$FIREWALL" != "nftables" ]; then
                printf "Invalid firewall \"%s\" specified\n" "$FIREWALL"
                exit 1
            fi
            printf "Using %s as firewall\n" "$FIREWALL"
            ;;
        d)
            POLICY="$OPTARG"
            printf "Setting firewall policy to default %s\n" "$POLICY"
            ;;
        r)
            RULES="$RULES $OPTARG"
            ;;
        S)
            RULES="$RULES 22,accept,in,$OPTARG"
            ;;
        N)
            ALLOW_DNS_IPS="$ALLOW_DNS_IPS $OPTARG"
            ;;
        h)
            help
            exit 0
            ;;
        i)
            ALLOW_PING=1
            ;;
        n)
            ALLOW_DNS_ALL=1
            ;;
        p)
            PERSIST=1
            ;;
        s)
            RULES="$RULES 22,accept,in,"
            ;;
        y)
            SKIP_CONNECTIVITY_CHECK=1
            ;;
        b)
            SKIP_BACKUP=1
            ;;
        *)
            help
            exit 1
            ;;
    esac
done


if [ -z "$FIREWALL" ]; then
    FIREWALL=$(detect_firewall)
fi

if [ "$FIREWALL" != "iptables" ] && [ "$FIREWALL" != "nftables" ]; then
    printf "No valid firewall found\n"
    exit 1
fi

printf "\nOLD RULES:\n%b" "$COLOR_RED"
print_rules
printf "%b" "$COLOR_NONE"

backup_rules
deactivate_frontends
clear_rules

if [ $ALLOW_DNS_ALL -eq 1 ]; then
    allow_dns
elif [ -n "$ALLOW_DNS_IPS" ]; then
    for ip in $ALLOW_DNS_IPS; do
        allow_dns $ip
    done
fi

if [ $ALLOW_PING -eq 1 ]; then
    allow_ping
fi

# Set all firewall rules
for rule in $RULES; do
    set_rule $rule
done

printf "\nNEW RULES:\n%b" "$COLOR_GREEN"
print_rules
printf "%b" "$COLOR_NONE"

# Restore original rules if user got kicked out
if [ $SKIP_CONNECTIVITY_CHECK -eq 0 ]; then
    printf "\n%bTo confirm you can still access this machine, log in using a new terminal and run \"touch /tmp/fw-confirm\"%b\nRestoring old rules in 30 seconds\n" "$COLOR_RED" "$COLOR_NONE"

    original_date=$(stat /tmp/fw-confirm 2>/dev/null)
    sleep 30
    current_date=$(stat /tmp/fw-confirm 2>/dev/null)

    if [ "$original_date" = "$current_date" ]; then
        printf "%bOriginal rules restored%b\n" "$COLOR_GREEN" "$COLOR_NONE"
        restore_rules
        if [ -e "${BACKUP_FILE}-nft.txt" ]; then
            rm -i "${BACKUP_FILE}-nft.txt"
        elif [ -e "${BACKUP_FILE}-ip.txt" ]; then
            rm -i "${BACKUP_FILE}-ip.txt"
            rm -i "${BACKUP_FILE}-ip6.txt"
        fi
        exit
    fi
fi

if [ $SKIP_BACKUP -eq 1 ]; then
    if [ -e "${BACKUP_FILE}-nft.txt" ]; then
        rm -f "${BACKUP_FILE}-nft.txt"
    elif [ -e "${BACKUP_FILE}-ip.txt" ]; then
        rm -f "${BACKUP_FILE}-ip.txt"
        rm -f "${BACKUP_FILE}-ip6.txt"
    fi
fi

printf "%bKeeping new rules%b\n" "$COLOR_GREEN" "$COLOR_NONE"
if [ $PERSIST -eq 1 ]; then
    persist_rules
fi
