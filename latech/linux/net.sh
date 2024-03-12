if [ $(command -v ufw) ]; then 
cp /etc/ufw/user.rules ufw-rules.pre
ufw disable
for port in $(ss -tulnp | grep LISTEN | tr -s ' '| cut -f 5 -d ' ' | rev | cut -f 1 -d ':' | rev); do ufw allow $port; echo lol allowed $port; done
ufw enable
ufw status verbose
fi

if [ $(command -v firewall-cmd) ]; then 
firewall-cmd --permanent --list-all > firewall-init

ss -tulnp | grep LISTEN | tr -s ' ' | while read -r line ; do
port=$(echo $line | cut -f 5 -d ' ' | rev | cut -f 1 -d ':' | rev)
proto=$(echo $line | cut -f 1 -d ' ' )
firewall-cmd --permanent --zone=public --add-port=$port/$proto; echo lol allowed $port/$proto
done

firewall-cmd --reload
fi

# firewall-cmd --permanent --zone=public --remove-port=666/tcp
# By default uses the public zone