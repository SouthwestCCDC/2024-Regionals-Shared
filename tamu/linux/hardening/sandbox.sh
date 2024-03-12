#!/bin/sh

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
	printf "Must run as root\n" >&2
	exit 1
fi

if [ -z "$SERVICE" ]; then
	printf "What service do you want to sandbox?: "
	read -r SERVICE
fi

if systemctl list-unit-files "${SERVICE}.service" | grep "^0 unit files listed"; then
	printf "Service not found\n"
	exit 1
fi

prompt_yn() {
	printf "%s [y/N]\n" "$1" >&2
	read -r promptmessage
	case "$promptmessage" in
		[yY]|[yY][eE][sS])
			printf "y"
			;;
		*)
			printf "n"
			;;
	esac
}

OVERRIDE_DIR="/etc/systemd/system/${SERVICE}.service.d"
OVERRIDE_CONF="/etc/systemd/system/${SERVICE}.service.d/override.conf"

if ! [ -e "$OVERRIDE_CONF" ]; then
	mkdir -p "$OVERRIDE_DIR"
	cp "profiles/generic-override.conf" "$OVERRIDE_CONF"
fi

while true; do
	systemctl edit "$SERVICE" || exit 1
	restartservice=$(prompt_yn "Restart $SERVICE to test new sandbox config?")
	if [ "$restartservice" = "y" ]; then
		printf "Restarting service...\n"
		systemctl restart "$SERVICE" || { journalctl -xeu "$SERVICE"; systemctl status "$SERVICE"; }
		if [ $? = 0 ]; then
			viewjournal=$(prompt_yn "$SERVICE successfully started (but could have failed after starting). View journalctl output?")
			if [ "$viewjournal" = "y" ]; then
				sleep 2
				journalctl -xeu "$SERVICE"
			fi
			keepediting=$(prompt_yn "Keep editing the sandbox config?")
			if [ "$keepediting" = "y" ]; then
				continue
			else
				break
			fi
		else
			keepediting=$(prompt_yn "Keep editing the sandbox config? Consider commenting everything out first, then adding restrictions.")
			if [ "$keepediting" = "y" ]; then
				continue
			else
				cancel=$(prompt_yn "Delete the sanbox config?")
				if [ "$cancel" = "y" ]; then
					rm -i $(systemctl cat "$SERVICE" | grep override.conf | cut -d" " -f2)
				else
					break
				fi
			fi
		fi
	else
		printf "Not restarting...\n"
		break
	fi
done
