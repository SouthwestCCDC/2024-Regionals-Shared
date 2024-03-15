#!./busybox sh

if [ $# -ne 2 ]; then
    echo "Usage: $0 file_port_start file_port_num"
    exit 1
fi

FILE_PORT_START=$1
FILE_PORT_NUM=$2

SRVDIR=$(pwd)

verify_input() {
    case "$@" in
        "")    echo "Input error"
               exit
               ;;
        *"/"*) echo "Input error"
               exit
               ;;
      esac
}

write_to_file() {
    if [ -n "$1" ]; then
        touch "$1"
        while IFS= read -r INPUT; do
            if [ "$INPUT" != "⟃---EOF---⟄" ]; then
                printf "%s\n" "$INPUT" >> "$1"
            else
                break
            fi
        done
    fi
}

print_status() {
    echo "Acknowledged"
    "$@"
    echo "Done."
}


# -----------------------------------------------------------------------------
# Identify/authenticate client

read -r COMMAND
echo "$COMMAND" >&2

# Existing client
if [ "$COMMAND" = "login" ]; then
    echo -n "Client name: "
    read -r TMPNAME
    echo -n "Client key: "
    read -r TMPKEY

    verify_input "$TMPNAME"

    # Check if provided credentials are accurate
    if [ -e "$SRVDIR/clients/$TMPNAME" ]; then
        KEY=$(cat "$SRVDIR/clients/$TMPNAME/_auth-key")
        if [ "$TMPKEY" = "$KEY" ]; then
            CLIENTNAME="$TMPNAME"
            CLIENTDIR="$SRVDIR/clients/$TMPNAME"
            echo "Auth success"
        else
            echo "Auth failure"; exit
        fi
    else
        echo "Auth failure"; exit
    fi
    unset TMPNAME
    unset TMPKEY

# New client
elif [ "$COMMAND" = "register" ]; then
    echo -n "Hostname: "
    read -r CLIENTHOSTNAME
    # Use shortened hostname and add random suffix to reduce collisions
    CLIENTHOSTNAME=$(echo "$CLIENTHOSTNAME" | sed 's/[^a-zA-Z]//g' | cut -c -16)
    CLIENTNAME="client_${CLIENTHOSTNAME}_$(( RANDOM * 2**30 + RANDOM * 2**15 + RANDOM ))"
    CLIENTDIR="$SRVDIR/clients/$CLIENTNAME"
    CLIENTKEY=$(( RANDOM * 2**30 + RANDOM * 2**15 + RANDOM ))
    mkdir -p "$CLIENTDIR"
    echo "$CLIENTKEY" > "$CLIENTDIR/_auth-key"
    echo "Name: $CLIENTNAME"
    echo "Key: $CLIENTKEY"
    unset CLIENTKEY
else
    echo "Command not found."
    exit
fi

cd "$CLIENTDIR"


# -----------------------------------------------------------------------------
# Client communication

while read -r COMMAND; do
    echo "$CLIENTNAME: $COMMAND" >&2

    if [ "$COMMAND" = "info" ]; then
        print_status write_to_file _info.txt


    elif [ "$COMMAND" = "processes" ]; then
        print_status write_to_file _processes.log


    elif [ "$COMMAND" = "file" ]; then
        echo -n "Filename: "
        read -r TMPFILENAME
        verify_input "F__${TMPFILENAME}"
        echo -n "Hash: "
        read -r TMPHASH

        FILENAME="F__${TMPFILENAME}"

        # Add suffix if file already exists
        if [ -e "$FILENAME" ]; then
            SUFFIX=1
            while [ -e "${FILENAME}_${SUFFIX}" ]; do
                SUFFIX=$(( SUFFIX + 1 ))
            done
            FILENAME="${FILENAME}_${SUFFIX}"
        fi

        # Grab an open port and listen for file. Use netcat since sh can't
        # handle binary data well
        ATTEMPTCOUNT=0
        SLEEPTIME=0
        while true; do
            sleep $(( RANDOM % (SLEEPTIME + 5) + 1 ))
            PORT=$(( (RANDOM * 2 + RANDOM % 2) % FILE_PORT_NUM + FILE_PORT_START ))
            nc -w 7 -l -p "$PORT" > "$FILENAME" 2>/dev/null &
            NC_PID=$!
            # Wait for nc to fail. There seems to be a bug with busybox sh where
            # using the builtin sleep when following the backgrounded nc
            # doesn't sleep, so calling the binary again
            #../../../busybox sleep 1
            /bin/sleep 1
            if ps -o pid | grep -q -e $NC_PID ; then
                break
            fi
            ATTEMPTCOUNT=$(( ATTEMPTCOUNT + 1 ))
            SLEEPTIME=$(( SLEEPTIME + 2 ))
            if [ $ATTEMPTCOUNT -gt 5 ]; then
                echo "$CLIENTNAME: ($FILENAME) Failed to bind open port for file transfer, giving up" >&2
                echo "[${FILERECVTIME}] File transfer failed: ${FILENAME}" >> _files.log
                exit
            fi
        done
        echo "$PORT"
        wait $NC_PID

        FILERECVTIME="$(date '+%Y-%m-%d %H:%M:%S')"
        echo "[${FILERECVTIME}] File received: ${FILENAME}" >> _files.log

        HASH=$(md5sum "$FILENAME" | cut -d' ' -f1)
        if [ "$HASH" != "$TMPHASH" ]; then
            echo "Checksum error"
        else
            echo "Transfer success"
        fi

        unset TMPFILENAME


    elif [ "$COMMAND" = "log" ]; then
        echo -n "Filename: "
        read -r TMPFILENAME
        verify_input "L__${TMPFILENAME}"
        print_status write_to_file "L__${TMPFILENAME}"
        unset TMPFILENAME


    elif [ "$COMMAND" = "command" ]; then
        echo -n "Filename: "
        read -r TMPFILENAME
        verify_input "C__${TMPFILENAME}"
        print_status write_to_file "C__${TMPFILENAME}"
        unset TMPFILENAME


    else
        echo "Command not found."
    fi
done
