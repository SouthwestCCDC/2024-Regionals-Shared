#!./busybox sh

# Use ports 46500 - 46800
SRVPORT=46500
FILE_PORT_START=46501
FILE_PORT_NUM=300
CWD=$(pwd)

# -----------------------------------------------------------------------------
# Start listening for clients

mkdir -p "$CWD/srv/clients"
cd "$CWD/srv"
tcpsvd -c 4096 0.0.0.0 "$SRVPORT" ../busybox sh ../server.sh "$FILE_PORT_START" "$FILE_PORT_NUM"
