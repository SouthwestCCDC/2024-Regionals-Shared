#!/bin/bash

YARA_DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))

cd "$YARA_DIR"

# scan memory
PROCESSES=$(sudo ps -eo pid= | xargs)
for PROCESS in ${PROCESSES}; do
        timeout 60s yara rules/* --fast-scan -a 10 $PROCESS
        if [ $? -eq 124 ]; then
                echo "${PROCESS}: scan timed out"
        fi
done

echo "scanned" $(echo "${PROCESSES}" | wc -w) "processes"

# scan disk
DIRECTORIES=$(/usr/bin/ls / -a | grep -Ev "^(sys|proc|\.|\.\.)$" | sed "s/^/\//" | xargs)
for DIRECTORY in ${DIRECTORIES}; do
        timeout 1h yara rules/* --fast-scan --no-follow-symlinks --recursive ${DIRECTORY}
        if [ $? -eq 124 ]; then
                echo "${DIRECTORY}: scan timed out"
        fi
done

echo "scanned" $(echo "${DIRECTORIES}" | wc -w) "directories"
