#!/bin/bash

# Use the provided subject list when present; otherwise use the default list.
if [ "$#" -gt 0 ]; then
    subjects=("$@")
else
    subjects=(
        lightftp bftpd proftpd pure-ftpd exim live555 kamailio forked-daapd lighttpd1
        proftpd-state-machines pure-ftpd-state-machines exim-state-machines
        live555-state-machines kamailio-state-machines forked-daapd-state-machines
    )
fi

# Iterate through the subjects and clean matching containers/images.
for subject in "${subjects[@]}"; do
    echo "Cleaning containers and image for: ${subject}"

    # Stop and remove all containers created from the subject image.
    { docker ps -a -q --filter "ancestor=${subject}:latest" | xargs docker stop 2>/dev/null | xargs docker rm 2>/dev/null; } >/dev/null 2>&1
done

echo "Clean complete"
