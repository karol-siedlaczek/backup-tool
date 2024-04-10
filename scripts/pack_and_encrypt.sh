#!/bin/bash

PATH=$1
ENCRYPTION_KEY=$2
NEW_PATH=$3

if [[ -z "$PATH" || -z "$ENCRYPTION_KEY" || -z "$NEW_PATH" ]]; then
    exit 1
fi

/usr/bin/tar -Ipigz -cO "$PATH" | /usr/bin/gpg2 --always-trust --yes --encrypt -r "$ENCRYPTION_KEY" > "$NEW_PATH.gpg"
echo -n $NEW_PATH.gpg
