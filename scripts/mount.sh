#!/bin/bash

MOUNT_POINT="${1:-/mnt/vtfs}"
SERVER_URL="${2:-http://127.0.0.1:8080}"

if ! lsmod | grep -q "^vtfs"; then
    echo "Loading vtfs module..."
    sudo insmod kernel/vtfs.ko
fi

sudo mkdir -p "$MOUNT_POINT"
sudo mount -t vtfs "$SERVER_URL" "$MOUNT_POINT"

echo "VTFS mounted at $MOUNT_POINT"