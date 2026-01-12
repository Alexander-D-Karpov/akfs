#!/bin/bash

MOUNT_POINT="${1:-/mnt/vtfs}"

if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    sudo umount "$MOUNT_POINT"
    echo "Unmounted $MOUNT_POINT"
fi

if lsmod | grep -q "^vtfs"; then
    sudo rmmod vtfs
    echo "Module unloaded"
fi