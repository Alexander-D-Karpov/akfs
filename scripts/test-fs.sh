#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

MOUNT_POINT="/mnt/vtfs"
MOUNT_POINT_RO="/mnt/vtfs_ro"
MODULE="vtfs"
TOKEN="admin"

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    exit 1
}

cleanup() {
    sudo umount "$MOUNT_POINT" 2>/dev/null || true
    sudo umount "$MOUNT_POINT_RO" 2>/dev/null || true
    sudo rmmod "$MODULE" 2>/dev/null || true
}

trap cleanup EXIT

cleanup

if ! lsmod | grep -q "^${MODULE}"; then
    echo "Loading module..."
    sudo insmod kernel/${MODULE}.ko || fail "Failed to load module"
fi
pass "Module loaded"

sudo mkdir -p "$MOUNT_POINT"
sudo mount -t vtfs -o token="$TOKEN" "http://127.0.0.1:8080" "$MOUNT_POINT" || fail "Failed to mount with token"
pass "Filesystem mounted with write access at $MOUNT_POINT"

echo ""
echo "--- File Operations ---"

echo "hello world" | sudo tee "$MOUNT_POINT/test.txt" > /dev/null
[ -f "$MOUNT_POINT/test.txt" ] || fail "File not created"
pass "Create file (touch/echo)"

CONTENT=$(cat "$MOUNT_POINT/test.txt")
[ "$CONTENT" = "hello world" ] || fail "Content mismatch: got '$CONTENT'"
pass "Read file (cat)"

echo "updated content" | sudo tee "$MOUNT_POINT/test.txt" > /dev/null
CONTENT=$(cat "$MOUNT_POINT/test.txt")
[ "$CONTENT" = "updated content" ] || fail "Update failed"
pass "Write file (echo >)"

echo ""
echo "--- Directory Operations ---"

sudo mkdir "$MOUNT_POINT/subdir" || fail "mkdir failed"
[ -d "$MOUNT_POINT/subdir" ] || fail "Directory not created"
pass "Create directory (mkdir)"

ls "$MOUNT_POINT" | grep -q "subdir" || fail "Directory not listed"
pass "List directory (ls)"

echo "nested file" | sudo tee "$MOUNT_POINT/subdir/nested.txt" > /dev/null
[ -f "$MOUNT_POINT/subdir/nested.txt" ] || fail "Nested file not created"
pass "Create nested file"

echo ""
echo "--- Hard Links ---"

sudo ln "$MOUNT_POINT/test.txt" "$MOUNT_POINT/test_link.txt" || fail "link failed"
[ -f "$MOUNT_POINT/test_link.txt" ] || fail "Hard link not created"
pass "Create hard link (ln)"

NLINK=$(stat -c %h "$MOUNT_POINT/test.txt")
[ "$NLINK" = "2" ] || fail "nlink should be 2, got $NLINK"
pass "Hard link nlink count"

LINK_CONTENT=$(cat "$MOUNT_POINT/test_link.txt")
[ "$LINK_CONTENT" = "updated content" ] || fail "Hard link content mismatch"
pass "Hard link content"

echo ""
echo "--- Read-Only Mount Test ---"

sudo mkdir -p "$MOUNT_POINT_RO"
sudo mount -t vtfs "http://127.0.0.1:8080" "$MOUNT_POINT_RO" || fail "Failed to mount read-only"
pass "Read-only mount successful"

if echo "test" | sudo tee "$MOUNT_POINT_RO/readonly_test.txt" > /dev/null 2>&1; then
    fail "Write should have failed on read-only mount"
fi
pass "Write blocked on read-only mount"

RO_CONTENT=$(cat "$MOUNT_POINT_RO/test.txt")
[ "$RO_CONTENT" = "updated content" ] || fail "Read-only read failed"
pass "Read works on read-only mount"

sudo umount "$MOUNT_POINT_RO"
pass "Read-only unmount successful"

echo ""
echo "--- Multi-client visibility test ---"

echo "multi-client test" | sudo tee "$MOUNT_POINT/multi.txt" > /dev/null
sudo mount -t vtfs "http://127.0.0.1:8080" "$MOUNT_POINT_RO" || fail "Failed to remount"
MULTI_CONTENT=$(cat "$MOUNT_POINT_RO/multi.txt")
[ "$MULTI_CONTENT" = "multi-client test" ] || fail "Multi-client visibility failed"
pass "Changes visible across mounts"
sudo umount "$MOUNT_POINT_RO"

echo ""
echo "--- Cleanup ---"

sudo rm "$MOUNT_POINT/test.txt" || fail "unlink failed"
[ ! -f "$MOUNT_POINT/test.txt" ] || fail "File still exists after unlink"
pass "Delete file (rm)"

REMAINING=$(cat "$MOUNT_POINT/test_link.txt")
[ "$REMAINING" = "updated content" ] || fail "Hard link data lost after unlink"
pass "Hard link survives original deletion"

sudo rm "$MOUNT_POINT/test_link.txt"
sudo rm "$MOUNT_POINT/multi.txt"
sudo rm "$MOUNT_POINT/subdir/nested.txt"
sudo rmdir "$MOUNT_POINT/subdir" || fail "rmdir failed"
[ ! -d "$MOUNT_POINT/subdir" ] || fail "Directory still exists"
pass "Delete directory (rmdir)"

echo ""
echo "--- Persistence Test ---"

echo "persist me" | sudo tee "$MOUNT_POINT/persist.txt" > /dev/null
sudo umount "$MOUNT_POINT"
pass "Unmount"

sudo mount -t vtfs -o token="$TOKEN" "http://127.0.0.1:8080" "$MOUNT_POINT"
PERSIST_CONTENT=$(cat "$MOUNT_POINT/persist.txt")
[ "$PERSIST_CONTENT" = "persist me" ] || fail "Data not persisted"
pass "Data persisted after remount"

sudo rm "$MOUNT_POINT/persist.txt"

echo ""
echo -e "${GREEN}=== All tests passed ===${NC}"