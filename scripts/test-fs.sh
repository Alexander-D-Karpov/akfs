#!/bin/bash

set -e

MOUNT_POINT="${1:-/mnt/vtfs}"
PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((++PASS))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((++FAIL))
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

cleanup() {
    log_info "Cleaning up test files..."
    rm -rf "$MOUNT_POINT/test_dir" 2>/dev/null || true
    rm -f "$MOUNT_POINT/test_file.txt" 2>/dev/null || true
    rm -f "$MOUNT_POINT/test_link.txt" 2>/dev/null || true
    rm -f "$MOUNT_POINT/large_file.bin" 2>/dev/null || true
    sync 2>/dev/null || true
}

trap cleanup EXIT

log_info "Starting VTFS tests on $MOUNT_POINT"
echo ""

cleanup
sleep 1

log_info "Test 1: Check mount point exists"
if [ -d "$MOUNT_POINT" ]; then
    log_pass "Mount point exists"
else
    log_fail "Mount point does not exist"
    exit 1
fi

log_info "Test 2: Create file"
if echo "Hello, VTFS!" > "$MOUNT_POINT/test_file.txt"; then
    sync
    log_pass "File created"
else
    log_fail "Failed to create file"
fi

log_info "Test 3: Read file"
sleep 0.5
CONTENT=$(cat "$MOUNT_POINT/test_file.txt")
if [ "$CONTENT" = "Hello, VTFS!" ]; then
    log_pass "File content correct"
else
    log_fail "File content mismatch: got '$CONTENT'"
fi

log_info "Test 4: Append to file"
echo " More data." >> "$MOUNT_POINT/test_file.txt"
sync
sleep 0.5
CONTENT=$(cat "$MOUNT_POINT/test_file.txt")
if echo "$CONTENT" | grep -q "More data"; then
    log_pass "Append successful"
else
    log_fail "Append failed"
fi

log_info "Test 5: File size check"
SIZE=$(stat -c%s "$MOUNT_POINT/test_file.txt" 2>/dev/null || stat -f%z "$MOUNT_POINT/test_file.txt" 2>/dev/null)
if [ "$SIZE" -gt 0 ]; then
    log_pass "File size is $SIZE bytes"
else
    log_fail "File size is 0"
fi

log_info "Test 6: Create directory"
if mkdir "$MOUNT_POINT/test_dir"; then
    log_pass "Directory created"
else
    log_fail "Failed to create directory"
fi

log_info "Test 7: Create file in directory"
if echo "Nested file" > "$MOUNT_POINT/test_dir/nested.txt"; then
    sync
    log_pass "Nested file created"
else
    log_fail "Failed to create nested file"
fi

log_info "Test 8: List directory"
sleep 0.5
if ls "$MOUNT_POINT/test_dir" | grep -q "nested.txt"; then
    log_pass "Directory listing works"
else
    log_fail "Directory listing failed"
fi

log_info "Test 9: Hard link"
if ln "$MOUNT_POINT/test_file.txt" "$MOUNT_POINT/test_link.txt" 2>/dev/null; then
    sync
    sleep 1
    ORIG_CONTENT=$(cat "$MOUNT_POINT/test_file.txt" 2>/dev/null || echo "")
    LINK_CONTENT=$(cat "$MOUNT_POINT/test_link.txt" 2>/dev/null || echo "")
    if [ -n "$LINK_CONTENT" ] && [ "$ORIG_CONTENT" = "$LINK_CONTENT" ]; then
        log_pass "Hard link works"
    else
        log_fail "Hard link content mismatch (orig='$ORIG_CONTENT' link='$LINK_CONTENT')"
    fi
else
    log_fail "Hard link creation failed"
fi

log_info "Test 10: Delete file"
if rm "$MOUNT_POINT/test_link.txt" 2>/dev/null; then
    sync
    sleep 0.5
    if [ ! -f "$MOUNT_POINT/test_link.txt" ]; then
        log_pass "File deleted"
    else
        log_fail "File still exists after delete"
    fi
else
    log_fail "Failed to delete file"
fi

log_info "Test 11: Delete nested file"
if rm "$MOUNT_POINT/test_dir/nested.txt"; then
    sync
    log_pass "Nested file deleted"
else
    log_fail "Failed to delete nested file"
fi

log_info "Test 12: Remove directory"
sleep 0.5
if rmdir "$MOUNT_POINT/test_dir"; then
    sync
    sleep 0.5
    if [ ! -d "$MOUNT_POINT/test_dir" ]; then
        log_pass "Directory removed"
    else
        log_fail "Directory still exists after rmdir"
    fi
else
    log_fail "Failed to remove directory"
fi

log_info "Test 13: Large file write"
dd if=/dev/urandom of="$MOUNT_POINT/large_file.bin" bs=1024 count=1024 2>/dev/null
sync
sleep 0.5
LARGE_SIZE=$(stat -c%s "$MOUNT_POINT/large_file.bin" 2>/dev/null || stat -f%z "$MOUNT_POINT/large_file.bin" 2>/dev/null)
if [ "$LARGE_SIZE" -eq 1048576 ]; then
    log_pass "Large file write (1MB)"
else
    log_fail "Large file size mismatch: got $LARGE_SIZE, expected 1048576"
fi

log_info "Test 14: File permissions"
if [ -r "$MOUNT_POINT/test_file.txt" ] && [ -w "$MOUNT_POINT/test_file.txt" ]; then
    log_pass "File permissions correct"
else
    log_fail "File permissions incorrect"
fi

log_info "Test 15: du command (i_blocks)"
DU_OUTPUT=$(du -h "$MOUNT_POINT/large_file.bin" 2>/dev/null | cut -f1)
if [ -n "$DU_OUTPUT" ] && [ "$DU_OUTPUT" != "0" ]; then
    log_pass "du reports $DU_OUTPUT"
else
    log_fail "du reports 0 or empty (i_blocks not set)"
fi

echo ""
echo "================================"
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi

exit 0