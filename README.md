# AKFS - Virtual Filesystem with TCP Backend

A Linux kernel module implementing a virtual filesystem that stores data on a remote server using a custom binary protocol over TCP with AES-GCM encryption.

## Architecture

```
+------------------------------------------------------------------------------+
|                                 Linux Kernel                                 |
+------------------------------------------------------------------------------+
| VFS                                                                          |
+------------------------------------------------------------------------------+
| AKFS Kernel FS                                                               |
|   - Superblock Ops (mount/statfs)                                            |
|   - Inode Ops (lookup/getattr)                                               |
|   - File/Dir Ops (readdir/read/write)                                        |
+------------------------------------------------------------------------------+
| Client Core                                                                  |
|   - Mount Opts/Auth                                                          |
|   - RPC Mux (TxnID)                                                          |
|   - Retry/Timeout                                                            |
|   - Page Cache/Readahead                                                     |
|   - Workqueue I/O (async)                                                    |
|   - Notify Bridge (watch events)                                             |
+------------------------------------------------------------------------------+
| Transport + Crypto (Kernel)                                                  |
|   - TCP Socket Client (connect/send/recv)                                    |
|   - AES-256-GCM (AEAD): nonce mgmt + KDF + header AAD                        |
+------------------------------------------------------------------------------+

                                       |
                        TCP/9000 (encrypted frames)
                                       v

+------------------------------------------------------------------------------+
|                              Go Backend Server                               |
+------------------------------------------------------------------------------+
| TCP Listener                                                                 |
|   - Conn Acceptor (per-client goroutine)                                     |
|   - Session/Auth Manager (token, RO/RW)                                      |
|   - Notify Hub (watchers)                                                    |
+------------------------------------------------------------------------------+
| Protocol + Crypto Layer                                                      |
|   - Frame/Opcode Parser (len/op/flags/txn)                                   |
|   - AES-256-GCM (AEAD): nonce mgmt + KDF + AAD                               |
+------------------------------------------------------------------------------+
| Storage Engine                                                               |
|   - Metadata/Inodes + Directories                                            |
|   - Page Manager / Allocator                                                 |
|   - Cache (LRU) + read-through                                               |
|   - WAL/Journal + crash recovery + writeback/sync                            |
+------------------------------------------------------------------------------+
| data.bin + WAL (single-file storage)                                         |
+------------------------------------------------------------------------------+
```

## Features

- **Binary Protocol**: Custom length-prefixed protocol with little-endian encoding
- **AES-256-GCM Encryption**: Authenticated encryption for all data in transit
- **Single-File Storage**: All data stored in a single disk image file
- **Write-Ahead Logging**: Crash recovery support
- **LRU Caching**: In-memory cache for improved performance
- **Directory Watch Notifications**: Real-time updates for watched directories
- **Multi-client Support**: Multiple simultaneous connections
- **Kernel 5.12 - 6.11+ Compatibility**: Works across multiple kernel versions (tested on 6.18.3)

## Requirements

### Build Requirements
- Linux kernel headers (5.12 - 6.11+)
- Go 1.22+
- Docker & Docker Compose (optional)
- GCC, make

### Runtime Requirements
- Linux kernel with crypto API support (gcm(aes), sha256)
- Network connectivity to backend server

## Quick Start

### 1. Start the Backend Server

Using Docker:
```bash
make run
```

Or build and run manually:
```bash
make build-backend
VTFS_LISTEN=0.0.0.0:9000 ./backend/bin/vtfs-server
```

### 2. Build and Load the Kernel Module

```bash
make build-kernel
sudo insmod kernel/vtfs.ko
```

### 3. Mount the Filesystem

Read-write mode (with token):
```bash
sudo mkdir -p /mnt/vtfs
sudo mount -t vtfs none /mnt/vtfs \
    -o host=127.0.0.1,port=9000,token=admin,key=default-encryption-key-32bytes!
```

Read-only mode (without token):
```bash
sudo mount -t vtfs none /mnt/vtfs \
    -o host=127.0.0.1,port=9000,key=default-encryption-key-32bytes!
```

### 4. Run Tests

```bash
make test
```

## Mount Options

| Option | Description | Default |
|--------|-------------|---------|
| `host` | Backend server IP address | 127.0.0.1 |
| `port` | Backend server port | 9000 |
| `token` | Authentication token (enables write access) | (none) |
| `key` | Encryption key passphrase | default-encryption-key-32bytes! |

## Configuration (Backend Server)

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `VTFS_LISTEN` | Listen address | 0.0.0.0:9000 |
| `VTFS_STORAGE` | Storage file path | /var/lib/vtfs/data.bin |
| `VTFS_WAL` | WAL file path | /var/lib/vtfs/data.wal |
| `VTFS_MAX_SIZE` | Maximum filesystem size (bytes) | 2147483648 (2GB) |
| `VTFS_TOKEN` | Authentication token | admin |
| `VTFS_KEY` | Encryption key passphrase | default-encryption-key-32bytes! |
| `LOG_LEVEL` | Log level | info |

## Protocol

Binary protocol with 24-byte header:

```
┌────────┬────────┬────────┬────────────────┬────────────────┐
│ Length │ Opcode │ Flags  │     TxnID      │    NodeID      │
│ 4 bytes│ 2 bytes│ 2 bytes│    8 bytes     │    8 bytes     │
└────────┴────────┴────────┴────────────────┴────────────────┘
```

Operations:
- `0x01` INIT - Initialize connection
- `0x10` LOOKUP - Lookup file/directory by name
- `0x11` GETATTR - Get inode attributes
- `0x20` READDIR - List directory contents
- `0x30` CREATE - Create file
- `0x31` MKDIR - Create directory
- `0x32` UNLINK - Delete file
- `0x33` RMDIR - Delete directory
- `0x34` LINK - Create hard link
- `0x35` RENAME - Rename file/directory
- `0x40` READ - Read file data
- `0x41` WRITE - Write file data
- `0x42` TRUNCATE - Truncate file
- `0x50` WATCH - Subscribe to directory changes
- `0x51` UNWATCH - Unsubscribe from directory changes
- `0x52` NOTIFY - Server notification (async)

## Storage Format

Single-file storage with page-based layout (4KB pages):

```
Page 0:     Superblock
Page 1:     Superblock backup
Page 2-65:  Inode table (64 pages)
Page 66+:   Data pages
```

Inode structure (128 bytes):
- Inode number (8 bytes)
- Mode (4 bytes)
- Nlink (4 bytes)
- Size (8 bytes)
- Timestamps (24 bytes)
- Data page pointers (up to 16)

## Development

### Project Structure

```
akfs/
├── backend/
│   ├── cmd/server/main.go      # Server entry point
│   └── internal/
│       ├── config/             # Configuration
│       ├── crypto/             # AES-GCM encryption
│       ├── domain/             # Domain types
│       ├── protocol/           # Binary protocol
│       ├── server/             # TCP server & handlers
│       └── storage/            # Storage engine
├── kernel/
│   ├── vtfs.h                  # Main header
│   ├── vtfs_compat.h           # Kernel compatibility
│   ├── vtfs_main.c             # Module init/exit
│   ├── vtfs_super.c            # Superblock operations
│   ├── vtfs_inode.c            # Inode operations
│   ├── vtfs_dir.c              # Directory operations
│   ├── vtfs_file.c             # File operations
│   ├── vtfs_net.c              # Network layer
│   ├── vtfs_crypto.c           # Kernel crypto
│   ├── vtfs_proto.c            # Protocol handling
│   └── Makefile
├── scripts/
│   └── test-fs.sh              # Test script
├── docker-compose.yml
├── Makefile
└── README.md
```

### Building for Different Kernels

```bash
# Build for current kernel
make build-kernel

# Build for specific kernel
make build-kernel KDIR=/usr/src/linux-headers-6.1.0
```

## Troubleshooting

### Cannot connect to server
- Check server is running: `docker-compose logs`
- Check firewall: `sudo iptables -L`
- Verify IP/port: `nc -zv 127.0.0.1 9000`

### Module won't load
- Check kernel version compatibility
- Check dmesg: `dmesg | tail -20`
- Verify crypto modules: `lsmod | grep aes`

### Mount fails
- Check dmesg for errors
- Verify encryption key matches on both sides
- Test connection: `nc -zv <host> <port>`

### Permission denied
- Mount without token = read-only mode
- Mount with token for write access

## License

GPL v2
