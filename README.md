# AKFS - AKarpov File System

AKFS is a Linux kernel **virtual filesystem** (kernel module `vtfs`) backed by a **Go HTTP API** with **PostgreSQL** storage.

It supports common file/directory operations, **hard links**, persistence (data survives remounts), and **token-gated write access**:
- **No token** → mount is **read-only**
- **Token provided** → mount is **read-write** (backend validates via `X-Auth-Token`)

## Architecture
```
┌───────────────────────────────┐
│           User space          │
│   tools: ls, cat, echo, cp    │
└───────────────┬───────────────┘
                │ VFS syscalls
                ▼
┌───────────────────────────────┐
│           Linux VFS           │
│   (superblock, inodes, dentry │
│    file ops: lookup/read/...) │
└───────────────┬───────────────┘
                │ vfs -> vtfs ops
                ▼
┌───────────────────────────────┐
│        VTFS kernel module     │
│   - implements VFS callbacks  │
│   - parses mount opts (token) │
│   - read-only if no token     │
│   - HTTP client (kernel TCP)  │
└───────────────┬───────────────┘
                │ HTTP/JSON
                ▼
┌───────────────────────────────┐
│        Go HTTP API backend    │
│   endpoints: /api/v1/*        │
│   - auth via X-Auth-Token     │
│   - enforces size quota       │
│   - maps ops -> repository    │
└───────────────┬───────────────┘
                │ SQL
                ▼
┌───────────────────────────────┐
│           PostgreSQL          │
│   tables: inodes, dir_entries │
│           file_content        │
└───────────────────────────────┘
```

## Requirements

### Backend (Server)
- Docker + Docker Compose  
  **OR**
- Go **1.24+**
- PostgreSQL **16+**

### Kernel Module (Client VM)
- Linux kernel 6.x (tested on 6.1, 6.5, 6.8, 6.11)
- Build tools + headers:
  - Debian/Ubuntu: `build-essential linux-headers-$(uname -r)`

## Quick Start

### 1) Start the Backend Server
```bash
git clone https://github.com/Alexander-D-Karpov/akfs.git
cd akfs

# Start PostgreSQL + API server
docker compose up -d --build

# Verify health
curl http://localhost:8080/health
````

> Config is read from environment variables. See **Configuration** below.

### 2) Build and Load the Kernel Module (on VM)

```bash
# Debian/Ubuntu deps
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r)

# Build module
make kernel-build

# Load module
make kernel-load

# Verify
lsmod | grep vtfs
dmesg | tail -20
```

### 3) Mount the Filesystem

#### Read-only mount (no token)

```bash
sudo mkdir -p /mnt/vtfs
sudo mount -t vtfs "http://127.0.0.1:8080" /mnt/vtfs
```

#### Read-write mount (token required)

```bash
sudo mkdir -p /mnt/vtfs
sudo mount -t vtfs -o token="admin" "http://127.0.0.1:8080" /mnt/vtfs
```

Now try it:

```bash
cd /mnt/vtfs
echo "Hello AKFS" | sudo tee hello.txt >/dev/null
cat hello.txt
mkdir dir1
ls -la
```

### 4) Unmount / Unload

```bash
make unmount
make kernel-unload
```

## Configuration

### Backend environment variables

Used by `docker-compose.yml` (defaults shown):

* `POSTGRES_PASSWORD` (default: `vtfs_secret_password`)
* `VTFS_TOKEN` (default: `admin`)
  Token required for **mutating** operations (`create`, `mkdir`, `unlink`, `rmdir`, `write`, `link`)
* `VTFS_MAX_SIZE` (default: `2147483648`)
  Maximum total filesystem size in bytes (default ~2 GiB)
* `PORT` (default: `8080`)
* `LOG_LEVEL` (default: `info`)
* `DATABASE_URL` (compose sets it automatically for the `api` container)

You can set these in a project-level `.env` file (not committed) or export them in your shell before running Docker.

### Mount options

* `token=<value>`
  Enables write access from the kernel module. Without a token, the FS is mounted **read-only** (and VFS operations that modify state will fail with `EROFS`).

Example:

```bash
sudo mount -t vtfs -o token="admin" "http://127.0.0.1:8080" /mnt/vtfs
```

## Features

* [x] Mount/unmount filesystem
* [x] Read-only mount without token
* [x] Read/write mount with token
* [x] Create/delete files (`touch`, `rm`, `echo >`)
* [x] Create/delete directories (`mkdir`, `rmdir`)
* [x] Read/write files (`cat`, `echo`, `tee`)
* [x] Hard links (`ln`)
* [x] Directory listing (`ls`)
* [x] Persistent storage (survives remount)
* [x] Multi-client visibility (changes visible across mounts)
* [x] Backend quota enforcement (`VTFS_MAX_SIZE`)

## API Endpoints

All endpoints are JSON over HTTP. Write operations require header `X-Auth-Token: <VTFS_TOKEN>`.

| Method | Endpoint         | Description                        |
| ------ | ---------------- | ---------------------------------- |
| POST   | `/api/v1/lookup` | Find entry by name                 |
| POST   | `/api/v1/list`   | List directory contents            |
| POST   | `/api/v1/create` | Create file *(auth)*               |
| POST   | `/api/v1/mkdir`  | Create directory *(auth)*          |
| POST   | `/api/v1/unlink` | Delete file *(auth)*               |
| POST   | `/api/v1/rmdir`  | Delete directory *(auth)*          |
| POST   | `/api/v1/read`   | Read file content                  |
| POST   | `/api/v1/write`  | Write file content *(auth, quota)* |
| POST   | `/api/v1/link`   | Create hard link *(auth)*          |
| GET    | `/api/v1/stats`  | FS usage (total/max/available)     |
| GET    | `/health`        | Health check                       |

## Makefile shortcuts

From the repository root:

```bash
make docker-up        # docker compose up -d --build
make docker-down
make docker-logs

make kernel-build     # build kernel module in ./kernel
make kernel-load
make kernel-unload
make kernel-reload

make mount            # mounts at /mnt/vtfs using http://localhost:8080 (no token => read-only)
make unmount

make test             # runs ./scripts/test-fs.sh
make clean            # kernel-clean + docker-down
```

## Development

### Run backend locally (without Docker)

```bash
cd backend
go mod download

export DATABASE_URL="postgres://vtfs:vtfs@localhost:5432/vtfs?sslmode=disable"
export PORT=8080
export LOG_LEVEL=info
export VTFS_TOKEN=admin
export VTFS_MAX_SIZE=2147483648

go run ./cmd/server
```

### Run tests

```bash
# Backend unit tests
cd backend && go test ./...

# Integration tests (requires backend running and kernel module buildable)
./scripts/test-fs.sh
```

## License

MIT (see `LICENSE`)
