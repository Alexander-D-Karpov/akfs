.PHONY: all clean build-backend build-kernel run stop status wait-server \
        load-module unload-module mount mount-ro umount test help

MODULE_NAME ?= vtfs
KMOD_PATH ?= kernel/vtfs.ko
MOUNT_POINT ?= /mnt/vtfs
SERVER_HOST ?= 127.0.0.1
SERVER_PORT ?= 9000
TOKEN ?= admin
KEY ?= 0123456789abcdef0123456789abcdef

DOCKER ?= docker
COMPOSE ?= $(DOCKER) compose

help:
	@echo "VTFS - Virtual Filesystem with TCP Backend"
	@echo ""
	@echo "Usage:"
	@echo "  make build-backend    Build the Go backend server"
	@echo "  make build-kernel     Build the kernel module"
	@echo "  make all              Build everything"
	@echo "  make run              Start the backend server (Docker)"
	@echo "  make stop             Stop the backend server"
	@echo "  make mount            Mount the filesystem (RW when TOKEN set)"
	@echo "  make mount-ro         Mount the filesystem read-only"
	@echo "  make umount           Unmount + unload module"
	@echo "  make test             Run filesystem tests"
	@echo "  make clean            Clean build artifacts"
	@echo ""
	@echo "Configuration:"
	@echo "  MOUNT_POINT=$(MOUNT_POINT)"
	@echo "  SERVER_HOST=$(SERVER_HOST)"
	@echo "  SERVER_PORT=$(SERVER_PORT)"

all: build-backend build-kernel

build-backend:
	cd backend && go build -o bin/vtfs-server ./cmd/server

build-kernel:
	$(MAKE) -C kernel

run:
	$(COMPOSE) up -d --build --remove-orphans

stop:
	docker compose down --remove-orphans -t 1

status:
	$(COMPOSE) ps

wait-server:
	@echo "Waiting for $(SERVER_HOST):$(SERVER_PORT)..."
	@for i in $$(seq 1 50); do \
		nc -z $(SERVER_HOST) $(SERVER_PORT) >/dev/null 2>&1 && exit 0; \
		sleep 0.2; \
	done; \
	echo "Backend not reachable on $(SERVER_HOST):$(SERVER_PORT)"; \
	$(COMPOSE) logs --tail=50 vtfs-server || true; \
	exit 1

unload-module:
	@# Unmount first (module removal will fail if still mounted)
	@mountpoint -q $(MOUNT_POINT) && sudo umount $(MOUNT_POINT) || true
	@# Remove module only if it is actually loaded
	@if lsmod | grep -q '^$(MODULE_NAME)\b'; then \
		echo "Unloading $(MODULE_NAME)..."; \
		sudo modprobe -r $(MODULE_NAME) 2>/dev/null || sudo rmmod $(MODULE_NAME); \
		for i in $$(seq 1 30); do \
			lsmod | grep -q '^$(MODULE_NAME)\b' || exit 0; \
			sleep 0.1; \
		done; \
		echo "ERROR: $(MODULE_NAME) is still loaded (busy)."; \
		echo "Try: sudo lsof +f -- $(MOUNT_POINT)"; \
		exit 1; \
	else \
		echo "$(MODULE_NAME) not loaded."; \
	fi


load-module:
	@# If already loaded, don’t fail (prevents 'File exists')
	@if lsmod | grep -q '^$(MODULE_NAME)\b'; then \
		echo "$(MODULE_NAME) already loaded; skipping insmod."; \
	else \
		echo "Loading $(MODULE_NAME)..."; \
		sudo insmod $(KMOD_PATH); \
	fi

reload-module: unload-module
	@echo "Reloading $(MODULE_NAME)..."
	@sudo insmod $(KMOD_PATH)

mount: build-kernel run wait-server load-module
	@mkdir -p $(MOUNT_POINT)
	@mountpoint -q $(MOUNT_POINT) && sudo umount $(MOUNT_POINT) || true
	sudo mount -t vtfs none $(MOUNT_POINT) \
		-o host=$(SERVER_HOST),port=$(SERVER_PORT),token=$(TOKEN),key=$(KEY)
	@echo "Mounted VTFS at $(MOUNT_POINT)"

mount-ro: build-kernel run wait-server load-module
	@mkdir -p $(MOUNT_POINT)
	@mountpoint -q $(MOUNT_POINT) && sudo umount $(MOUNT_POINT) || true
	sudo mount -t vtfs none $(MOUNT_POINT) \
		-o host=$(SERVER_HOST),port=$(SERVER_PORT),key=$(KEY)
	@echo "Mounted VTFS (read-only) at $(MOUNT_POINT)"

umount:
	@mountpoint -q $(MOUNT_POINT) && sudo umount $(MOUNT_POINT) || true
	@$(MAKE) unload-module

test: mount
	@echo "Running filesystem tests..."
	./scripts/test-fs.sh $(MOUNT_POINT)
	@echo "Tests completed"

clean:
	$(MAKE) -C kernel clean
	rm -rf backend/bin
	$(COMPOSE) down -v --remove-orphans || true
