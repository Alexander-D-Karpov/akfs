.PHONY: all build clean docker-up docker-down kernel-build kernel-load kernel-unload test

all: build

build: docker-up kernel-build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

kernel-build:
	$(MAKE) -C kernel

kernel-clean:
	$(MAKE) -C kernel clean

kernel-load:
	sudo insmod kernel/vtfs.ko

kernel-unload:
	-sudo umount /mnt/vtfs 2>/dev/null || true
	-sudo rmmod vtfs 2>/dev/null || true

kernel-reload: kernel-unload kernel-load

mount:
	sudo mkdir -p /mnt/vtfs
	sudo mount -t vtfs "http://localhost:8080" /mnt/vtfs

unmount:
	sudo umount /mnt/vtfs

test:
	./scripts/test-fs.sh

clean: kernel-clean docker-down