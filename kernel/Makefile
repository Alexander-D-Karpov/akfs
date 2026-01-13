obj-m += vtfs.o
vtfs-objs := vtfs_main.o vtfs_super.o vtfs_inode.o vtfs_dir.o vtfs_file.o \
             vtfs_net.o vtfs_crypto.o vtfs_proto.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ccflags-y := -DDEBUG -g -Wall

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers

install: all
	sudo insmod vtfs.ko

uninstall:
	sudo rmmod vtfs || true

reload: uninstall install

.PHONY: all clean install uninstall reload
