MODULE_NAME := vtfs
$(MODULE_NAME)-objs := vtfs_main.o vtfs_super.o vtfs_inode.o vtfs_dir.o vtfs_file.o http.o
obj-m := $(MODULE_NAME).o

KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers