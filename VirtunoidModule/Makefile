MODULE_NAME=virtunoid-module

ifneq ($(KERNELRELEASE),)
	obj-m := $(MODULE_NAME).o
	# filter function tracer: __fentry__
	KBUILD_CFLAGS := $(filter-out -pg, $(KBUILD_CFLAGS))
	# filter all the .debug_xxx sections
	KBUILD_CFLAGS := $(filter-out -g, $(KBUILD_CFLAGS))
	# do not check stack overflow : __stack_chk_fail-0x4
	KBUILD_CFLAGS += -fno-stack-protector
else
	KDIR ?= ~/undermining/src/linux-3.0/
	PWD := $(shell pwd)

all: virtunoid initrd

virtunoid:
	make -C $(KDIR) M=$(PWD) modules

initrd:
	mkdir -p out
	cp $(MODULE_NAME).ko out/virtunoid.ko
	cp init out/init
	chmod +x out/init
	mkdir -p out/proc
	mkdir -p out/bin
	cp ~/undermining/src/busybox-1.17.1/busybox out/bin/busybox
	ln -sf busybox out/bin/ls
	ln -sf busybox out/bin/mknod
	ln -sf busybox out/bin/mount
	ln -sf busybox out/bin/ifconfig
	ln -sf busybox out/bin/udhcpc
	ln -sf busybox out/bin/insmod
	ln -sf busybox out/bin/sh
	ln -sf busybox out/bin/ping
	ln -sf busybox out/bin/dmesg
	ln -sf busybox out/bin/grep
	ln -sf busybox out/bin/less
	(cd out && find | cpio -o -Hnewc) > initrd
	gzip -f initrd

clean: 
	make -C $(KDIR) M=$(PWD) clean
	rm -fR out
	rm initrd.gz
endif
