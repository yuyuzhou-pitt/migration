ifneq ($(KERNELRELEASE),)
	obj-m := virtunoid-module.o
	KBUILD_CFLAGS := $(filter-out -pg, $(KBUILD_CFLAGS))
else
	KDIR ?= ../src/linux-3.0/
	PWD := $(shell pwd)

all: hello initrd

hello:
	make -C $(KDIR) M=$(PWD) modules

initrd:
	mkdir -p out
	cp hello.ko out/hello.ko
	cp init out/init
	chmod +x out/init
	mkdir -p out/proc
	mkdir -p out/bin
	cp ../src/busybox-1.17.1/busybox out/bin/busybox
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
