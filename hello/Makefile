ifneq ($(KERNELRELEASE),)
	obj-m := hello.o #shellcode.o
else
	PWD := $(shell pwd)
	KDIR := $(PWD)/../linux-3.0
	KERNELDIR ?= $(KDIR)/build

shellcode: shellcode.o
	ld -o shellcode shellcode.o --entry=entry -s --oformat=binary -Ttext=0 --omagic
	bin2shell/bin2shell shellcode > shellcode.string
	cat shellcode |wc -c >shellcode.length


shellcode.o: shellcode.c shellcode.h shellcode-config.h Makefile
	$(CC) \
	-c \
	-nostdlib \
	-nostartfiles \
	-fno-stack-protector \
	-fomit-frame-pointer \
	-fno-dwarf2-cfi-asm \
	-fno-exceptions \
	-fno-asynchronous-unwind-tables \
	 shellcode.c \
	 -fno-ident \
	-mno-red-zone \
	-o shellcode.o 

module: 
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f shellcode.o shellcode.ascii shellcode shellcode.string shellcode.length shellcode-config.old
endif
