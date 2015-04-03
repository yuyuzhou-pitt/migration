ifneq ($(KERNELRELEASE),)
	# kbuild part of makefile
	obj-m  := printkfunc.o
	#ccflags-y := -UCONFIG_FUNCTION_TRACER

	# filter function tracer: __fentry__
	KBUILD_CFLAGS := $(filter-out -pg, $(KBUILD_CFLAGS))
	# filter all the .debug_xxx sections
	KBUILD_CFLAGS := $(filter-out -g, $(KBUILD_CFLAGS))
	# do not check stack overflow : __stack_chk_fail-0x4
	KBUILD_CFLAGS += -fno-stack-protector

else
	# normal makefile
	KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	rm modules.order  Module.symvers  printkfunc.ko  printkfunc.mod.c *.o

endif
