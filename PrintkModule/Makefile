ifneq ($(KERNELRELEASE),)
	# kbuild part of makefile
	obj-m  := printkfunc.o
	#ccflags-y := -UCONFIG_FUNCTION_TRACER
	KBUILD_CFLAGS := $(filter-out -pg, $(KBUILD_CFLAGS))

else
	# normal makefile
	KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

endif
