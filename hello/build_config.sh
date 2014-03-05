#!/bin/bash

cd ../qemu-kvm-0.14.0+noroms;dpkg-buildpackage
cd ..;sudo dpkg -i qemu-kvm*deb
cd hello;

mv shellcode-config.h shellcode-config.old
X=shellcode-config.h
KVM=/usr/bin/kvm

echo $'#define FORK\t0x'`objdump -t ${KVM} |grep fork@@|cut -b-16` >> shellcode-config.h
echo $'#define EXECV\t0x'`objdump -t ${KVM} |grep execv@@|cut -b-16` >> shellcode-config.h
echo "">>$X
echo $'#define RTC_UPDATE_SECOND\t0x'`objdump -t ${KVM} |grep rtc_update_second$|cut -b-16` >> shellcode-config.h
echo "" >>$X
echo '#define SIZEOF_RTCSTATE                  488' >> $X
echo '#define OFFSET_RTCSTATE_NEXT_SECOND_TIME 0x1b8' >> $X
echo '#define OFFSET_RTCSTATE_SECOND_TIMER     0x1d8' >> $X
echo "" >>$X
echo $'#define SCSI_REQ_COMPLETE\t0x'`objdump -t ${KVM} |grep scsi_req_complete|cut -b-16` >> shellcode-config.h
echo $'#define SCSI_READ_COMPLETE\t0x'`objdump -t ${KVM} |grep scsi_read_complete|cut -d$'\n' -f2|cut -b-16` >> shellcode-config.h
echo $'#define MPROTECT\t0x'`objdump -t ${KVM} |grep mprotect|cut -b-16` >> shellcode-config.h
echo "" >> $X
echo $'#define ISA_UNASSIGN_IOPORT\t0x'`objdump -t ${KVM} |grep isa_unassign_ioport|cut -b-16` >> shellcode-config.h
echo "" >> $X
echo $'#define CLOCK_HVA\t0x'`objdump -t ${KVM} |grep arch_config_name|cut -b-16`'+0xc4' >> shellcode-config.h
#echo $'#define CLOCK_HVA\t0x'`objdump -t ${KVM} |grep CLOCK_HVA|cut -b-16` >> shellcode-config.h
echo "" >> $X
echo $'#define CPU_OUTL\t0x'`objdump -t ${KVM} |grep cpu_outl|cut -b-16` >> shellcode-config.h
echo "" >> $X
echo '#define SIZEOF_BUS_STATE        56' >> $X
echo '#define SIZEOF_SCSI_REQUEST     112' >> $X
echo '#define SIZEOF_SCSI_GENERIC_REQ 216' >> $X
echo "" >> $X
echo $'#define IOPORT_WRITEB_THUNK\t0x'`objdump -t ${KVM} |grep ioport_writeb_thunk|cut -b-16` >> shellcode-config.h
echo $'#define IOPORT_READL_THUNK\t0x'`objdump -t ${KVM} |grep ioport_readl_thunk|cut -b-16` >> shellcode-config.h
echo $'#define QEMU_GET_RAM_PTR\t0x'`objdump -t ${KVM} |grep qemu_get_ram_ptr|cut -b-16` >> shellcode-config.h
echo "" >> $X
echo $'#define BDRV_RW_EM_CB\t0x'`objdump -t ${KVM} |grep bdrv_rw_em_cb|cut -b-16` >> shellcode-config.h
echo $'#define KVM_ARCH_DO_IOPERM\t0x'`objdump -t ${KVM} |grep kvm_arch_do_ioperm|cut -b-16` >> shellcode-config.h
echo "" >> $X
echo $'#define ADDR_RAMLIST_FIRST\t0x'`objdump -t ${KVM} |grep ' ram_list$'|cut -b-16`'+8' >> shellcode-config.h
echo "" >> $X
echo $'#define E820_TABLE\t0x'`objdump -t ${KVM} |grep e820_table|cut -b-16` >> shellcode-config.h
echo '#define SIZEOF_E820_TABLE        324'>>$X
echo $'#define HPET_CFG\t0x'`objdump -t ${KVM} |grep hpet_cfg|cut -b-16` >> shellcode-config.h
echo '#define SIZEOF_HPET_CFG          121'>>$X
echo "" >> $X
echo '#define PACKET_OFFSET   74' >>$X
echo "" >> $X
echo '#undef HAVE_TIMER_SCALE' >>$X
diff shellcode-config.old $X
