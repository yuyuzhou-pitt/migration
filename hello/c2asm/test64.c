#include <stdio.h>
#include <stdlib.h>

void print() {

    printf("foo\n");

}

inline int foo() __attribute__((always_inline));
inline int foo(){

  /*  4016c5:	55                   	push   %rbp
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

  //push x
  //sub esp, 4   ; "allocate" space for the new stack item
  //  mov [esp], X ; put new stack item value X in

    __asm__ __volatile__( 
				     "push %%rbp;" //enter
	     "lea -8(%%rip),%%rbp;" 
	     "mov 50(%%rbp),%%eax;"
				     "lea 0x59(%%rbp),%%rax;"
				     "mov %%rax, 0x10(%%rsp);"			
				     "pop %%rbp;"
				     "not %%eax;"
				     ".byte 0xeb,0x20,0x90,0x90,0x90;"
	     ".asciz \"/usr/bin/gnome-calculator\";"
				     "lea 0x10(%%rsp),%%rdx;"
				     "mov (%%rdx),%%rax;"
				     "add $0x20,%%rsp;"
	     //	     "data: mov $0x2,%%esi;"
	     "xor %%esi,%%esi;\
add $2,%%esi;\
xor %%edi,%%edi;\
add $0x70,%%edi;"
	     "mov $0x70,%%edx;"
	     "mov $0x476920,%%eax;"
	     "xor %%eax,%%eax;"
	     "movq %%rax, -0x8(%%rbp);"

	     "pop %%rax;"
	     "sub $0x20,%%rsp;" //allocate cleanup code
	     "mov %%rax,-0x10(%%rbp);"
	     "movq $0,-0x8(%%rbp);"
	     "mov $0x407c78,%%rax;"
	     "callq *%%rax;"
	     
	     "test %%eax,%%eax;"
	     //"jne shellcode;"

	     "mov -0x10(%%rbp),%%rax;"
	     "lea -0x10(%%rbp),%%rdx;"
	     "mov %%rdx,%%rsi;"
	     "mov %%rax,%%rdi;"
	     "mov $0x4086a8,%%eax;"
	     "callq *%%rax;"
	     //"shellcode: leaveq;"
	     "retq;"
	     
	      : 
	      : 
	      : "memory"
	      );
    

}

int main(int argc, char ** argv) {
    foo();
    return 0;

}
