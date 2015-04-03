#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/init.h>         /* Needed for the macros */
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>

/* function address defined in System.map */
#define PRINTK                   0xffffffff8130acce

int pfunc(const char *fmt, ...);

void printstr(char *str){
    ((typeof(pfunc)*)PRINTK)(str);
}

static int __init hello_start(void)
{
    /* .text: use arrary to store the string */
    char str1[20] = "I'm in .text";
    printstr(str1);

    /* .rodata: format strings in printf statements */
    printstr("Hello printk!\n");
    printstr("I'm in .rodata.\n");
    printstr("I'm still in .rodata.\n");

    return 0;
}

static void __exit hello_end(void)
{
    char str2[20] = "Goodby Mr.\n";
    printstr(str2);
}
module_init(hello_start);
module_exit(hello_end);
