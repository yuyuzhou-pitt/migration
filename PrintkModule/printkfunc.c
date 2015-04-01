#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/init.h>         /* Needed for the macros */
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>

#define PRINTK                   0xffffffff8130acce

int pfunc(const char *fmt, ...);

void printstr(char *str){
    ((typeof(pfunc)*)PRINTK)(str);
}

static int __init hello_start(void)
{
    char str[20] = "abcddfunc";
    printstr(str);
    return 0;
}

static void __exit hello_end(void)
{
    printk(KERN_INFO "Goodbye Mr.\n");
}
module_init(hello_start);
module_exit(hello_end);
