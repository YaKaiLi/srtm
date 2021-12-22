#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("liyakai <liyakai@iie.ac.cn>");
MODULE_DESCRIPTION("hello world");
MODULE_VERSION("0.1");

static int hello_export(void) {
    printk(KERN_INFO"hello_export from another module");
    return 0;
}

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello world!\n");
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_INFO "Goodbye world.\n");
}

EXPORT_SYMBOL(hello_export);
module_init(hello_init);
module_exit(hello_exit);