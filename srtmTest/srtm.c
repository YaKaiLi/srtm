#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>

//cat /boot/System.map-`uname -r` | grep sys_close
//cat /proc/kallsyms | grep sys_call_table
//cat /proc/kallsyms | grep sys_open
// ffffffff81e001e0 R sys_call_table
// ffffffff81e01240 R ia32_sys_call_table

/*
./arch/x86/include/asm/uaccess.h:32:9: error: dereferencing pointer to incomplete type struct task_struct
  current->thread.addr_limit = fs;
报错修改：
/lib/modules/4.18.0-305.12.1.el8_4.x86_64/build/arch/x86/include/asm/uaccess.h文件中添加

#include <linux/sched.h>
*/

/*
问题思考：
1、kallsyms_lookup_name获取到的系统调用表位置不正确，但为什么能正确运行？
2、直接读取用户空间地址崩溃的根本原因是什么？
3、为什么写到同一地址的函数能够分别执行呢：335 336 地址都为0x00000000a2f75fc4
4、对指针的%d代表什么？
*/


#define SYS_CALL_TABLE  0xffffffff81e001e0
// unsigned long *real_sys_call_table ;
#define __NR_pull_images 335	/* 系统调用号335 */

// static int srtm_pull_image(char **uintptrConfigJSON, int *uintptrConfigJSONLen, int testInt2);
// static int srtm_run_container(void);

static int (*pull_images_saved)(void);	/*定义一个函数指针，用来保存一个系统调用*/


void disable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}

void enable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}

/* 添加自己的系统调用函数 */
unsigned long srtm_pull_image(int testInt1, int testInt2, int testInt3, int testInt4, int testInt5)
{
	int ret = 789;
	printk("srtm_pull_image syscall is successful!\n");
	printk("------------------------------------\n");

	int testInt = 0;
	int *lenConfigJSONPoint = &testInt;

	// int *lenConfigJSONPoint = kmalloc(sizeof(int), GFP_KERNEL);
    // if (NULL == lenConfigJSONPoint) {
	// 	printk("lenConfigJSONPoint kmalloc filed");
    //     return -ENOMEM;
    // }

	printk("lenConfigJSONPoint point addr: %p\n", &lenConfigJSONPoint);
	printk("lenConfigJSONPoint point: %p\n", lenConfigJSONPoint);
	printk("lenConfigJSONPoint *data: %d\n", *lenConfigJSONPoint);
	printk("testInt data: %d\n", testInt);
	printk("testInt1 data: %d\n", testInt1);
	printk("testInt2 data: %d\n", testInt2);
	printk("testInt3 data: %d\n", testInt3);
	printk("testInt4 data: %d\n", testInt4);
	printk("testInt5 data: %d\n", testInt5);
	return ret;
}

/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_addsyscall(void)
{
	printk("SRTM syscall is starting\n");

	// real_sys_call_table = (unsigned long *)SYS_CALL_TABLE;
	unsigned long *real_sys_call_table = (unsigned long *)SYS_CALL_TABLE;


   	printk("real_sys_call_table: 0x%p\n", real_sys_call_table);
   	// printk("__NR_pull_images sys_call_table: 0x%p\n", (void *)(real_sys_call_table[__NR_pull_images]));
	
	// pull_images_saved = (void *)(real_sys_call_table[__NR_pull_images]);	/* 保存原始系统调用 */

	// disable_wp();

	// real_sys_call_table[__NR_pull_images] = (unsigned long)&srtm_pull_image;	/* 更改原始的系统调用服务地址 */

    // enable_wp();
	return 0;
}

/*出口函数，卸载模块*/
static void __exit exit_addsyscall(void)
{
	// disable_wp();
    // real_sys_call_table[__NR_pull_images] = (unsigned long)pull_images_saved;	/* 恢复原有的中断向量表中的函数指针的值 */
    // enable_wp();
   	printk("SRTM syscall exit....\n");	
}

module_init(init_addsyscall);
module_exit(exit_addsyscall);
MODULE_LICENSE("GPL");