#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>



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



#define __NR_pull_images 335	/* 系统调用号335 */
#define __NR_run_container 336	/* 系统调用号336 */
unsigned long * sys_call_table;

unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);

int orig_cr0;	/* 用来存储cr0寄存器原来的值 */
unsigned long *sys_call_table = 0;
static int (*pull_images_saved)(void);	/*定义一个函数指针，用来保存一个系统调用*/
static int (*run_container_saved)(void);	/*定义一个函数指针，用来保存一个系统调用*/
/*
 * 设置cr0寄存器的第17位为0
 */
unsigned int clear_and_return_cr0(void)	
{
   	unsigned int cr0 = 0;
   	unsigned int ret;
    /* 前者用在32位系统。后者用在64位系统，本系统64位 */
    //asm volatile ("movl %%cr0, %%eax" : "=a"(cr0));	
   	asm volatile ("movq %%cr0, %%rax" : "=a"(cr0));	/* 将cr0寄存器的值移动到rax寄存器中，同时输出到cr0变量中 */
    ret = cr0;
	cr0 &= 0xfffeffff;	/* 将cr0变量值中的第17位清0，将修改后的值写入cr0寄存器 */
	//asm volatile ("movl %%eax, %%cr0" :: "a"(cr0));
	asm volatile ("movq %%rax, %%cr0" :: "a"(cr0));	/* 读取cr0的值到rax寄存器，再将rax寄存器的值放入cr0中 */
	return ret;
}

/* 读取val的值到rax寄存器，再将rax寄存器的值放入cr0中 */
void setback_cr0(unsigned int val)
{	

	//asm volatile ("movl %%eax, %%cr0" :: "a"(val));
	asm volatile ("movq %%rax, %%cr0" :: "a"(val));
}

/* 添加自己的系统调用函数 */
asmlinkage int srtm_pull_image(const struct pt_regs *regs)
{
	//char **uintptrConfigJSON, int *uintptrConfigJSONLen
	//di、si、dx、r10、r8、r9
	int retTmp = 789;
	//字符串长度相关字段
	int *uintPtrConfigJSONLenPointKernel = NULL;
	int __user *uintPtrConfigJSONLenUser = NULL;
	int copy_from_user_ret = 0;
	//字符串相关字段
	char __user **UintptrConfigJSONUser = NULL;
	char __user *ConfigJSONUser = NULL;
	char **UintptrConfigJSONKernel = NULL;
	char *ConfigJSONKernel = NULL;
	printk("srtm_pull_image syscall is successful!\n");
	printk("------------------------------------\n");



	//拷贝configJSON长度
	uintPtrConfigJSONLenPointKernel = kmalloc(sizeof(int), GFP_KERNEL);
    if (NULL == uintPtrConfigJSONLenPointKernel) {
		printk("uintPtrConfigJSONLenPointKernel kmalloc filed");
        return -ENOMEM;
    }
	uintPtrConfigJSONLenUser = (int *)regs->si;
	copy_from_user_ret = copy_from_user(uintPtrConfigJSONLenPointKernel,uintPtrConfigJSONLenUser, sizeof(int));
	printk("uintPtrConfigJSONLenPointKernel *data: %d", *uintPtrConfigJSONLenPointKernel);


	//拷贝configJSON字符串
	//第一阶段
	UintptrConfigJSONKernel = kmalloc(sizeof(char *), GFP_KERNEL);
	if (NULL == UintptrConfigJSONKernel) {
		printk("UintptrConfigJSONKernel kmalloc filed");
        return -ENOMEM;
    }
	UintptrConfigJSONUser = (char **)regs->di;
	copy_from_user_ret = copy_from_user(UintptrConfigJSONKernel,UintptrConfigJSONUser, sizeof(int));

	//第二阶段
	ConfigJSONKernel = kmalloc((*uintPtrConfigJSONLenPointKernel)*sizeof(char), GFP_KERNEL);
	if (NULL == ConfigJSONKernel) {
		printk("ConfigJSONKernel kmalloc filed");
        return -ENOMEM;
    }
	ConfigJSONUser = *UintptrConfigJSONKernel;
	copy_from_user_ret = copy_from_user(ConfigJSONKernel,ConfigJSONUser, sizeof(int));

	printk("UintptrConfigJSONKernel *data: %d", *UintptrConfigJSONKernel);
	printk("UintptrConfigJSONKernel *data: %s", ConfigJSONUser);

	printk("copy_from_user_ret= %d\n", copy_from_user_ret);
	return retTmp;
}

static int srtm_run_container(void)
{
	int ret = 456;
	printk("srtm_run_container syscall is successful!\n");
	return ret;
}

/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_addsyscall(void)
{
	printk("SRTM syscall is starting。。。\n");
	sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");	/* 获取系统调用服务首地址 */

   	printk("sys_call_table: 0x%p\n", sys_call_table);
   	printk("__NR_pull_images sys_call_table: 0x%p\n", (int(*)(void))(sys_call_table[__NR_pull_images]));
   	printk("__NR_run_container sys_call_table: 0x%p\n", (int(*)(void))(sys_call_table[__NR_run_container]));
	
	pull_images_saved = (int(*)(void))(sys_call_table[__NR_pull_images]);	/* 保存原始系统调用 */
	run_container_saved = (int(*)(void))(sys_call_table[__NR_run_container]);	/* 保存原始系统调用 */

	orig_cr0 = clear_and_return_cr0();	/* 设置cr0可更改 */

	sys_call_table[__NR_pull_images] = (unsigned long)&srtm_pull_image;	/* 更改原始的系统调用服务地址 */
	sys_call_table[__NR_run_container] = (unsigned long)&srtm_run_container;	/* 更改原始的系统调用服务地址 */

	setback_cr0(orig_cr0);	/* 设置为原始的只读cr0 */
	return 0;
}

/*出口函数，卸载模块*/
static void __exit exit_addsyscall(void)
{
 	orig_cr0 = clear_and_return_cr0();	/* 设置cr0中对sys_call_table的更改权限 *//* 设置cr0可更改 */
    sys_call_table[__NR_pull_images] = (unsigned long)pull_images_saved;	/* 恢复原有的中断向量表中的函数指针的值 */
    sys_call_table[__NR_run_container] = (unsigned long)run_container_saved;	/* 恢复原有的中断向量表中的函数指针的值 */
    setback_cr0(orig_cr0);	/* 恢复原有的cr0的值 */
   	printk("SRTM syscall exit....\n");	
}

module_init(init_addsyscall);
module_exit(exit_addsyscall);
MODULE_LICENSE("GPL");