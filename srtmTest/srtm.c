#include <linux/init.h>
 #include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/unistd.h>
 #include <asm/uaccess.h>
 #include <linux/uaccess.h>
 #include <linux/sched.h>
 
 //去系统调用表中查找一个空闲的系统调用号
 //使用已经存在的调用号也ok
 #define my_syscall_num 335
 //如下的这个就是上一步获得的值
 #define sys_call_table_adress 0xffffffffa06001e0
 
 unsigned int clear_and_return_cr0(void);//清除写保护位并返回
 void setback_cr0(unsigned int val);//恢复写保护位
 static asmlinkage long sys_mycall(const struct pt_regs *regs);//自定义的系统调用函数
 
 int orig_cr0;
 unsigned long *sys_call_table = 0;
 static int (*anything_saved)(void);//函数指针
 
 unsigned int clear_and_return_cr0(void)
 {
    
     unsigned int cr0 = 0;
     unsigned int ret;
     asm("movq %%cr0, %%rax":"=a"(cr0));
     ret = cr0;
     cr0 &= 0xfffffffffffeffff;
     asm("movq %%rax, %%cr0"::"a"(cr0));
     return ret;
 }
 
 void setback_cr0(unsigned int val) //读取val的值到eax寄存器，再将eax寄存器的值放入cr0中
 {
    
     asm volatile("movq %%rax, %%cr0"::"a"(val));
 }
 
 static int __init init_addsyscall(void)
 {
    
     printk("hello, kernel\n");
 
     sys_call_table = (unsigned long *)sys_call_table_adress;//获取系统调用服务首地址
     anything_saved = (int(*)(void))(sys_call_table[my_syscall_num]);//保存原始系统调用的地址
  
     orig_cr0 = clear_and_return_cr0();//设置cr0可更改
     sys_call_table[my_syscall_num] = (unsigned long)&sys_mycall;//更改原始的系统调用服务地址  
     setback_cr0(orig_cr0);//设置为原始的只读cr0
 
     return 0;
 }
 
 static asmlinkage long sys_mycall(const struct pt_regs *regs)
 {
	 printk("the int2: %ld",regs->di);
	 printk("the int3: %ld",regs->si);
	 printk("the int4: %ld",regs->dx);
	 printk("the int5: %ld",regs->r10);
	 printk("the int6: %p",regs->r8);

     int testInt10 = 0;
	 int *int10PointKernel = &testInt10;
	 printk("the int10: %d",*int10PointKernel);
     int __user *user_int10Point = (int *)regs->r8;
	 int ret = raw_copy_from_user(int10PointKernel, user_int10Point, sizeof(int));
     printk("copy ret:%d\n",ret);
	 printk("the int10: %d",*int10PointKernel);
     
     printk("This is my system call!\n");
     return 1;
 }
 
 static void __exit exit_addsyscall(void)
 {
    
     //设置cr0中对sys_call_table的更改权限。
     orig_cr0 = clear_and_return_cr0();//设置cr0可更改
 
     //恢复原有的中断向量表中的函数指针的值。
     sys_call_table[my_syscall_num] = (unsigned long)anything_saved;
  
     //恢复原有的cr0的值
     setback_cr0(orig_cr0);
 
     printk("call exit \n");
 }
 
 module_init(init_addsyscall);
 module_exit(exit_addsyscall);
 MODULE_LICENSE("GPL");