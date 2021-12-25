#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xf8cdd757, "module_layout" },
	{ 0x361c68dd, "cdev_del" },
	{ 0x21e01071, "class_destroy" },
	{ 0x7b4244f7, "device_destroy" },
	{ 0x58d9cd11, "cdev_add" },
	{ 0x71a3afd4, "cdev_init" },
	{ 0xfae8f523, "device_create" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0xe42dbab4, "__class_create" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x37a0cba, "kfree" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xf86c8d03, "kmem_cache_alloc_trace" },
	{ 0x8200293d, "kmalloc_caches" },
	{ 0x27e1a049, "printk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "97E72E73215CD7F32C4E04C");
MODULE_INFO(rhelversion, "8.4");
