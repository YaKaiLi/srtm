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
	{ 0x868784cb, "__symbol_get" },
	{ 0x21e01071, "class_destroy" },
	{ 0x7b4244f7, "device_destroy" },
	{ 0x58d9cd11, "cdev_add" },
	{ 0x71a3afd4, "cdev_init" },
	{ 0xfae8f523, "device_create" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0xe42dbab4, "__class_create" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x2e2b40d2, "strncat" },
	{ 0xb0e602eb, "memmove" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0x85df9b6c, "strsep" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x9166fada, "strncpy" },
	{ 0x84651806, "crypto_shash_digest" },
	{ 0xe156f99a, "crypto_destroy_tfm" },
	{ 0x4b7f0aff, "crypto_alloc_shash" },
	{ 0x69acdf38, "memcpy" },
	{ 0xfb578fc5, "memset" },
	{ 0x754d539c, "strlen" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0x37a0cba, "kfree" },
	{ 0xa7eedcc4, "call_usermodehelper" },
	{ 0x61651be, "strcat" },
	{ 0xe914e41e, "strcpy" },
	{ 0xf86c8d03, "kmem_cache_alloc_trace" },
	{ 0x8200293d, "kmalloc_caches" },
	{ 0x2adb8261, "kernel_read" },
	{ 0x91715312, "sprintf" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0xa92e474e, "filp_close" },
	{ 0x2a35269e, "filp_open" },
	{ 0x9202ba1c, "current_task" },
	{ 0x6e9dd606, "__symbol_put" },
	{ 0x27e1a049, "printk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "575F13BCE30145A27D22BE6");
MODULE_INFO(rhelversion, "8.4");
