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
	{ 0x8200293d, "kmalloc_caches" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0x4b7f0aff, "crypto_alloc_shash" },
	{ 0x754d539c, "strlen" },
	{ 0xa92e474e, "filp_close" },
	{ 0x85df9b6c, "strsep" },
	{ 0x91715312, "sprintf" },
	{ 0x2adb8261, "kernel_read" },
	{ 0xfb578fc5, "memset" },
	{ 0x9202ba1c, "current_task" },
	{ 0x27e1a049, "printk" },
	{ 0x84651806, "crypto_shash_digest" },
	{ 0x5a921311, "strncmp" },
	{ 0xa7eedcc4, "call_usermodehelper" },
	{ 0x61651be, "strcat" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0xe156f99a, "crypto_destroy_tfm" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xf86c8d03, "kmem_cache_alloc_trace" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0xb0e602eb, "memmove" },
	{ 0xe914e41e, "strcpy" },
	{ 0x2a35269e, "filp_open" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "EDE45F1B17683F456EFA142");
MODULE_INFO(rhelversion, "8.4");
