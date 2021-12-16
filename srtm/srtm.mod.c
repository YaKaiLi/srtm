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
	{ 0xe007de41, "kallsyms_lookup_name" },
	{ 0x85df9b6c, "strsep" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x5a921311, "strncmp" },
	{ 0xb0e602eb, "memmove" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0xa7eedcc4, "call_usermodehelper" },
	{ 0x61651be, "strcat" },
	{ 0xfb578fc5, "memset" },
	{ 0x2adb8261, "kernel_read" },
	{ 0x91715312, "sprintf" },
	{ 0xa92e474e, "filp_close" },
	{ 0x2a35269e, "filp_open" },
	{ 0x4b7f0aff, "crypto_alloc_shash" },
	{ 0x754d539c, "strlen" },
	{ 0x37a0cba, "kfree" },
	{ 0x84651806, "crypto_shash_digest" },
	{ 0x27e1a049, "printk" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0xe156f99a, "crypto_destroy_tfm" },
	{ 0x97651e6c, "vmemmap_base" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x9202ba1c, "current_task" },
	{ 0xad27f361, "__warn_printk" },
	{ 0x4c9d28b0, "phys_base" },
	{ 0x7cd8d75e, "page_offset_base" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "71DBBA3065A16017C033384");
MODULE_INFO(rhelversion, "8.4");
