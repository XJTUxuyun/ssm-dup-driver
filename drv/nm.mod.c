#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x3758301, "mutex_unlock" },
	{ 0xca975b7a, "nf_register_hook" },
	{ 0x8ce3169d, "netlink_kernel_create" },
	{ 0xde0bdcff, "memset" },
	{ 0x4bf79039, "__mutex_init" },
	{ 0xea147363, "printk" },
	{ 0xd4defbf4, "netlink_kernel_release" },
	{ 0xb4390f9a, "mcount" },
	{ 0xfee8a795, "mutex_lock" },
	{ 0x27418d14, "netlink_unicast" },
	{ 0xd3c80841, "skb_pull" },
	{ 0x1c740bd6, "init_net" },
	{ 0x25421969, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x7e5a6ea3, "nf_unregister_hook" },
	{ 0x236c8c64, "memcpy" },
	{ 0x207b7e2c, "skb_put" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "A516277D55D4CE600E5AC86");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 2,
};
