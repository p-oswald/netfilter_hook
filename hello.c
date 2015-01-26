//'Hello World' kernel module, logs call to init_module
// and cleanup_module to /var/log/messages

// In Ubuntu 8.04 we use make and appropriate Makefile to compile kernel module

#define __KERNEL__
#define __MODULE__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init config_init(void)
{
	printk(KERN_INFO "config_init executed successfully\n");
	return 0;
}

static void __exit config_exit(void)
{
	printk(KERN_INFO "config_exit executed succesfully\n");
	return;
}

module_init(config_init);
module_exit(config_exit);
