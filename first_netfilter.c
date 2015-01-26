//expansion of hello.c to include netfilter


#define __KERNEL__
#define __MODULE__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops nfho; //struct holding set of hook function options

//unction to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*))
{
	printk(KERN_INFO "packet dropped\n"); //log to /var/log/syslog
	return NF_DROP;		//drops the packets
}


//called when module loaded via 'insmod'

int init_module()
{
	nfho.hook = hook_func;  //funtion to call when conditions below are met
	nfho.hooknum = NF_IP_PRE_ROUTING;	//called right after packed recieved, first hook in Netfilter
	nfho.pf = PR_INET;	//IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;	//set to highest priorityover all other hook functions
	nf_register_hook(&nfho);	//regiter hook
	return 0;	//return 0 for no error
}

//called when module is unloaded using 'rmmod'

void cleanup_module()
{
	nf_unregister_hook(&nfho);	//cleanup - unregister hook
}


/*
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
*/

