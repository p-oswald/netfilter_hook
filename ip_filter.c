/*IP_filter to drop ip_packets by source ip*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>



static struct nf_hook_ops nfho; //struct holding set of hook function options
struct sk_buff *sock_buff;
struct udphdr *udp_header;
struct iphdr *ip_header;



//function to be called by hook
unsigned int my_nf_hookfn( const struct nf_hook_ops *ops,
						/*unsigned int hooknum, */
						struct sk_buff *skb, 
						const struct net_device *in, 
						const struct net_device *out, 
						int (*okfn)(struct sk_buff *))
{
	sock_buff = skb;
	
	ip_header = (struct iphdr *)skb_network_header(sock_buff); //access to ip header through accessor
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	/*unsigned int dest_ip = (unsigned int)ip_header->daddr;*/

	if (!sock_buff) 
	{
		return NF_ACCEPT;
	}

	if (ip_header->saddr==src_ip)
	{
		printk(KERN_INFO "got ip packet \n"); 	//log that a udp packet was captured to /var/log/syslog
		return NF_DROP;
	}

	return NF_ACCEPT;

}


//called when module loaded via 'insmod'

int __init reg_my_hook(void)
{
	nfho.hook = my_nf_hookfn;  //funtion to call when conditions below are met
	nfho.hooknum = NF_INET_PRE_ROUTING;	//called right after packed recieved, first hook in Netfilter
	nfho.pf = PF_INET;	//IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;	//set to highest priorityover all other hook functions
	nf_register_hook(&nfho);	//regiter hook
	return 0;	//return 0 for no error
}

//called when module is unloaded using 'rmmod'

void __exit exi_my_hook(void)
{
	nf_unregister_hook(&nfho);	//cleanup - unregister hook
}

module_init(reg_my_hook);
module_exit(exi_my_hook);
