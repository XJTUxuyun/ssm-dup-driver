#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/atomic.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/mutex.h>

#define NIPQUAD(addr)	\
	((unsigned char *)&addr)[0], 	((unsigned char *)&addr)[1], 	((unsigned char *)&addr)[2], 	((unsigned char *)&addr)[3]

#define NF_IP_PRE_ROUTING 0
#define NF_IP_LOCAL_IN 1
#define NF_IP_FORWARD 2
#define NF_IP_LOCAL_OUT 3
#define NF_IP_POST_ROUTING 4
#define NF_IP_NUMHOOKS 5


#define NETLINK_TEST 25  // protocal

#define MAX_MSG_LEN 1024  

#define UNUSED (254 + 255*256 + 255*256*256 + 255*256*256*256)

#define ASSERT(expr) \ 
	if(unlikely(!(expr))){ \
		printk("Assertion failed! %s, %s, %s, line=%d\n", \
		#expr, __FILE__, __func__, __LINE__); \
	}

enum{
	NLMSG_TYPE_NONE=0,
	NLMSG_TYPE_SETPID,
	NLMSG_TYPE_KERNEL,
	NLMSG_TYPE_APP,
};

struct nlmsg{
	int type;
	int len;
	char msg[MAX_MSG_LEN];
};

struct network_manager_s{
	struct mutex mutex;
	char total;
	unsigned int ip_list[8];
	struct sock *g_nl_sk;	
} inner_nms;  // global variant.


/*************************************function declare******************************************/

static int network_manager_init(struct network_manager_s *nms);
static int network_manager_destory(struct network_manager_s *nms);
static int network_manager_ip_add(struct network_manager_s *nms, unsigned int ip);
static int network_manager_ip_rm(struct network_manager_s *nms, unsigned int ip);
static int network_manager_ip_reset(struct network_manager_s *nms);
static int network_manager_cmd_parse(char *msg, int pid);
static void network_manager_print(struct network_manager_s *nms);
static int string_len(char *s);
static int string_cpy(char *s, char *d);
static int nl_sendmsg(struct sock *sk, struct nlmsg *pmsg, int pid);
static void nl_recvmsg(struct sk_buff *skb);

/*************************************function implement******************************************/

static void network_manager_print(struct network_manager_s *nms){
	printk(KERN_INFO"************************inner of nms begin************************");
	int i=0;
	for(i=0; i<8; i++){
		printk(KERN_INFO"\t\t\t index: %d-> %u.%u.%u.%u\n", i, NIPQUAD(nms->ip_list[i]));
	}
	printk(KERN_INFO"************************inner of nms end************************");
}

static int string_len(char *s){
	int slen = 0;
	for(; *s; s++){
		slen++;
	}
	return slen;
}

static int string_cpy(char *s, char *d){
	int slen = 0;
	for(; *s; s++){
		*d = *s;
		d ++;
		slen ++;
		if(slen > 1023){
			break;
		}
	}
	return slen;
}

static int network_manager_init(struct network_manager_s *nms){
	char i = 0;
	mutex_init(&nms->mutex);
	nms->total = 0;
	for(i=0; i<8; i++){
		nms->ip_list[i] = UNUSED;  // represent unused.
	}
	/*  
     * struct sock *netlink_kernel_create(struct net *net, int unit, unsigned int groups, 
     *                                    void (*input)(struct sk_buff *skb), 
     *                                    struct mutex *cb_mutex, struct module *module) 
     */  
	nms->g_nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, 0, nl_recvmsg,  NULL, THIS_MODULE);
	if (!nms->g_nl_sk){
		printk(KERN_INFO"\tnetlink_kernel_create error.\n");
		return -1;
	}else{
		printk(KERN_INFO"\tnetlink_kernel_create success.\n");
	}
	return 0;
}

static int network_manager_destory(struct network_manager_s *nms){
	
	if (nms->g_nl_sk){
		printk(KERN_INFO"\tnetlink_kernel_release.\n");
		netlink_kernel_release(nms->g_nl_sk);	
	}
	return 0;
}

static int network_manager_ip_add(struct network_manager_s *nms, unsigned int ip){
	char i=0;
	mutex_lock(&nms->mutex);
	if (8 <= nms->total){
		goto full;
	}
	for(i=0; i<nms->total; i++){
		if(ip == nms->ip_list[i]){
			goto exist;
		}
	}
	nms->ip_list[nms->total] = ip;
	nms->total ++;
	printk(KERN_INFO"\t\tadd ip: %u.%u.%u.%u success.\n", NIPQUAD(ip));
	mutex_unlock(&nms->mutex);
	return 0;
full:
	printk(KERN_INFO"\t\tadd ip: %u.%u.%u.%u failed due to inner_nms is full.\n", NIPQUAD(ip));
	mutex_unlock(&nms->mutex);
	return -1;
exist:
	printk(KERN_INFO"\t\tadd ip: %u.%u.%u.%u is already in inner_nms.\n", NIPQUAD(ip));
	mutex_unlock(&nms->mutex);
	return -2;
}

static int network_manager_ip_rm(struct network_manager_s *nms, unsigned int ip){
	mutex_lock(&nms->mutex);
	char cur = 10;
	char i = 0;
	for(i=0; i<nms->total; i++){
		printk(KERN_INFO"\t\t\t ip_list-> %u  ip-> %u\n", nms->ip_list[i], ip);
		if(ip == nms->ip_list[i]){
			cur = i;
			break;	
		}
	}
	if(10 == cur){
		goto inexist;
	}
	
	nms->ip_list[cur] = nms->ip_list[nms->total -1];
	nms->ip_list[nms->total -1] = UNUSED;  // make slot unused.
	nms->total --;
	printk(KERN_INFO"\t\tremove ip: %u.%u.%u.%u success.\n", NIPQUAD(ip));
	mutex_unlock(&nms->mutex);
	return 0;
inexist:
	printk(KERN_INFO"\t\tremove ip: %u.%u.%u.%u not in inner_nms.\n", NIPQUAD(ip));
	mutex_unlock(&nms->mutex);
	return -1;
}

static int network_manager_ip_reset(struct network_manager_s *nms){
	mutex_lock(&nms->mutex);
	char i = 0;
	for(i=0; i<8; i++){
		nms->ip_list[i] = UNUSED;
	}
	nms->total = 0;
	mutex_unlock(&nms->mutex);
	printk(KERN_INFO"\t\treset inner_nms success.\n");
	return 0;
}

static int network_manager_cmd_parse(char *msg, int pid){
	int r = -1;
	int slen = 0;
	char c[1024] = {0};
	struct nlmsg msg_tmp;
	msg_tmp.type = NLMSG_TYPE_KERNEL;
	if((msg[0] == 'a') && (msg[1] == ':')){
		printk(KERN_INFO"\tcommand add.\n");
		unsigned int ip = *(unsigned int *)(msg + 2);
		r = network_manager_ip_add(&inner_nms, ip);
		if (r == 0){
			slen = string_cpy("add ip success", c);
		}else if(r == -1){
			slen = string_cpy("nms is full", c);
		}else if(r == -2){
			slen = string_cpy("ip already exist",c);
		}	
	}else if((msg[0] == 'd') && (msg[1] == ':')){
		printk(KERN_INFO"\tcommand rm.\n");
		unsigned int ip = *(unsigned int *)(msg + 2);
		r = network_manager_ip_rm(&inner_nms, ip);
		if(r == 0){
			slen = string_cpy("del ip success", c);
		}else if(r == -1){
			slen = string_cpy("ip inexist", c);
		}
	}else if((msg[0] == 'r') && (msg[1] == ':' )){
		printk(KERN_INFO"\tcommand reset.\n");
		r = network_manager_ip_reset(&inner_nms);
		slen = string_cpy("reset nms", c);
	}else if((msg[0] == 'q')){
		printk(KERN_INFO"\tcommand query.\n");
	}else{
		printk(KERN_INFO"\tcommand unknow.\n");
		slen = string_cpy("command unknow", c);
	}
	msg_tmp.len = slen + offsetof(struct nlmsg, msg) + 1;
	memcpy(msg_tmp.msg, c, msg_tmp.len);
	nl_sendmsg(inner_nms.g_nl_sk, &msg_tmp, pid);
	network_manager_print(&inner_nms);
	return 0;
}

/*
int nl_sendskb(struct sock *sk, struct sk_buff *skb){
	struct iphdr *iph = NULL;
	struct nlmsghdr *nlh = NULL;
	struct sk_buff *nl_skb = NULL;
	
	int skb_len = 0;
	ASSERT(skb != NULL);
	ASSERT(sk != NULL);
	if( 0 > g_nlpid){
		return 0;
	}

	iph = ip_hdr(skb);
	skb_len = iph->tot_len;
	nl_skb = alloc_skb(NLMSG_SPACE(skb_len), GFP_ATOMIC);
	if (!nl_skb){
		printk(KERN_INFO"nl_skb == NULL, failed.\n");
		return -1;
	}	
	
	nlh = nlmsg_put(nl_skb, 0, 0, 0, NLMSG_SPACE(skb_len) - sizeof(struct nlmsghdr), 0);
	NETLINK_CB(nl_skb).pid = 0;
	memcpy(NLMSG_DATA(nlh), (char *)iph, htons(iph->tot_len));
	return netlink_unicast(sk, nl_skb, g_nlpid, MSG_DONTWAIT);
}*/

int nl_sendmsg(struct sock *sk, struct nlmsg *pmsg, int pid){
	struct nlmsghdr *nlh = NULL;
	struct sk_buff *nl_skb = NULL;
	int msglen = pmsg->len;
	ASSERT(pmsg != NULL);
	ASSERT(sk != NULL);
	if (0 > pid){
		return 0;
	}

	nl_skb =  alloc_skb(NLMSG_SPACE(msglen), GFP_ATOMIC);
	if (!nl_skb){
		printk(KERN_INFO"nl_skb == NULL, msglen = %d, failed.\n", msglen);
		return -1;
	}

	nlh = nlmsg_put(nl_skb, 0, 0, 0, NLMSG_SPACE(msglen) - NLMSG_HDRLEN, 0);
	NETLINK_CB(nl_skb).pid = 0;
	memcpy(NLMSG_DATA(nlh), pmsg, msglen);
	
	return netlink_unicast(sk, nl_skb, pid, MSG_DONTWAIT);
}

static void nl_recvmsg(struct sk_buff *skb){
	struct nlmsg *pmsg = NULL;
	struct nlmsghdr *nlh = NULL;
	uint32_t rlen = 0;
	while(skb->len > NLMSG_SPACE(0)){
		nlh = nlmsg_hdr(skb);
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len){
			return;
		}

		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len){
			rlen = skb->len;
		}

		pmsg = (struct nlmsg *)NLMSG_DATA(nlh);
		
		switch(pmsg->type){
			case NLMSG_TYPE_SETPID:
				printk(KERN_INFO"pid: %d\t msg: %s\n", nlh->nlmsg_pid, pmsg->msg);
				network_manager_cmd_parse(pmsg->msg, nlh->nlmsg_pid);
				char *pmsg = "fuck u";
				struct nlmsg msg;
				msg.type = NLMSG_TYPE_KERNEL;
				msg.len = strlen(pmsg) + offsetof(struct nlmsg, msg) + 1;
				memcpy(msg.msg, pmsg, msg.len);
				//nl_sendmsg(inner_nms.g_nl_sk, &msg, g_nlpid);
				break;
			case NLMSG_TYPE_KERNEL:
				break;
			case NLMSG_TYPE_APP:
				break;
		}

		skb_pull(skb, rlen);
	}
}

static atomic_t pktcnt = {
	.counter = 0,
};

static unsigned int myhook_func(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	char i = 0;
	const struct iphdr *iph = ip_hdr(skb);
	/*if (((unsigned char *)&iph->saddr)[0] == 27){
		printk(KERN_INFO"reject addr: %u %u %u %u", NIPQUAD(iph->saddr));
		return NF_DROP;
	}*/
	for (i=0; i< inner_nms.total; i++){
		if(iph->saddr == inner_nms.ip_list[i]){
			printk(KERN_INFO"reject addr: %u %u %u %u", NIPQUAD(iph->saddr));
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops nfho1 = {
	.hook = myhook_func,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_IP_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
};

static int __init myhook_init(void){
	printk(KERN_INFO"install network manager kernel module.\n");
	network_manager_init(&inner_nms);
	return nf_register_hook(&nfho1);
}

static void __exit myhook_fini(void){
	printk(KERN_INFO"uninstall network manager kernel module.\n");
	network_manager_destory(&inner_nms);
	nf_unregister_hook(&nfho1);
}

module_init(myhook_init);
module_exit(myhook_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("xuyun");
MODULE_DESCRIPTION("network manager.");
