/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     ker.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-14 17:43
***************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h> 
#include <linux/ip.h>
#include <linux/phy.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <net/netfilter/nf_nat_core.h>

#include "ker.h"
#include "../user/pub.h"

#define PORTAL_PORT   8012
#define NETLINK_PENGWIFI 26
//#define NETLINK_TEST NETLINK_GENERIC
#define MAX_MSGSIZE 1024
int stringlength(char *s);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,66)
void sendnlmsg(void * message, int len);
#endif
static int pid; // user process pid
static struct sock *nl_sk = NULL;
#ifdef KER_TEST
int g_ap_flag = 1;
#else
int g_ap_flag = 0;
#endif

#ifdef MODEL_DMGROUTER
int g_bridge_mode = 0;
#else
int g_bridge_mode = 1;
#endif
rwlock_t g_table_lock;
struct hlist_head sta_table[STA_HASH_SIZE];
struct timer_list sta_timer;

extern struct wlan_arg wlans[];

unsigned char _tmp_mac[ETH_ALEN] = {1,1,1,1,1,1};
#define ANCHOR_MAC    _tmp_mac

unsigned int _tmp_ip = 1;
#define ANCHOR_IP     _tmp_ip

static inline int have_important_pkt(struct iphdr *iph)
{
	struct udphdr *udph;

	if(iph && iph->protocol == IPPROTO_UDP) {
		udph = (struct udphdr *)((char*)iph + iph->ihl*4);
		if(udph && (udph->dest == htons(67) || udph->dest == htons(53))) {
			return 1;
		}
	}
	
	return 0;
}

struct msg_to_ker* build_sta_msg(unsigned char *mac, u32 ipaddr, char *ifname, int action)
{
	struct msg_to_ker *m;
	struct sta_ctl sc;
	
	int len = sizeof(struct msg_to_ker) + sizeof(struct sta_ctl);
	m = (struct msg_to_ker *)kmalloc(len, GFP_ATOMIC);
	if(m) {
		memset(m, 0, len);
		if(mac){
			memcpy(sc.mac, mac, ETH_ALEN);
		}
		sc.ipaddr = ipaddr;
		sc.action = action;
		if(ifname){
			memcpy(sc.ifname, ifname, IFNAMSIZ);
		}
		m->type = M2K_STACTL;
		m->len = sizeof(struct sta_ctl);
		memcpy(m->value, &sc, m->len);
	}

	return m;
}

static void free_sta_msg(struct msg_to_ker *m)
{
	if(m)kfree(m);
	return;
}

int add_bw_anchor(void)
{
	struct u_sta_blk_wht sta_bw;
	struct u_dn_blk_wht dn_bw;

	/*add anchor node*/
	memset(&sta_bw, 0, sizeof(struct u_sta_blk_wht));
	memset(&dn_bw, 0, sizeof(struct u_dn_blk_wht));

	memcpy(sta_bw.mac, ANCHOR_MAC, ETH_ALEN);
	sta_bw.map[0][0]=1;

	dn_bw.ipaddr = ANCHOR_IP;
	dn_bw.map[0][0]=1;
	snprintf(dn_bw.domain, sizeof(dn_bw.domain), "%s", "http://www.xxx.com");

	do_add_sta_blk_wht(&sta_bw);
	do_add_dn_blk_wht(&dn_bw);

	return 0;
}

static void timer_handler(unsigned long arg)
{
	unsigned long now, next;
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_info *node;
	struct msg_to_ker *m;
	int i = 0;

	write_lock(&g_table_lock);
	for(i = 0; i < STA_HASH_SIZE; i++){
		head = &sta_table[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			if(!memcmp(ANCHOR_MAC, node->mac, ETH_ALEN)){
				continue;
			}
			
			if((1 != node->will_timeout) && time_after(jiffies, node->pre_timeout)){
				node->will_timeout = 1;
			}else if((STATE_STALE != node->state) && time_after(jiffies, node->timeout)){
				printk("Timer: delete %02x:%02x:%02x:%02x:%02x:%02x\n",
				node->mac[0], node->mac[1], node->mac[2],node->mac[3], node->mac[4], node->mac[5]);
				node->state = STATE_STALE;
				m = build_sta_msg(node->mac, node->ipaddr, node->ifname, STA_TIMEOUT);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,66)
				sendnlmsg(m, sizeof(struct msg_to_ker)+sizeof(struct sta_ctl));
#endif
				free_sta_msg(m);
			}else if(time_after(jiffies, node->max_time) && (STATE_AUTHED == node->state)){
				printk("Timer: runout %02x:%02x:%02x:%02x:%02x:%02x, %lu, %lu\n",
				node->mac[0], node->mac[1], node->mac[2],node->mac[3], node->mac[4], node->mac[5], jiffies, node->max_time);
				node->state = STATE_UNAUTH;
				m = build_sta_msg(node->mac, node->ipaddr, node->ifname, STA_TIME_RUNOUT);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,66)
				sendnlmsg(m, sizeof(struct msg_to_ker)+sizeof(struct sta_ctl));
#endif
			}else if((STATE_STALE == node->state) && (time_after(jiffies, node->timeout + 86400))){
				hlist_del_init_rcu(&node->hlist);
			}
		}
	}
	write_unlock(&g_table_lock);

	now = jiffies;
	next = jiffies + 5 * HZ;
	mod_timer(&sta_timer, next);

	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,66)
void sendnlmsg(void *message, int data_len)
{
    struct sk_buff *skb_1;
    struct nlmsghdr *nlh;
	int err;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    //int slen = 0;
    if(!message || !nl_sk)
    {
        return ;
    }
    
    skb_1 = alloc_skb(len,GFP_KERNEL);
    if(!skb_1)
    {
        printk(KERN_ERR "my_net_link:alloc_skb_1 error\n");
    }
    
    //slen = stringlength(message);
    nlh = nlmsg_put(skb_1,0,0,0,MAX_MSGSIZE,0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
    NETLINK_CB(skb_1).portid = 0;
#else
    NETLINK_CB(skb_1).pid = 0;
#endif
    NETLINK_CB(skb_1).dst_group = 0;

    //message[slen]= '\0';
    memcpy(NLMSG_DATA(nlh),message,data_len);
	printk("%s:%d,type=%d\n",__FUNCTION__,__LINE__,((struct msg_to_ker *)message)->type);
    //printk("my_net_link:send message '%s'.\n",(char *)NLMSG_DATA(nlh));

    err = netlink_unicast(nl_sk,skb_1,pid,MSG_DONTWAIT);
	printk("%s:%d, err=%d\n", __FUNCTION__,__LINE__,err);
	//kfree_skb(skb_1);
}
#endif

int stringlength(char *s)
{
    int slen = 0;

    for(; *s; s++){
        slen++;
    }

    return slen;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,66)
void nl_data_ready(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct completion cmpl;
    skb = skb_get (__skb);
	struct msg_to_ker *m;
    
    if(skb->len >= NLMSG_SPACE(0))
    {
        nlh = nlmsg_hdr(skb);

		if(!nlh){
			return;
		}

        m = (struct msg_to_ker *)NLMSG_DATA(nlh);
        printk("[KERNEL] Message received:%d\n",m->type) ;
        pid = nlh->nlmsg_pid;
		if(M2K_APONLINE == m->type){
			int *flag;
		
			flag = (int *)(m->value);

			printk("kernel rcv online: %d\n", *flag);	

			if(0 == *flag){
        		g_ap_flag = 0;
				del_all_sta();
			}else{
				g_ap_flag = 1;
			}
		}else if(M2K_STACTL == m->type){
			struct sta_ctl *sc;

			sc = (struct sta_ctl *)(m->value);printk("ker: action=%d, %x\n", sc->action,sc->mac[5]);
			if(STA_ALLOW == sc->action){
				set_sta_state(sc->mac, STATE_AUTHED);
			}else if((STA_DENY == sc->action) || (STA_KICKOFF == sc->action)){
				set_sta_state(sc->mac, STATE_UNAUTH);
			}
		}else if(M2K_STA_BLKWHT_SET == m->type){
			struct u_sta_blk_wht *s;
			
			s = (struct u_sta_blk_wht *)(m->value);
			do_add_sta_blk_wht(s);
		}else if(M2K_STA_BLKWHT_CLEAR == m->type){
			clear_sta_blk_wht();	
		}else if(M2K_DN_BLKWHT_SET == m->type){
			struct u_dn_blk_wht *s;
			
			s = (struct u_dn_blk_wht *)(m->value);
			do_add_dn_blk_wht(s);
		}else if(M2K_DN_BLKWHT_CLEAR == m->type){
			clear_dn_blk_wht();	
		}else if(M2K_PORTAL_CONFIG == m->type){
			struct wlan_arg w[MAX_WLAN_COUNT];
			int i = 0;
			
			memcpy(w, m->value, sizeof(w));
			for(i = 0; i < MAX_WLAN_COUNT; i++){
				memcpy(wlans[i].portal_url, w[i].portal_url, sizeof(wlans[i].portal_url));
				memcpy(wlans[i].portal_ipaddr, w[i].portal_ipaddr, sizeof(wlans[i].portal_ipaddr));
				wlans[i].no_portal = w[i].no_portal;
				wlans[i].max_time = w[i].max_time;
				wlans[i].idle_timeout = w[i].idle_timeout;
			}
		}else{
			printk("kernel rcv other\n");	
		}
        kfree_skb(skb);
    }
}
#endif

static __be32 get_lan_ipaddr(void)
{
	__be32 addr;
	struct net_device *dev;
	struct in_device *ip;
	struct in_ifaddr *in;
	
	if((dev = dev_get_by_name(&init_net, LAN_IFNAME)) == NULL){
		printk("get lan addr error.\n");
		return 0;
	}
	
	ip = dev->ip_ptr;
	if ((ip == NULL) || ((in = ip->ifa_list) == NULL)) {
		printk(KERN_WARNING "Device not assigned an IP address!\n");
	}

	addr = in->ifa_address;
	dev_put(dev);

	return addr;	
}

int is_daddr_local(__be32 daddr)
{
	int ret = 0;//0-false, 1-true
		
	struct net_device *dev;
	struct in_device *ip;
	struct in_ifaddr *in;

	if((dev = dev_get_by_name(&init_net, LAN_IFNAME)) == NULL){
		printk("get dev br0 error.\n");
		return 0;
	}
	
	ip = dev->ip_ptr;
	in = ip->ifa_list;
	while(in != NULL){
		if(daddr == in->ifa_address){
			ret = 1;
			break;
		}
		in = in->ifa_next;
	}	
	dev_put(dev);
	
	return ret;
}

static int dm_nat_http_packet(unsigned int hooknum, struct sk_buff * skb, unsigned char *mac)
{
	struct iphdr *iph;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;
	struct in_addr s4;
	struct tcphdr *tcph;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36) || LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
	struct nf_nat_range range;
	memset(&range, 0, sizeof(struct nf_nat_range));
#else
	struct nf_nat_ipv4_range range;
	memset(&range, 0, sizeof(struct nf_nat_ipv4_range));
#endif

	iph = ip_hdr(skb);//if(iph && iph->protocol != IPPROTO_ICMP)printk(KERN_ALERT"%d, proto=%d\n", __LINE__, iph?iph->protocol:-1);
	if(iph && iph->protocol == IPPROTO_TCP) {//printk(KERN_ALERT"%d\n", __LINE__);

		tcph = (struct tcphdr *)((char*)iph + iph->ihl*4);
		if(tcph && tcph->dest == htons(80)) {//printk("8080808080 %d\n", __LINE__);

#if 0
			in4_pton("192.168.10.1", strlen("192.168.10.1"), 
				(unsigned char *)&s4.s_addr, '\0', NULL);
#endif			
			s4.s_addr = get_lan_ipaddr();
			if(!s4.s_addr || (iph->daddr == s4.s_addr))return NF_ACCEPT;

			/* For DST manip, map port here to where it's expected. */
//#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
			range.flags = (IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED);
#else
			range.flags = (NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
			range.min_addr.ip = range.max_addr.ip = s4.s_addr;
			range.min_proto.tcp.port = range.max_proto.tcp.port = htons(PORTAL_PORT);	
#else
			range.min_ip = range.max_ip = s4.s_addr;
			range.min.tcp.port = range.max.tcp.port = htons(PORTAL_PORT);
#endif
			ct = nf_ct_get(skb, &ctinfo);//printk("%d\n", __LINE__);
			NF_CT_ASSERT(ct != NULL &&
				(ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED));//printk("%d\n", __LINE__);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
			//if(ct && !nf_nat_initialized(ct, IP_NAT_MANIP_DST)){printk("%d\n", __LINE__);
			if(ct){//printk("%d: nat \n", __LINE__);
				clear_bit(IPS_DST_NAT_DONE_BIT, &ct->status);//printk("%d\n", __LINE__);
				nf_nat_setup_info(ct, &range, IP_NAT_MANIP_DST);//printk("%d\n", __LINE__);
				//nf_nat_packet(ct, ctinfo, hooknum, skb);
#else
			if(ct && !nf_nat_initialized(ct, NF_NAT_MANIP_DST)){
				nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#endif
			}
			set_sta_state(mac, STATE_IN_PORTAL);
		}
	}

	return 0;
}

int check_sta_table(struct sk_buff * skb)
{

	return 0;
}

unsigned int dmsniff(
	unsigned int hooknum,
	struct sk_buff * skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn) (struct sk_buff *))
{
	struct ethhdr *eh = NULL;
	struct iphdr *iph;
	//__be32 sip,dip;
	const unsigned char *smac = NULL;
	char buf[32] = {0};
	char tmp_str[256] = {0};
	int result = 0;
	int cret = 0;
	int i = 0;
	int n_state;
	struct net_device *idev=NULL;
	int found = 0;
	int need_reinit = 0;
	struct msg_to_ker *m;
	struct hlist_head *head = NULL;
	struct hlist_node *pos;
	struct sta_info *node;

	if(unlikely(!skb)) {
		return NF_ACCEPT;
	}

	/*struct sk_buff *sb = NULL;
	sb = skb;
	struct iphdr *iph;
	iph = ip_hdr(sb);
	sip = iph->saddr;
	dip = iph->daddr;
	//printk("Packet for source address: %d.%d.%d.%d\n destination address: %d.%d.%d.%d\n ", NIPQUAD(sip), NIPQUAD(dip));
	*/
	
	if(!g_bridge_mode){
		// check in_dev is br-lan
		if(skb->dev && (0 != strncmp(skb->dev->name, "br", 2))) {
			//printk("dev=%s\n", skb->dev->name);
			return NF_ACCEPT;
		}
	}

	if(skb->dev && (0 == strncmp(skb->dev->name, "lo", 2))) {
		return NF_ACCEPT;
	}

	eh = eth_hdr(skb);
	if(!eh) {
		return NF_ACCEPT;
	}

	if(eh->h_proto != htons(ETH_P_IP)) {
		//printk("eh->h_proto=%d\n", eh->h_proto);	
		return NF_ACCEPT;
	}

	if(skb_is_nonlinear(skb)){
		if(skb_linearize(skb) != 0){
			if (net_ratelimit())
				printk(KERN_ERR "dmsniff: failed to linearize ");
			return NF_ACCEPT;
		}
	}
	
	if(unlikely(!g_ap_flag)){
		return NF_ACCEPT;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
	idev = __dev_get_by_index(sock_net(skb->sk),skb->iif);
#else
	idev = __dev_get_by_index(sock_net(skb->sk),skb->skb_iif);
#endif

	if(!idev){
		printk("get dev name failed!\n");
		return NF_ACCEPT;	
	}
	
	if(0 == strncmp(idev->name, "eth", 3)){
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);

	if(iph && is_daddr_local(iph->daddr)){
		return NF_ACCEPT;
	}

	cret = check_sta_blk_wht(eh->h_source, iph->daddr, idev->name);
	if(DST_DENY == cret){
		return NF_DROP;
	}else if(IN_WHITE == cret || DST_ALLOW == cret){
		return NF_ACCEPT;
	}
	
	/*start sta check*/	
	read_lock(&g_table_lock);
	head = &sta_table[get_sta_hash(eh->h_source)];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
	hlist_for_each_entry_rcu(node, head, hlist) {
#else
	hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
		if((STATE_STALE != node->state) && (0 == memcmp(node->mac, eh->h_source, ETH_ALEN)) && 
			(0 == memcmp(node->ifname, idev->name, IFNAMSIZ))){
			found = 1;
			node->pre_timeout = jiffies + 5 * HZ;
			if(1 == node->will_timeout){
				if(have_important_pkt(iph)) {//important pkt means sta access in.
					node->will_timeout = 0;
					need_reinit = 1;
				}
			}
			node->timeout = jiffies + node->config_timeout * HZ;
			n_state = node->state;
			if(unlikely(!node->ipaddr || node->ipaddr != iph->saddr)){
				node->ipaddr = iph->saddr;
			}
			break;
		}
	}
	read_unlock(&g_table_lock);

	if(0 == found){
		do_add_sta(eh->h_source, iph->saddr, idev->name);
		/*snprintf(tmp_str, sizeof(tmp_str)-1, 
		"{\"type\":\"sta_control\",\"subtype\":\"upstream\","
		"\"data\":{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ip\":\"%d.%d.%d.%d\",\"dev\":\"%s\",\"state\":\"init\"}}", 
		eh->h_source[0],eh->h_source[1],eh->h_source[2],eh->h_source[3],eh->h_source[4],eh->h_source[5],
		NIPQUAD(iph->saddr),  skb->dev->name);*/
		m = build_sta_msg(eh->h_source, iph->saddr, idev->name, STA_INIT);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,66)
		sendnlmsg(m, sizeof(struct msg_to_ker)+sizeof(struct sta_ctl));
#endif		
		free_sta_msg(m);
	}else if(1 == found){
		if(1 == need_reinit){
			m = build_sta_msg(eh->h_source, iph->saddr, idev->name, STA_UPDATE_INIT);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,66)
			sendnlmsg(m, sizeof(struct msg_to_ker)+sizeof(struct sta_ctl));
#endif		
			free_sta_msg(m);
		}

		switch(n_state){
			case STATE_INIT:
				result = FLAG_PORTAL;
				break;
			case STATE_AUTHED:
				result = FLAG_ACCEPT;
				break;
			case STATE_UNAUTH:
				result = FLAG_PORTAL;
				break;
			case STATE_IN_PORTAL:
				result = FLAG_PORTAL;
				break;
			case STATE_IN_WHITE:
				result = FLAG_ACCEPT;
				break;
			case STATE_IN_BLACK:
				result = FLAG_DROP;
				break;
			case STATE_STALE:
				result = FLAG_PORTAL;
				break;
			default:
				result = FLAG_DROP;
				break;
		}
	}
	
	if(FLAG_ACCEPT == result){
		goto dm_accept;
	}else if(FLAG_DROP == result){
		//goto dm_drop;
	}else if(FLAG_PORTAL == result){
#ifdef KER_TEST	
		__be32 ip_portal1, ip_portal2, ip_portal3;
		ip_portal1 = in_aton("211.161.127.27");
		ip_portal2 = in_aton("118.144.162.20");
		ip_portal3 = in_aton("118.144.162.15");
		if (ip_portal1 == iph->daddr ||
			ip_portal2 == iph->daddr ||
			ip_portal3 == iph->daddr){
			goto dm_accept;
		}
#else		
		if(DST_ALLOW == is_dst_portal(iph->daddr)){
			goto dm_accept;
		}
#endif
		for(i = 0; i < MAX_WLAN_COUNT;i++){
			if(wlans[i].portal_ipaddr)
				break;	
		}
		if(i == MAX_WLAN_COUNT){
			goto dm_accept;	
		}

		dm_nat_http_packet(hooknum, skb, eh->h_source);
	}

	/*end sta_check*/

dm_accept:
	return NF_ACCEPT;  
dm_drop:
	return NF_DROP;
}

#ifdef MODEL_DMGROUTER
struct nf_hook_ops dmsniff_ops = {
    .hook = dmsniff,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_NAT_DST-2,
};

struct nf_hook_ops dmacl_ops = {
    .hook = dmacl,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_IP_PRI_CONNTRACK+2,
};
#else
struct nf_hook_ops dmsniff_ops = {
    .hook = dmsniff,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_NAT_DST-2,
}; 

struct nf_hook_ops dmacl_ops = {
    .hook = dmacl,
    .pf = NFPROTO_BRIDGE,
    .hooknum = NF_BR_FORWARD,
    .priority = NF_BR_PRI_FILTER_BRIDGED+2,
}; 
#endif
int dm_main_init(void)
{
	int i = 0;
	struct sta_info *sta;

	nf_register_hook(&dmsniff_ops);
	nf_register_hook(&dmacl_ops);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,3,8)
    nl_sk = netlink_kernel_create(&init_net, NETLINK_PENGWIFI, 1,
                                 nl_data_ready, NULL, THIS_MODULE);
#else
	struct netlink_kernel_cfg cfg = {
		.input	= nl_data_ready,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_PENGWIFI, &cfg);

#endif
    if(!nl_sk){
        printk(KERN_ERR "my_net_link: create netlink socket error.\n");
        return 1;
    }

    printk("pengwifi: create netlink socket ok.\n");

	rwlock_init(&g_table_lock);
	
	proc_dm_devices_init();

	for(i = 0; i < STA_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&sta_table[i]);
	}

	/*add anchor node*/
	sta = (struct sta_info *)kmalloc(sizeof(struct sta_info), GFP_KERNEL);
	if(!sta) {
		printk("dmcell: malloc memory failed.");
		return -1;
	}	
	memset(sta, 0, sizeof(struct sta_info));
	INIT_HLIST_NODE(&sta->hlist);
	memcpy(sta->mac, ANCHOR_MAC, ETH_ALEN);
	add_sta(sta);

	add_bw_anchor();
	/*add end*/

	/*init timer*/
	setup_timer(&sta_timer, timer_handler, 0);
	sta_timer.expires = jiffies + 5*HZ;
	add_timer(&sta_timer);
	
	/**/
    printk("pengwifi: module loaded\n");

    return 0;
}

static void dm_main_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,66)
    if(nl_sk != NULL){
        netlink_kernel_release(nl_sk);
    }
#endif	
	del_timer(&sta_timer);
	proc_dm_devices_exit();
	nf_unregister_hook(&dmacl_ops);  
	nf_unregister_hook(&dmsniff_ops);  

    printk("pengwifi: self module exited\n");
}

module_init(dm_main_init);
module_exit(dm_main_exit);

MODULE_AUTHOR("domy");
MODULE_LICENSE("GPL");

