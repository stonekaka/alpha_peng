/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     acl.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-14 17:42
***************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h> 
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <net/netfilter/nf_nat_core.h>

#include "ker.h"
#include "../user/pub.h"

rwlock_t g_sta_bw_lock;
struct hlist_head sta_bw_table[STA_HASH_SIZE];  //sta black/white list
rwlock_t g_dn_bw_lock;
struct hlist_head dn_bw_table[STA_HASH_SIZE];   //domain black/white list

extern int g_ap_flag;
extern int g_bridge_mode;
extern rwlock_t g_table_lock;
extern struct hlist_head sta_table[STA_HASH_SIZE];

#define IFNAME_FMT "athxx"
char *wlan_ifname[MAX_WLAN_COUNT][2]={{"ath0","ath16"},{"ath1","ath17"},{"ath2","ath18"},{"ath3","ath19"},{"ath4","ath20"},{"ath5","ath21"}};
struct wlan_arg wlans[MAX_WLAN_COUNT];

int is_dst_portal(unsigned int daddr)
{
	int ret = -1;
	int i = 0, j = 0;
	int n = 0;

	if(!daddr){
		return -1;
	}

	n = sizeof(wlans[0].portal_ipaddr)/sizeof(wlans[0].portal_ipaddr[0]);
		
	for(i = 0; i < MAX_WLAN_COUNT; i++) {
		for(j = 0; j < n; j++){
			if(0 != wlans[i].portal_ipaddr[j] && daddr == wlans[i].portal_ipaddr[j]){
				ret = DST_ALLOW;
				break;
			}
		}
	}

	return ret;
}

int check_sta_blk_wht(unsigned char *smac, unsigned int daddr, char *ifname)
{
	int ret = -1;
	int i = 0;
	int len = 0;
	struct hlist_head *head, *dn_head;
	struct hlist_node *pos, *dn_pos;
	struct sta_blk_wht *node;
	struct dn_blk_wht *dn_node;

	if(unlikely(!smac || !ifname)){
		return -1;
	}

	for(i = 0; i < MAX_WLAN_COUNT; i++) {
		if(wlans[i].no_portal &&
			(!strcmp(ifname, wlan_ifname[i][0]) || !strcmp(ifname, wlan_ifname[i][1]))){
			return IN_WHITE; //this ssid no need redirect to portal.
		}
	}

	len = strlen(IFNAME_FMT);

	read_lock(&g_sta_bw_lock);
	read_lock(&g_dn_bw_lock);
	for(i = 0; i < MAX_WLAN_COUNT; i++) {
		if(!strncmp(ifname, wlan_ifname[i][0], len) || !strncmp(ifname, wlan_ifname[i][1], len)){
			dn_head = &dn_bw_table[get_dn_bw_hash(daddr)];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
			hlist_for_each_entry_rcu(dn_node, dn_head, hlist) {
#else
			hlist_for_each_entry_rcu(dn_node, dn_pos, dn_head, hlist) {
#endif
				if(dn_node->ipaddr == daddr){
					if(dn_node->map[0][i]){
						ret = DST_DENY;
						break;
					}else if(dn_node->map[1][i]){
						ret = DST_ALLOW;
						break;
					}
				}
			}

			head = &sta_bw_table[get_sta_bw_hash(smac)];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
			hlist_for_each_entry_rcu(node, head, hlist) {
#else
			hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
				if(!memcmp(node->mac, smac, ETH_ALEN)){
					if(node->map[0][i]){
						ret = IN_BLACK;
						break;
					}else if(node->map[1][i]){
						ret = IN_WHITE;
						break;
					}
				}
			}
		}

		if(ret >= 0){
			break;
		}
	}
	read_unlock(&g_sta_bw_lock);
	read_unlock(&g_dn_bw_lock);

	return ret;
}

unsigned int dmacl(
	unsigned int hooknum,
	struct sk_buff * skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn) (struct sk_buff *))
{
	struct ethhdr *eh = NULL;
	struct iphdr *iph;
	int ret = NF_DROP;
	int cret = 0;
	struct hlist_head *head = NULL;
	struct hlist_node *pos;
	struct sta_info *node;
	struct net_device *idev = NULL;
	int i = 0;
	int found = 0;

	if(unlikely(!skb)) {
		return NF_ACCEPT;
	}

#ifdef MODEL_AP200
	if(!g_bridge_mode){
		// check in_dev is br-lan
		if(skb->dev && (0 != strncmp(skb->dev->name, "br", 2))) {
			//printk("dev=%s\n", skb->dev->name);
			return NF_ACCEPT;
		}
	}
#endif	

	eh = eth_hdr(skb);
	if(!eh) {
		return NF_ACCEPT;
	}

	if(eh->h_proto != htons(ETH_P_IP)) {
		//printk("eh->h_proto=%d\n", eh->h_proto);	
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);

	if(iph && (iph->protocol == IPPROTO_ICMP)){
		return NF_ACCEPT;
	}

	if(iph && (iph->protocol == IPPROTO_TCP)) {
		struct tcphdr *tcph;
		tcph = (struct tcphdr *)((char*)iph + iph->ihl*4);
		if(tcph && (tcph->dest == htons(53) || tcph->dest == htons(67))) {
			return NF_ACCEPT;
		}
	} else if(iph && (iph->protocol == IPPROTO_UDP)) {
		struct udphdr *udph;
		udph = (struct udphdr *)((char*)iph + iph->ihl*4);
		if(udph && ((udph->dest == htons(53)) || (udph->dest == htons(67)))) {
			return NF_ACCEPT;
		}
	}

	if(unlikely(!g_ap_flag)){
		//return NF_DROP;
		return NF_ACCEPT;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
	idev = __dev_get_by_index(sock_net(skb->sk),skb->iif);
#else
	idev = __dev_get_by_index(sock_net(skb->sk),skb->skb_iif);
#endif

	if(!idev){
		printk("get dev name failed !\n");
		return NF_ACCEPT;	
	}
	
	if(0 == strncmp(idev->name, "eth", 3)){
		read_lock(&g_table_lock);
#ifdef MODEL_AP200
		head = &sta_table[get_sta_hash(eh->h_dest)];
#endif		
#ifdef MODEL_DMGROUTER		
		for(i = 0; i < STA_HASH_SIZE; i++) {
			head = &sta_table[i];
#endif			
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			found = 0;
#ifdef MODEL_AP200
			if(0 == memcmp(node->mac, eh->h_dest, ETH_ALEN)){
#endif
#ifdef MODEL_DMGROUTER
			if(node->ipaddr == iph->daddr){
#endif
				node->downbytes += skb->len;
				if(node->downbytes > 1073741824){
					node->downbytes = 0;
					node->downbytes_g += 1;
				}
				found = 1;
			}
			if(found)break;
		}
#ifdef MODEL_DMGROUTER		
			if(found)break;
		}
#endif
		read_unlock(&g_table_lock);
		return NF_ACCEPT;
	}

	cret = check_sta_blk_wht(eh->h_source, iph->daddr, idev->name);
	if(IN_BLACK == cret){
		set_sta_state(eh->h_source, STATE_IN_BLACK);	
		return NF_DROP;
	}else if(DST_DENY == cret){
		return NF_DROP;
	}else if(IN_WHITE == cret){
		set_sta_state(eh->h_source, STATE_IN_WHITE);	
		return NF_ACCEPT;
	}else if(DST_ALLOW == cret){
		return NF_ACCEPT;
	}
	
	read_lock(&g_table_lock);
	head = &sta_table[get_sta_hash(eh->h_source)];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
	hlist_for_each_entry_rcu(node, head, hlist) {
#else
	hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
		if(0 == memcmp(node->mac, eh->h_source, ETH_ALEN)){
			if((node->state == STATE_AUTHED) || (node->state == STATE_IN_WHITE)){
				ret = NF_ACCEPT;	
				node->upbytes += skb->len;
				if(node->upbytes > 1073741824){
					node->upbytes = 0;
					node->upbytes_g += 1;
				}
			}else if(node->state == STATE_IN_PORTAL){
#ifdef KER_TEST
				__be32 ip_portal1, ip_portal2, ip_portal3;
				ip_portal1 = in_aton("211.161.127.27");
				ip_portal2 = in_aton("118.144.162.20");
				ip_portal3 = in_aton("118.144.162.15");
				if (ip_portal1 == iph->daddr ||
					ip_portal2 == iph->daddr ||
					ip_portal3 == iph->daddr){
					ret = NF_ACCEPT;
				}
#else				
				if(DST_ALLOW == is_dst_portal(iph->daddr)){
					ret = NF_ACCEPT;
				}
#endif
			}
			break;
		}
	}
	read_unlock(&g_table_lock);

#ifdef MODEL_DMGROUTER
	if(!g_bridge_mode){
		// check in_dev is br-lan
		if(skb->dev && (0 != strncmp(skb->dev->name, "br", 2))) {
			//printk("dev=%s\n", skb->dev->name);
			return NF_ACCEPT;
		}
	}
#endif	

	return ret;
}


