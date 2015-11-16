/***************************************************************************
* Copyright (C), 2013-2015, Beijing Teleron Telecom Engineering Co.,Ltd
* File name:     dmfilter.h
* Author:        renleilei - renleilei@ezlink.us
* Description:   
* Others: 
* Last modified: 2014-08-05 16:25
***************************************************************************/

#ifndef __DMFILTER_H
#define __DMFILTER_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat_core.h>
#include <linux/netfilter_bridge.h>
#include <net/sock.h>
#include <linux/jhash.h>


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
#include <linux/spinlock_types.h>
#else
//#include <linux/spinlock.h>
#include <linux/rwlock_types.h>
#endif

#include "../user/pub.h"

#define DM_ACCEPT    1
#define DM_DROP      0

#define IN_WHITE 0
#define IN_BLACK 1
#define DST_DENY 2
#define DST_ALLOW 3

#define STA_HASH_BITS   8
#define STA_HASH_SIZE   (1<<STA_HASH_BITS)

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
#define ANCHOR_HASH  13
#define STA_BW_ANCHOR_HASH  13
#define DN_BW_ANCHOR_HASH  234
#else
#define ANCHOR_HASH  194
#define STA_BW_ANCHOR_HASH  13
#define DN_BW_ANCHOR_HASH  13
#endif

extern rwlock_t g_table_lock;
extern struct hlist_head sta_table[STA_HASH_SIZE];

#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3]

enum _sta_state{
	STATE_INIT = 0,
	STATE_AUTHED,
	STATE_UNAUTH,
	STATE_IN_PORTAL,
	STATE_IN_WHITE,
	STATE_IN_BLACK,
	STATE_STALE
};

enum _dm_flag{
	FLAG_ACCEPT,
	FLAG_DROP,
	FLAG_PORTAL
};

struct sta_info {
	struct hlist_node hlist;
	struct list_head free_sta_list;
	unsigned char mac[ETH_ALEN];
	unsigned int ipaddr;
	int state;
	unsigned long timeout;
	char ifname[IFNAMSIZ];
};

struct sta_blk_wht{
	struct hlist_node hlist;
	struct list_head free_sta_list;
	unsigned char mac[ETH_ALEN]; 		
	/*ssid map
	 *[0][1][2][3][4][5] --black
	 *[0][1][2][3][4][5] --white
	 * */
#define SSMA_BLK 	0
#define SSMA_WHT	1
	int map[2][MAX_WLAN_COUNT];
};

struct dn_blk_wht{
	struct hlist_node hlist;
	struct list_head free_sta_list;
	unsigned int ipaddr;
	char domain[MAX_DOMAIN_LEN];
	/*ssid map
	 *[0][1][2][3][4][5] --black
	 *[0][1][2][3][4][5] --white
	 * */
#define SSMA_BLK 	0
#define SSMA_WHT	1
	int map[2][MAX_WLAN_COUNT];
};

unsigned int dmacl(
	unsigned int hooknum,
	struct sk_buff * skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn) (struct sk_buff *));

int proc_dm_devices_init(void);
int add_sta(struct sta_info *dev);
int del_sta(struct sta_info *dev);
int del_all_sta(void);

int add_bw_anchor(void);

int proc_dm_devices_init(void);
void proc_dm_devices_exit(void);


int do_add_sta_blk_wht(struct u_sta_blk_wht *in);
int do_add_dn_blk_wht(struct u_dn_blk_wht *in);
int clear_sta_blk_wht(void);
int clear_dn_blk_wht(void);

int check_sta_blk_wht(unsigned char *smac, unsigned int daddr, char *ifname);
int is_dst_portal(unsigned int daddr);

int do_add_sta(unsigned char *mac, unsigned int ipaddr, char *ifname);
static inline int get_sta_hash(const unsigned char *mac)
{
	int tmp = 0;
	
	if(unlikely(!mac)){
		printk("%s: input error.", __FUNCTION__);
		return -1;
	}

	tmp = mac[0] ^ mac[1];
	tmp = tmp ^ (mac[2] ^ mac[3]);
	tmp = tmp ^ (mac[4] ^ mac[5]);
		
	return jhash_1word(tmp, 0) & (STA_HASH_SIZE - 1);	
}

static inline int set_sta_state(const unsigned char *mac, int state)
{
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_info *node;

	if(unlikely(!mac))return -1;

	write_lock(&g_table_lock);
	head = &sta_table[get_sta_hash(mac)];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
	hlist_for_each_entry_rcu(node, head, hlist) {
#else
	hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
		if(0 == memcmp(node->mac, mac, ETH_ALEN)){
			node->state = state;
			break;
		}
	}
	write_unlock(&g_table_lock);
	return 0;
}

static inline int get_sta_bw_hash(const unsigned char *mac)
{
	int tmp = 0;
	
	if(unlikely(!mac)){
		printk("%s: input error.", __FUNCTION__);
		return -1;
	}

	tmp = mac[0] ^ mac[1];
	tmp = tmp ^ (mac[2] ^ mac[3]);
	tmp = tmp ^ (mac[4] ^ mac[5]);
		
	return jhash_1word(tmp, 0) & (STA_HASH_SIZE - 1);	
}

static inline int get_dn_bw_hash(unsigned int ipaddr)
{
	int tmp = 0;
	
	tmp = (int) ipaddr;
		
	return jhash_1word(tmp, 0) & (STA_HASH_SIZE - 1);	
}

#endif

