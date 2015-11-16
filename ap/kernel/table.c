/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     table.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-12 15:31
***************************************************************************/

#include "ker.h"

extern unsigned char _tmp_mac[ETH_ALEN];
#ifndef ANCHOR_MAC
#define ANCHOR_MAC    _tmp_mac
#endif

extern unsigned int _tmp_ip;
#ifndef ANCHOR_IP
#define ANCHOR_IP     _tmp_ip
#endif

extern struct hlist_head sta_table[];
extern struct hlist_head sta_table[STA_HASH_SIZE];
extern rwlock_t g_table_lock;

extern rwlock_t g_sta_bw_lock;
extern struct hlist_head sta_bw_table[STA_HASH_SIZE];
extern rwlock_t g_dn_bw_lock;
extern struct hlist_head dn_bw_table[STA_HASH_SIZE];

int add_sta(struct sta_info *sta)
{
	int ret = 0;
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_info *node;

	printk(KERN_ALERT"start add sta");

	if(unlikely(!sta)) {
		ret = -1;
		return ret;
	}

	write_lock(&g_table_lock);
	head = &sta_table[get_sta_hash(sta->mac)];
	//printk(KERN_ALERT"mac=%02x:%02x:%02x:%02x:%02x:%02x,hash=%d", sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],get_sta_hash(sta->mac));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
	hlist_for_each_entry_rcu(node, head, hlist) {printk(KERN_ALERT"%d\n", __LINE__);
#else
	hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
		if(0 == memcmp(sta->mac, node->mac, ETH_ALEN)) {printk(KERN_ALERT"%d\n", __LINE__);
			hlist_del_rcu(&node->hlist);printk(KERN_ALERT"%d\n", __LINE__);
			if(node) {printk(KERN_ALERT"%d\n", __LINE__);
				kfree(node);printk(KERN_ALERT"%d\n", __LINE__);
				//node = NULL;printk(KERN_ALERT"%d\n", __LINE__);
			}
		}
	}printk(KERN_ALERT"%d\n", __LINE__);
		
	hlist_add_head_rcu(&sta->hlist, head);	
	write_unlock(&g_table_lock);printk(KERN_ALERT"%d\n", __LINE__);

#if 1
	int i ;
	for(i = 0; i < STA_HASH_SIZE; i++) {
		head = &sta_table[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			printk(KERN_ALERT"hash=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x, ip=%d.%d.%d.%d\n", 
				i, node->mac[0],node->mac[1],node->mac[2],node->mac[3],node->mac[4],node->mac[5],
				 NIPQUAD(node->ipaddr));
		}
	}
#endif 
	return ret;
}

int del_sta(struct sta_info *sta)
{
	int ret = 0;
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_info *node, *inode;
	LIST_HEAD(free_list);

	if(unlikely(!sta)) {
		ret = -1;
		return ret;
	}

	write_lock(&g_table_lock);
	head = &sta_table[get_sta_hash(sta->mac)];
	//printk("%02x:%02x:%02x:%02x:%02x:%02x", dev->mac[0], dev->mac[1],dev->mac[2],dev->mac[3],dev->mac[4],dev->mac[5]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
	hlist_for_each_entry_rcu(node, head, hlist) {
#else
	hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
		if(0 == memcmp(sta->mac, node->mac, ETH_ALEN)) {
			list_add(&node->free_sta_list, &free_list);
			hlist_del_rcu(&node->hlist);	
		}
	}
	write_unlock(&g_table_lock);

	list_for_each_entry_safe(node, inode, &free_list, free_sta_list){
		list_del(&node->free_sta_list);
		kfree(node);
	}

	return ret;
}

int del_all_sta(void)
{
	int ret = 0;
	int i = 0;
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_info *node, *inode;
	LIST_HEAD(free_list);

	write_lock(&g_table_lock);
	for( i = 0; i < STA_HASH_SIZE; i++){
		head = &sta_table[i];
		//printk("%02x:%02x:%02x:%02x:%02x:%02x", dev->mac[0], dev->mac[1],dev->mac[2],dev->mac[3],dev->mac[4],dev->mac[5]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			if(0 == memcmp(node->mac, ANCHOR_MAC, ETH_ALEN)){
				continue;
			}
			list_add(&node->free_sta_list, &free_list);
			hlist_del_rcu(&node->hlist);	
		}
	}
	write_unlock(&g_table_lock);

	list_for_each_entry_safe(node, inode, &free_list, free_sta_list){
		list_del(&node->free_sta_list);
		kfree(node);
	}

	return ret;
}

int do_add_sta(unsigned char *mac, unsigned int ipaddr, char *ifname)
{
	int ret = 0;
	struct sta_info *tmp;
	
	if(!mac || !ifname){
		printk("mac is null.");
		return -1;
	}

	tmp = (struct sta_info *)kmalloc(sizeof(struct sta_info), GFP_KERNEL);
	if(!tmp) {
		printk("sta: malloc memory failed.");
		return -1;
	}	

	memset(tmp, 0, sizeof(struct sta_info));
	INIT_HLIST_NODE(&tmp->hlist);
	
	memcpy(tmp->mac, mac, ETH_ALEN);
	tmp->ipaddr = ipaddr;
	tmp->state = STATE_INIT;
	tmp->timeout = jiffies + 600 * HZ;
	memcpy(tmp->ifname, ifname, IFNAMSIZ);
	//printk(KERN_ALERT"add: %02x:%02x:%02x:%02x:%02x:%02x", tmp->mac[0], tmp->mac[1],tmp->mac[2],tmp->mac[3],tmp->mac[4],tmp->mac[5]);
	add_sta(tmp);

	return ret;
}

int do_del_sta(unsigned char *mac)
{
	int ret = 0;
	struct sta_info tmp;

	if(unlikely(!mac)){
		printk(KERN_INFO"input error !!!");
		return -1;
	}

	memset(&tmp, 0, sizeof(struct sta_info));
	memcpy(tmp.mac, mac, ETH_ALEN);
	//printk(KERN_ALERT"del: %02x:%02x:%02x:%02x:%02x:%02x", tmp.mac[0], tmp.mac[1],tmp.mac[2],tmp.mac[3],tmp.mac[4],tmp.mac[5]);
	del_sta(&tmp);

	return ret;
}

int add_sta_blk_wht(struct sta_blk_wht *in)
{
	int ret = 0;
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_blk_wht *node;

	printk(KERN_ALERT"start add sta_blk_wht");

	if(unlikely(!in)) {
		ret = -1;
		return ret;
	}

	write_lock(&g_sta_bw_lock);
	head = &sta_bw_table[get_sta_bw_hash(in->mac)];
	//printk(KERN_ALERT"mac=%02x:%02x:%02x:%02x:%02x:%02x,hash=%d", sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],get_sta_hash(sta->mac));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
	hlist_for_each_entry_rcu(node, head, hlist) {
#else
	hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
		if(0 == memcmp(in->mac, node->mac, ETH_ALEN)) {
			hlist_del_rcu(&node->hlist);	
			if(node) {
				kfree(node);
				//node = NULL;
			}
		}
	}

	hlist_add_head_rcu(&in->hlist, head);	
	write_unlock(&g_sta_bw_lock);

#if 1
	int i;
	for(i = 0; i < STA_HASH_SIZE; i++) {
		head = &sta_bw_table[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			printk(KERN_ALERT"hash=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x, map=%d.%d.%d.%d.%d.%d  %d.%d.%d.%d.%d.%d\n", 
				i, node->mac[0], node->mac[1], node->mac[2], node->mac[3], node->mac[4], node->mac[5],
				node->map[0][0], node->map[0][1], node->map[0][2],
				node->map[0][3], node->map[0][4], node->map[0][5],
				node->map[1][0], node->map[1][1], node->map[1][2],
				node->map[1][3], node->map[1][4], node->map[1][5]);
		}
	}
#endif 
	return ret;
}

int add_dn_blk_wht(struct dn_blk_wht *in)
{
	int ret = 0;
	struct hlist_head *head;
	struct hlist_node *pos;
	struct dn_blk_wht *node;

	printk(KERN_ALERT"start add dn_blk_wht");

	if(unlikely(!in)) {
		ret = -1;
		return ret;
	}

	write_lock(&g_dn_bw_lock);
	head = &dn_bw_table[get_dn_bw_hash(in->ipaddr)];
	//printk("ip hash=%d\n",get_dn_bw_hash(in->ipaddr[0]));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
	hlist_for_each_entry_rcu(node, head, hlist) {
#else
	hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
		if(in->ipaddr == node->ipaddr) {
			hlist_del_rcu(&node->hlist);	
			if(node) {
				kfree(node);
				//node = NULL;
			}
		}
	}

	hlist_add_head_rcu(&in->hlist, head);	
	write_unlock(&g_dn_bw_lock);

#if 1
	int i ;
	for(i = 0; i < STA_HASH_SIZE; i++) {
		head = &dn_bw_table[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			printk(KERN_ALERT"hash=%d, ip=%d.%d.%d.%d, map=%d.%d.%d.%d.%d.%d  %d.%d.%d.%d.%d.%d\n", 
				i, NIPQUAD(node->ipaddr), 
				node->map[0][0], node->map[0][1], node->map[0][2],
				node->map[0][3], node->map[0][4], node->map[0][5],
				node->map[1][0], node->map[1][1], node->map[1][2], 
				node->map[1][3], node->map[1][4], node->map[1][5]);
		}
	}
#endif 
	return ret;
}

int clear_sta_blk_wht(void)
{
	int ret = 0;
	int i = 0;
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_blk_wht *node, *inode;
	LIST_HEAD(free_list);

	write_lock(&g_sta_bw_lock);
	for(i = 0; i < STA_HASH_SIZE; i++){
		head = &sta_bw_table[i];
		//printk("%02x:%02x:%02x:%02x:%02x:%02x", dev->mac[0], dev->mac[1],dev->mac[2],dev->mac[3],dev->mac[4],dev->mac[5]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			if(0 == memcmp(node->mac, ANCHOR_MAC, ETH_ALEN)){
				continue;
			}
			list_add(&node->free_sta_list, &free_list);
			hlist_del_rcu(&node->hlist);
		}
	}
	write_unlock(&g_sta_bw_lock);

	list_for_each_entry_safe(node, inode, &free_list, free_sta_list){
		list_del(&node->free_sta_list);
		kfree(node);
	}

	return ret;
}

int clear_dn_blk_wht(void)
{
	int ret = 0;
	int i = 0;
	struct hlist_head *head;
	struct hlist_node *pos;
	struct dn_blk_wht *node, *inode;
	LIST_HEAD(free_list);

	write_lock(&g_dn_bw_lock);
	for(i = 0; i < STA_HASH_SIZE; i++){
		head = &dn_bw_table[i];
		//printk("%02x:%02x:%02x:%02x:%02x:%02x", dev->mac[0], dev->mac[1],dev->mac[2],dev->mac[3],dev->mac[4],dev->mac[5]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			if(node->ipaddr == ANCHOR_IP){
				continue;
			}
			list_add(&node->free_sta_list, &free_list);
			hlist_del_rcu(&node->hlist);
		}
	}
	write_unlock(&g_dn_bw_lock);

	list_for_each_entry_safe(node, inode, &free_list, free_sta_list){
		list_del(&node->free_sta_list);
		kfree(node);
	}

	return ret;
}

int do_add_sta_blk_wht(struct u_sta_blk_wht *in)
{
	int ret = 0;
	struct sta_blk_wht *tmp;
	
	if(!in){
		printk("do_add_sta_blk_wht:  arg is null.");
		return -1;
	}

	tmp = (struct sta_blk_wht *)kmalloc(sizeof(struct sta_blk_wht), GFP_KERNEL);
	if(!tmp) {
		printk("sta: malloc memory failed.");
		return -1;
	}	

	memset(tmp, 0, sizeof(struct sta_blk_wht));
	INIT_HLIST_NODE(&tmp->hlist);
	
	memcpy(tmp->mac, in->mac, ETH_ALEN);
	memcpy(tmp->map, in->map, sizeof(in->map));
	//printk(KERN_ALERT"add: %02x:%02x:%02x:%02x:%02x:%02x", tmp->mac[0], tmp->mac[1],tmp->mac[2],tmp->mac[3],tmp->mac[4],tmp->mac[5]);
	add_sta_blk_wht(tmp);

	return ret;
}

int do_add_dn_blk_wht(struct u_dn_blk_wht *in)
{
	int ret = 0;
	struct dn_blk_wht *tmp;
	
	if(!in){
		printk("do_add_sta_blk_wht:  arg is null.");
		return -1;
	}

	tmp = (struct dn_blk_wht *)kmalloc(sizeof(struct dn_blk_wht), GFP_KERNEL);
	if(!tmp) {
		printk("sta: malloc memory failed.");
		return -1;
	}	

	memset(tmp, 0, sizeof(struct dn_blk_wht));
	INIT_HLIST_NODE(&tmp->hlist);
	
	tmp->ipaddr = in->ipaddr;
	memcpy(tmp->map, in->map, sizeof(in->map));
	memcpy(tmp->domain, in->domain, sizeof(in->domain));
	printk(KERN_ALERT"mapsize=%d, ip=%d.%d.%d.%d, map=%d.%d.%d.%d.%d.%d  %d.%d.%d.%d.%d.%d\n", 
		sizeof(in->map), NIPQUAD(tmp->ipaddr), 
		tmp->map[0][0], tmp->map[0][1], tmp->map[0][2],
		tmp->map[0][3], tmp->map[0][4], tmp->map[0][5],
		tmp->map[1][0], tmp->map[1][1], tmp->map[1][2], 
		tmp->map[1][3], tmp->map[1][4], tmp->map[1][5]);
	add_dn_blk_wht(tmp);

	return ret;
}

