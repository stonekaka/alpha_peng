#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
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
extern rwlock_t g_table_lock;

extern rwlock_t g_sta_bw_lock;
extern struct hlist_head sta_bw_table[];
extern rwlock_t g_dn_bw_lock;
extern struct hlist_head dn_bw_table[];

extern struct wlan_arg wlans[];

static struct proc_dir_entry *g_pengwifi_proc_dir;

static inline char *get_state_str(char *state_str, int state)
{
	switch(state){
		case STATE_INIT:
			snprintf(state_str, 15, "I            ");
			break;
		case STATE_AUTHED:
			snprintf(state_str, 15, "  A          ");
			break;
		case STATE_UNAUTH:
			snprintf(state_str, 15, "    U        ");
			break;
		case STATE_IN_PORTAL:
			snprintf(state_str, 15, "      P      ");
			break;
		case STATE_IN_WHITE:
			snprintf(state_str, 15, "        W    ");
			break;
		case STATE_IN_BLACK:
			snprintf(state_str, 15, "          B  ");
			break;
		case STATE_STALE:
			snprintf(state_str, 15, "            S");
			break;
		default:
			snprintf(state_str, 15, "-            ");
			break;
	}

	return state_str;
}

static inline char *get_bw_map_str(char *map_str, int state[], int len)
{
#define __STR_YES "Y"
	snprintf(map_str, 15, "%s %s %s %s %s %s", 
		state[0]?__STR_YES:"_",
		state[1]?__STR_YES:"_",
		state[2]?__STR_YES:"_",
		state[3]?__STR_YES:"_",
		state[4]?__STR_YES:"_",
		state[5]?__STR_YES:"_"
		);

	return map_str;
}
static int stainfo_show(struct seq_file *f, void *v)
{
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_info *node;
	int i = 0;
	char state_str[16] = {0};
	char ip_str[24] = {0};
	
	read_lock(&g_table_lock);

	for(i = 0; i < STA_HASH_SIZE; i++) {
		if(0 == i){
			seq_printf(f, "HASH\tMAC\t\t\tIP\t\tI|A|U|P|W|B|S\tIFNAME\tUP\t\tUP_G\tDOWN\t\tDOWN_G\tW_TOUT\n");
		}
		head = &sta_table[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			if(0 == memcmp(node->mac, ANCHOR_MAC, ETH_ALEN)){
				continue;
			}
			snprintf(ip_str, 23, "%d.%d.%d.%d", NIPQUAD(node->ipaddr));
			seq_printf(f, "%d\t%02x:%02x:%02x:%02x:%02x:%02x\t%-15s\t%s\t%s\t%lu\t\t%lu\t%lu\t\t%lu\t%d\n", i, 
			node->mac[0],node->mac[1],node->mac[2],node->mac[3],node->mac[4],node->mac[5],
			ip_str, get_state_str(state_str, node->state), node->ifname,
			node->upbytes, node->upbytes_g, node->downbytes, node->downbytes_g, node->will_timeout);	
		}
	}
	read_unlock(&g_table_lock);

	return 0;
}

static int sta_bw_show(struct seq_file *f, void *v)
{
	struct hlist_head *head;
	struct hlist_node *pos;
	struct sta_blk_wht *node;
	int i = 0;
	char map_blk_str[16] = {0};
	char map_wht_str[16] = {0};
	
	read_lock(&g_sta_bw_lock);

	for(i = 0; i < STA_HASH_SIZE; i++) {
		if(0 == i){
			seq_printf(f, "    \t   \t\t\tBLACK\t\tWHITE\n");
			seq_printf(f, "HASH\tMAC\t\t\t1|2|3|4|5|6\t1|2|3|4|5|6\n");
		}
		head = &sta_bw_table[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			if(0 == memcmp(node->mac, ANCHOR_MAC, ETH_ALEN)){
				continue;
			}
			seq_printf(f, "%d\t%02x:%02x:%02x:%02x:%02x:%02x\t%s\t%s\n", i, 
			node->mac[0],node->mac[1],node->mac[2],node->mac[3],node->mac[4],node->mac[5],
			get_bw_map_str(map_blk_str, node->map[0], sizeof(node->map[0])/sizeof(node->map[0][0])), 
			get_bw_map_str(map_wht_str, node->map[1], sizeof(node->map[1])/sizeof(node->map[1][1])));	
		}
	}
	read_unlock(&g_sta_bw_lock);

	return 0;
}

static int dn_bw_show(struct seq_file *f, void *v)
{
	struct hlist_head *head;
	struct hlist_node *pos;
	struct dn_blk_wht *node;
	int i = 0;
	char map_blk_str[16] = {0};
	char map_wht_str[16] = {0};
	char ip_str[24] = {0};
	
	read_lock(&g_dn_bw_lock);

	for(i = 0; i < STA_HASH_SIZE; i++) {
		if(0 == i){
			seq_printf(f, "    \t   \t\tBLACK\t\tWHITE\n");
			seq_printf(f, "HASH\tIPs\t\t1|2|3|4|5|6\t1|2|3|4|5|6\tURL\n");
		}
		head = &dn_bw_table[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,38)
		hlist_for_each_entry_rcu(node, head, hlist) {
#else
		hlist_for_each_entry_rcu(node, pos, head, hlist) {
#endif
			if(node->ipaddr == ANCHOR_IP){
				continue;
			}
			snprintf(ip_str, 23, "%d.%d.%d.%d", NIPQUAD(node->ipaddr));
			seq_printf(f, "%d\t%-15s\t%s\t%s\t%-20s\n", i, 
			ip_str,
			get_bw_map_str(map_blk_str, node->map[0], sizeof(node->map[0])/sizeof(node->map[0][0])), 
			get_bw_map_str(map_wht_str, node->map[1], sizeof(node->map[1])/sizeof(node->map[1][1])),
			node->domain);
		}
	}
	read_unlock(&g_dn_bw_lock);

	return 0;
}

static int portal_proc_show(struct seq_file *f, void *v)
{
	int i = 0, j = 0;
	int n = 0;
	char ip_str[24] = {0};

	n = sizeof(wlans[0].portal_ipaddr)/sizeof(wlans[0].portal_ipaddr[0]);

	seq_printf(f, "NUM\tIPADDR              \tPORTAL_URL                     \t\t\tMAXTIME IDLETIME NO_PORTAL\n");
	for(i = 0; i < MAX_WLAN_COUNT; i++){
		snprintf(ip_str, 23, "%d.%d.%d.%d", NIPQUAD(wlans[i].portal_ipaddr[0]));
		seq_printf(f, "%-2d\t%-20s\t%-40s\t%-8d%-8d%-3d\n", i, ip_str,
			wlans[i].portal_url, wlans[i].max_time, wlans[i].idle_timeout, wlans[i].no_portal);
		for(j = 1; j < n; j++){
			if(!wlans[i].portal_ipaddr[j])continue;

			snprintf(ip_str, 23, "%d.%d.%d.%d", NIPQUAD(wlans[i].portal_ipaddr[j]));
			seq_printf(f, "%-8s\t%-20s\t%-40s\n", " ", ip_str, " ");
		}
	}

	return 0;
}

static void *stainfo_start(struct seq_file *f, loff_t *pos)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
#else
	return seq_hlist_start(&sta_table[ANCHOR_HASH], *pos);
#endif
}

static void *sta_bw_start(struct seq_file *f, loff_t *pos)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
	return NULL;
#else
	return seq_hlist_start(&sta_bw_table[STA_BW_ANCHOR_HASH], *pos);
#endif
}

static void *dn_bw_start(struct seq_file *f, loff_t *pos)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
	return NULL;
#else
	return seq_hlist_start(&dn_bw_table[DN_BW_ANCHOR_HASH], *pos);
#endif
}

static void *stainfo_next(struct seq_file *f, void *v, loff_t *pos)
{
	return NULL;
	//return seq_hlist_next(v, &sta_table, pos);
}

static void *sta_bw_next(struct seq_file *f, void *v, loff_t *pos)
{
	return NULL;
	//return seq_hlist_next(v, &sta_table, pos);
}

static void *dn_bw_next(struct seq_file *f, void *v, loff_t *pos)
{
	return NULL;
	//return seq_hlist_next(v, &sta_table, pos);
}

static void stainfo_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}

static void sta_bw_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}

static void dn_bw_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}

static const struct seq_operations stainfo_ops = {
	.start = stainfo_start,
	.next  = stainfo_next,
	.stop  = stainfo_stop,
	.show  = stainfo_show
};

static const struct seq_operations sta_bw_ops = {
	.start = sta_bw_start,
	.next  = sta_bw_next,
	.stop  = sta_bw_stop,
	.show  = sta_bw_show
};

static const struct seq_operations dn_bw_ops = {
	.start = dn_bw_start,
	.next  = dn_bw_next,
	.stop  = dn_bw_stop,
	.show  = dn_bw_show
};

static int stainfo_open(struct inode *inode, struct file *filp)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
	return single_open(filp, stainfo_show, NULL);
#else
	return seq_open(filp, &stainfo_ops);
#endif
}

static int sta_bw_open(struct inode *inode, struct file *filp)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
	return single_open(filp, sta_bw_show, NULL);
#else
	return seq_open(filp, &sta_bw_ops);
#endif
}

static int dn_bw_open(struct inode *inode, struct file *filp)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
	return single_open(filp, dn_bw_show, NULL);
#else
	return seq_open(filp, &dn_bw_ops);
#endif
}

static int portal_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, portal_proc_show, NULL);
}

static const struct file_operations proc_stainfo_operations = {
	.open		= stainfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static const struct file_operations proc_sta_bw_operations = {
	.open		= sta_bw_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static const struct file_operations proc_dn_bw_operations = {
	.open		= dn_bw_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static const struct file_operations proc_portal_operations = {
	.open		= portal_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

int proc_dm_devices_init(void)
{
	g_pengwifi_proc_dir = proc_mkdir("pengwifi", NULL);
	if(!g_pengwifi_proc_dir)
		return 1;
	
	proc_create("pengwifi/stas", 0, NULL, &proc_stainfo_operations);
	proc_create("pengwifi/1_sta_bw", 0, NULL, &proc_sta_bw_operations);
	proc_create("pengwifi/2_dn_bw", 0, NULL, &proc_dn_bw_operations);
	proc_create("pengwifi/3_portal", 0, NULL, &proc_portal_operations);
	return 0;
}

void proc_dm_devices_exit(void) {
//#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
#if 1
	if(g_pengwifi_proc_dir){
		remove_proc_entry("stas", g_pengwifi_proc_dir);
		remove_proc_entry("1_sta_bw", g_pengwifi_proc_dir);
		remove_proc_entry("2_dn_bw", g_pengwifi_proc_dir);
		remove_proc_entry("3_portal", g_pengwifi_proc_dir);
		remove_proc_entry("pengwifi", NULL);
	}
#else
	proc_remove(g_pengwifi_proc_dir);		
#endif
}


