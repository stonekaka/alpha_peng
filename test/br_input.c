/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/igmp.h>
#include <linux/if_arp.h>
#include <linux/spinlock.h>
#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/times.h>
#include <linux/timer.h>
#include <linux/jhash.h>
#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/ip.h>
#ifdef  CONFIG_MULTI_VLAN  /* Jack add 25/03/08 +++ */
#include "br_vlan_alpha.h"
#endif
/*+++ Limited Administration, Builder, 2008/03/11 +++*/
#ifdef CONFIG_LIMITED_ADMIN
#include <linux/if_vlan.h>
#endif /*CONFIG_LIMITED_ADMIN*/
/*+++ Limited Administration, Builder, 2008/03/11 +++*/
#ifdef CONFIG_IPV6
#include <net/ipv6.h>
#endif
#ifdef ELBOX_PROGS_PRIV_MDNS_BC2UC
spinlock_t	 dnslock;
 struct br_mac_ap_table_t dnslist;
static char dnsinit;
   struct ath_name
   	{
   		char name[6];
	};
  
extern const char*ether_sprintf(const u_int8_t *mac);
#endif
#define is_print(skb) \
do{\
	struct iphdr *iph;\
	struct tcphdr *tcph;\
\
	if(!skb){\
		f=0;/*printk("%s,%d: no skb\n",__FUNCTION__,__LINE__);*/\
	}else{\
		if(skb->protocol != htons(ETH_P_IP)){\
			f=0;/*printk("%s,%d: not ip pkt\n",__FUNCTION__,__LINE__);*/\
		}else{\
			iph = ip_hdr(skb);\
			if(iph && iph->protocol == IPPROTO_TCP) {\
				tcph = (struct tcphdr *)((char*)iph + iph->ihl*4);\
				if(tcph && tcph->dest == htons(80)) { \
					f= 1;\
				}\
			}\
		}\
	}\
}while(0)
/*+++ Limite  Administration, Builder, 2008/03/11 +++*/
#ifdef CONFIG_LIMITED_ADMIN
/*Check IP falls into Admin Range(return 1) or not(return 0).*/
int iprangecheck(struct net_bridge *br, unsigned int ip)
{
    int poolidx;
    for(poolidx=0; poolidx<4; poolidx++)
    {
        if((ip>=br->admin_ip_pool[poolidx].startip)&&(ip<=br->admin_ip_pool[poolidx].endip))
            return 1;
    }
    /*if admin ip pool is empty, we allow all packet.just like limited ip is disabled.phelpsll,2009-7-15*/
    for(poolidx=0; poolidx<4; poolidx++)
    {
        if((0 != br->admin_ip_pool[poolidx].startip) || (0 != br->admin_ip_pool[poolidx].endip))
            return 0;
    }
    return 1;
}
#endif /*CONFIG_LIMITED_ADMIN*/
/*+++ Limited Administration, Builder, 2008/03/11 +++*/
/*
function: pkt_should_block
	added by phelpsll, 2010/04/16
return value:
	0 , not in black list, not to check admin IP.
	1 , should check admin IP.
others:
	the document "admin IP range spec.ppt" describes all the ports those should be blocked.
*/
#include <linux/tcp.h>
static int pkt_should_block(struct net_bridge *br,struct sk_buff *skb, struct iphdr *iphdp)
{
    static int blocked_tcp_dest_ports[]= {80,443,23,22}; //HTTP,HTTPS,telnet,SSH
    /*if AP array is disabled, don't check 55000
      if neap is disabled, don't check 0xfc00.
      because, UDP protocol could use those ports bigger than 1024 connecting to some remote server.*/
    static int blocked_udp_dest_ports[]= {161/*,55000,0xfc00*/}; //SNMP,AP array,neap
    static int blocked_tcp_source_ports[]= {20,21}; //FTP(ap is not server but client)
    static int blocked_udp_source_ports[]= {69}; //TFTP(ap is not server but client)

    if (iphdp->protocol==IPPROTO_TCP)
    {
        int dest_port;
        int source_port;
        int i;
        struct tcphdr _ports, *pptr;
        pptr = skb_header_pointer(skb, iphdp->ihl*4,sizeof(_ports), &_ports);
        if (pptr==NULL)
            return 0;
        dest_port = ntohs(pptr->dest);
        for (i=0; i<ARRAY_SIZE(blocked_tcp_dest_ports); i++)
        {
            if (dest_port == blocked_tcp_dest_ports[i])
            {
                return 1;
            }
        }
        source_port = ntohs(pptr->source);
        for (i=0; i<ARRAY_SIZE(blocked_tcp_source_ports); i++)
        {
            if (source_port == blocked_tcp_source_ports[i])
            {
                return 1;
            }
        }
    }
    else if (iphdp->protocol==IPPROTO_UDP)
    {
        int dest_port;
        int source_port;
        int i;
        struct udphdr _ports, *pptr;
        pptr = skb_header_pointer(skb, iphdp->ihl*4,sizeof(_ports), &_ports);
        if (pptr==NULL)
            return 0;
        dest_port = ntohs(pptr->dest);
        for (i=0; i<ARRAY_SIZE(blocked_udp_dest_ports); i++)
        {
            if (dest_port == blocked_udp_dest_ports[i])
            {
                return 1;
            }
        }
        source_port = ntohs(pptr->source);
        for (i=0; i<ARRAY_SIZE(blocked_udp_source_ports); i++)
        {
            if (source_port == blocked_udp_source_ports[i])
            {
                return 1;
            }
        }
        /*when aparray is not enabled, we don't block dest port 55000*/
        if (br->block_aparray == 1 && dest_port == 55000)
        {
            return 1;
        }
        /*when neap is not enabled, we don't block dest port 0xfc00*/
        if (br->block_neap == 1 && dest_port == 0xfc00)
        {
            return 1;
        }
    }
    return 0;
}

/* Bridge group multicast address 802.1d (pg 51). */
const u8 br_group_address[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

#ifdef CONFIG_BRIDGE_MAC_CLONE
void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
#else
static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
#endif
{int f=0;is_print(skb); if(f)printk("%s:%d ++++++start++++%d++\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
    struct net_device *indev, *brdev = br->dev;

    /*+++ Limited Administration, Builder, 2008/03/11 +++*/
#ifdef CONFIG_LIMITED_ADMIN
    struct ethhdr           *ethhd;
#endif /*CONFIG_LIMITED_ADMIN*/
    /*+++ Limited Administration, Builder, 2008/03/11 +++*/

    /*+++ Limited Administration, Builder, 2008/03/11 +++*/
#ifdef CONFIG_LIMITED_ADMIN
    ethhd = eth_hdr(skb);

    /*****************************
    *  0: Limited Admin Disable  *
    *  1: Admin with VID         *
    *  2: Admin with Limited IP  *
    ******************************/
    if(br->limit_admin_type & LIMITED_ADMIN_TYPE_VID)
    {
        /*1: Admin with VID*/
        if(ntohs(ethhd->h_proto)!=EAPOL_TYPE)//Joe, 2009-08-27, let EAPOL packets go if any
        {
            if(ntohs(ethhd->h_proto)==ETH_P_8021Q)
            {
                struct vlan_hdr *tcip, tci;
                tcip = skb_header_pointer(skb, 0, sizeof(struct vlan_hdr), &tci);

                /*Check VLAN ID*/
                if(tcip!=NULL && (tcip->h_vlan_TCI&VLAN_VID_MASK) != br->admin_vid)
                {if(f)printk("%s:%d ++++++drop3++++++\n",__FUNCTION__,__LINE__);
                    /*Not My VLAN ID: free skb and drop it.*/
                    kfree_skb(skb);
                    br->statistics.rx_dropped++;
                    return;
                }
                else
                {
                    /*My VLAN ID: move data point to ip header and let it go.*/
                    skb->protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
                    skb_pull(skb, sizeof(struct vlan_hdr));
                }
            }
            else
            {
                /*not 802.1Q packet: free skb and drop it.*/
                /*except DHCP packets.*/
                int is_dhcp_packet = 0;
                if (ntohs(ethhd->h_proto)==0x0800)
                {
                    struct iphdr _iph, *ih;
                    ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
                    if(ih!=NULL && ih->protocol==0x11)
                    {
                        struct udphdr _ports, *pptr;
                        pptr = skb_header_pointer(skb, ih->ihl*4,sizeof(_ports), &_ports);
                        if(pptr!=NULL && (pptr->dest==0x43 || pptr->dest==0x44))
                        {
                            is_dhcp_packet = 1;
                        }
                    }
                }
                if (!is_dhcp_packet)
                {if(f)printk("%s:%d ++++++drop 2++++++\n",__FUNCTION__,__LINE__);
                    kfree_skb(skb);
                    br->statistics.rx_dropped++;
                    return;
                }
            }
        }
    }
#endif /*CONFIG_LIMITED_ADMIN*/
    /*+++ Limited Administration, Builder, 2008/03/11 +++*/
#ifdef  CONFIG_MULTI_VLAN  /* Jack add 25/03/08 +++ */
    if (br->vlan_state == VLAN_ENABLE)
    {
        if (br->vlan_mode == VLAN_STATIC) // static vlan mode
        {
            int state = alpha_vlan_to_TCP(br, skb);
            if (state == VLAN_DROP_PKT_AND_DONT_FREE_SKB)
            {
#if VLAN_DEBUG_LV0
                printk(" no_to_TCP \n");
#endif
                return;
            }
            //else   // pass

#if  VLAN_DEBUG_LV0
            printk(" to_TCP \n");
#endif
        }
        else if (br->vlan_mode == VLAN_DYNAMIC) // DYNAMIC vlan mode
        {
            int state = alpha_NAP_vlan_to_TCP(br, skb);
            if (state == VLAN_DROP_PKT_AND_DONT_FREE_SKB)
            {
#if VLAN_DEBUG_LV0
                printk(" no_to_TCP! \n");
#endif
                return;
            }
            //else   // pass
#if VLAN_DEBUG_LV0
            printk(" to_TCP! \n");
#endif
        }
    }
#endif     // end of #ifdef CONFIG_MULTI_VLAN  /* Jack add 25/03/08 --- */
#ifdef CONFIG_LIMITED_ADMIN
    if(br->limit_admin_type & LIMITED_ADMIN_TYPE_IP)
    {
        /*2: Admin with Limited IP*/
        /*phelpsll:limited_IP_and_limited_VLAN_can_work_at_the_sametime.
          if the packet is taged, skip VLAN tag and check next 4 byte*/
        struct ethhdr *ethhd = eth_hdr(skb);
        if(ntohs(ethhd->h_proto!=EAPOL_TYPE))//Joe, 2009-08-27, let EAPOL packets go if any
        {
            if(ntohs(ethhd->h_proto)==ETH_P_8021Q)
            {
                char* tmp = (char*)ethhd;
                ethhd = (void*)(tmp+4);
            }
            if(ntohs(ethhd->h_proto)==ETH_P_IP)
            {
                /*Check IP packet*/
                struct iphdr        *iphdp;
                struct iphdr        iphd;
                iphdp = skb_header_pointer(skb, 0, sizeof(struct iphdr), &iphd);

                /*Match IP range?*/
                if(iphdp!=NULL && !iprangecheck(br, iphdp->saddr) && pkt_should_block(br, skb,iphdp) )
                {if(f)printk("%s:%d ++++++ drop 1++++++\n",__FUNCTION__,__LINE__);
                    /*No: free skb and drop it.*/
                    kfree_skb(skb);
                    br->statistics.rx_dropped++;
                    return;
                }
            }
        }
    }
#endif
    /*dhcp server no provide to eth0's pc 2008-01-23 dennis start */
    /*phelpsll:when group vid is enabled, eth0's pc can get ip through dhcp.
    to fix it, move this function after group vid add.*/
#ifdef CONFIG_DHCP_SERVER_ENABLE
    {
        struct iphdr _iph, *ih;
        struct ethhdr *ethhd = eth_hdr(skb);
        if(br->dhcp_server_enable==1)
        {
            /*phelpsll:limited_IP_and_limited_VLAN_can_work_at_the_sametime.
              if the packet is taged, skip VLAN tag and check next 4 byte*/
            if(ntohs(ethhd->h_proto)==ETH_P_8021Q)
            {
                char* tmp = (char*)ethhd;
                ethhd = (void*)(tmp+4);
            }
#if defined(ELBOX_MODEL_DAP2695) || defined(ELBOX_MODEL_LAP300) || defined(ELBOX_MODEL_WAPAC02A) || defined(ELBOX_MODEL_DAP3662)
            if((!strncmp(skb->dev->name,"eth0",4)) || !strncmp(skb->dev->name,"eth1",4))
            {
#else
            if((!strncmp(skb->dev->name,"eth0",4)))
            {
#endif
                if(ntohs(ethhd->h_proto)==0x0800)
                {
                    ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
                    if(ih!=NULL && ih->protocol==0x11)
                    {
                        struct udphdr _ports, *pptr;
                        pptr = skb_header_pointer(skb, ih->ihl*4,sizeof(_ports), &_ports);
                        if(pptr !=NULL)
                        {
                            if(pptr->dest==0x43)
                            {
                                kfree_skb(skb);
                                return 0;
                            }
                        }

                    }
                }
            }
        }
    }
#endif
    brdev->stats.rx_packets++;
    brdev->stats.rx_bytes += skb->len;

    indev = skb->dev;
    skb->dev = brdev;if(f)printk("%s:%d ++++++go to netfi_receive_skb++++%d++\n",__FUNCTION__,__LINE__,skb?skb->len:-1);

    NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
            netif_receive_skb);
}

#ifdef CONFIG_IGMP_SNOOP
static int remove_ap_GROUP_from_pool(struct port_igmp_ap_table_t *pt, int gIdx)
{

    pt->group_list[gIdx].used = 0;
    pt->group_list[gIdx].ip_addr = 0;
    pt->group_list[gIdx].max_response_time=0;
    pt->group_list[gIdx].port_aging_time=0;
    pt->group_list[gIdx].in_special_query=0;
    return 0;
}
static int check_ap_GROUP_is_empty_and_remove(struct port_igmp_ap_table_t *pt, int gIdx)
{
    int i,used=0;
    for (i=0; i<HOSTLIST_NUMBER; ++i)
    {
        if (pt->group_list[gIdx].host_list[i].used == 1)
            ++used;
    }
    if (used == 0)
    {
        remove_ap_GROUP_from_pool(pt, gIdx);
        return 0;
    }
    else
        return 0;
}
void br_timer_check_table(unsigned long __data)
{
    struct net_bridge *br = (struct net_bridge *)__data;
    struct net_bridge_port *p;

    atomic_set(&br->br_igmp_AP_query_enable, 0);
    if(br->igmp_switch_query_timer!=0)
    {
        br->igmp_switch_query_timer = br->igmp_switch_query_timer - 5;
    }
    else
    {

        list_for_each_entry_rcu(p, &br->port_list, list)
        {
            write_lock(&p->port_igmp_ap_table_rwlock);
            if(p->port_igmp_ap_table.enable == 1)
            {
                int i;
                for (i=0; i< GROUPLIST_NUMBER; ++i)
                {
                    if(p->port_igmp_ap_table.group_list[i].used == 1)
                    {
                        //aging >0 and flag = 0
                        if ((p->port_igmp_ap_table.group_list[i].port_aging_time > 0)&&(p->port_igmp_ap_table.group_list[i].in_special_query == 0) )
                        {
                            p->port_igmp_ap_table.group_list[i].port_aging_time = p->port_igmp_ap_table.group_list[i].port_aging_time - 5;
                        }
                        //aging =0 so set flag =0 and reponse time = 10
                        else if ((p->port_igmp_ap_table.group_list[i].port_aging_time == 0)&&(p->port_igmp_ap_table.group_list[i].in_special_query == 0) )
                        {
                            p->port_igmp_ap_table.group_list[i].in_special_query = 1;
                            p->port_igmp_ap_table.group_list[i].max_response_time = 15;
                            atomic_set(&br->br_igmp_AP_query_enable, 1); // send igmp query
                        }
                        //aging =0 and flag =1 and response >0
                        else if ((p->port_igmp_ap_table.group_list[i].port_aging_time == 0)&&(p->port_igmp_ap_table.group_list[i].in_special_query == 1)&&(p->port_igmp_ap_table.group_list[i].max_response_time>0) )
                        {
                            p->port_igmp_ap_table.group_list[i].max_response_time = p->port_igmp_ap_table.group_list[i].max_response_time -5;

                        }
                        //aging time ==0 flag ==1 response time ==0
                        else if ((p->port_igmp_ap_table.group_list[i].port_aging_time == 0)&&(p->port_igmp_ap_table.group_list[i].in_special_query == 1)&&(p->port_igmp_ap_table.group_list[i].max_response_time<=0) )
                        {
                            int j,k;
                            for(j=0; j<8; j++)
                            {
                                p->port_igmp_ap_table.group_list[i].host_list[j].used = 0;
                                for(k=0; k<6; k++)
                                {
                                    p->port_igmp_ap_table.group_list[i].host_list[j].mac_addr[k] = 0;
                                }
                            }
                            remove_ap_GROUP_from_pool(&p->port_igmp_ap_table,i);//remove group
                        }
                    }
                }
            }
            write_unlock(&p->port_igmp_ap_table_rwlock);

        }
    }
    mod_timer(& br->igmptimer, jiffies + 5*HZ);
}

void br_igmp_timer_enable(struct net_bridge *br)
{
    struct timer_list *timer = &br->igmptimer;
    init_timer(timer);
    timer->data = (unsigned long) br;
    timer->function = br_timer_check_table;
    timer->expires = jiffies + 5*HZ;
    add_timer(timer);
}
void br_igmp_timer_disable(struct net_bridge *br)
{
    del_timer(&br->igmptimer);
}


static int get_ap_MAC(unsigned char * mac_addr, struct net_bridge *br, uint32_t ip_addr)
{
    struct br_mac_ap_table_t *tlist;
    int find = -1;
    int i;
    read_lock(&br->br_mac_table_ap_rwlock);
    list_for_each_entry(tlist,&(br->br_mac_ap_table.list), list)
    {
        if ( tlist->ip_addr == ip_addr)
        {
            find = 0;
            for (i =0; i<6; i++)
                mac_addr[i] = tlist->mac_addr[i];
            break;
        }
    }
    read_unlock(&br->br_mac_table_ap_rwlock);
    return find;
}

int search_group_ap_IP(struct port_igmp_ap_table_t *pt, uint32_t ip_addr)
{
    int i;
    for (i=0; i< GROUPLIST_NUMBER; ++i)
    {
        if (pt->group_list[i].used == 1 )
            if (pt->group_list[i].ip_addr == ip_addr)
                return i;
    }
    return (-1);
}
static int search_ap_list_MAC(struct port_igmp_ap_table_t *pt, int groupIndex, unsigned char* mac_addr)
{
    int i;
    for (i=0; i<HOSTLIST_NUMBER; ++i)
    {
        if (pt->group_list[groupIndex].host_list[i].used==1)
            if (pt->group_list[groupIndex].host_list[i].mac_addr[0] == *mac_addr				)
                if (pt->group_list[groupIndex].host_list[i].mac_addr[1] == *(mac_addr+1)			)
                    if (pt->group_list[groupIndex].host_list[i].mac_addr[2] == *(mac_addr+2)		)
                        if (pt->group_list[groupIndex].host_list[i].mac_addr[3] == *(mac_addr+3)		)
                            if (pt->group_list[groupIndex].host_list[i].mac_addr[4] == *(mac_addr+4)	)
                                if (pt->group_list[groupIndex].host_list[i].mac_addr[5] == *(mac_addr+5)	)
                                    return i;
    }
    return (-1);
}

static int get_ap_element_from_MAC_pool(struct port_igmp_ap_table_t *pt ,int gIdx)
{
    int i;
    for(i=0; i<HOSTLIST_NUMBER; ++i)
    {
        if (pt->group_list[gIdx].host_list[i].used == 0) return i;
    }
    return (-1);
}
static int ap_add_MAC_2_pool(struct port_igmp_ap_table_t *pt, int gIdx, int mIdx, unsigned char* mac_addr)
{
    int i;
    pt->group_list[gIdx].host_list[mIdx].used =1;

    for (i=0; i<6; i++)
        pt->group_list[gIdx].host_list[mIdx].mac_addr[i] = *(mac_addr+i);
    return 0;
}

static int add_ap_GROUP(struct port_igmp_ap_table_t *pt, int gIdx, uint32_t ip_addr)
{
    pt->group_list[gIdx].used = 1;
    pt->group_list[gIdx].ip_addr = ip_addr;
    pt->group_list[gIdx].in_special_query = 0;
    pt->group_list[gIdx].port_aging_time = 125;
    pt->group_list[gIdx].max_response_time = 15;
    return 0;
}

static int check_ap_GROUP_pool(struct port_igmp_ap_table_t *pt)
{
    int i;
    for( i=0; i<GROUPLIST_NUMBER; ++i)
    {
        if( pt->group_list[i].used == 0) return i;
    }
    return -1;
}


static void add_to_port_igmp_ap_table_t(	struct net_bridge_port *p,	struct port_igmp_ap_table_t *pt,
        uint32_t ip32_addr, 	unsigned char * mac_addr)
{
    /* search group IP */
    int groupIdx,ipIdx;
    uint8_t *ip8_addr;
    groupIdx = search_group_ap_IP(pt, ip32_addr);//check the group ip exist or not
    if(groupIdx >= 0)
    {
        /* search list MAC */
        ipIdx = search_ap_list_MAC(pt, groupIdx, mac_addr);//check the group's sta_mac

        if(ipIdx >= 0 )
        {
            pt->group_list[groupIdx].port_aging_time = 125;
            pt->group_list[groupIdx].in_special_query = 0;
            pt->group_list[groupIdx].max_response_time = 15;
            //printk("[BR_IGMP_AP_PROC]-> MAChas been existed !!\n");

        }
        else
        {
            /* check MAC pool */
            int macPoolIdx;
            macPoolIdx = get_ap_element_from_MAC_pool(pt, groupIdx);
            if (macPoolIdx >=0 )
            {
                /* add MAC to pool */
                ap_add_MAC_2_pool(pt, groupIdx, macPoolIdx, mac_addr);
                //printk("[BR_IGMP_AP_PROC]-> MAC: %X:%X:%X:%X:%X:%X add !!\n",
                //		*mac_addr,*(mac_addr+1),*(mac_addr+2),*(mac_addr+3),*(mac_addr+4),*(mac_addr+5) );
                pt->group_list[groupIdx].port_aging_time = 125;
                pt->group_list[groupIdx].in_special_query = 0;
                pt->group_list[groupIdx].max_response_time = 15;
            }
            else
            {
                //printk("pool------error\n");
            }
        }
    }
    else
    {

        /* check group pool */
        int groupPoolIdx;
        groupPoolIdx = check_ap_GROUP_pool(pt);
        if(groupPoolIdx >= 0)
        {
            add_ap_GROUP(pt, groupPoolIdx, ip32_addr);
            trans_32to8(&ip32_addr, &ip8_addr);
            //printk(KERN_INFO "[BR_IGMP_AP_PROC]-> Group IP: %u.%u.%u.%u add !!\n",
            //									*ip8_addr, *(ip8_addr+1), *(ip8_addr+2), *(ip8_addr+3));

            ap_add_MAC_2_pool(pt, groupPoolIdx, 0, mac_addr);
            //printk("[BR_IGMP_AP_PROC]-> MAC: %X:%X:%X:%X:%X:%X add !!\n",
            //			*mac_addr,*(mac_addr+1),*(mac_addr+2),*(mac_addr+3),*(mac_addr+4),*(mac_addr+5) );

        }
        else
        {
            //printk("group pool is full------input\n");

        }
    }

    return;
}
static int remove_ap_MAC_from_pool(struct port_igmp_ap_table_t *pt, int gIdx, int mIdx)
{
    int i;
    pt->group_list[gIdx].host_list[mIdx].used = 0;

    for (i=0; i<6; i++)
        pt->group_list[gIdx].host_list[mIdx].mac_addr[i] = 0;
    return 0;
}


static void del_to_port_igmp_ap_table_t(struct port_igmp_ap_table_t *pt, uint32_t igmp_group_ip, unsigned char * sta_mac_addr)
{
    /* search group IP */
    int groupIdx,ipIdx;
    groupIdx = search_group_ap_IP(pt, igmp_group_ip);
    if(groupIdx >= 0)
    {
        /* search list MAC */
        ipIdx = search_ap_list_MAC(pt, groupIdx, sta_mac_addr);
        if(ipIdx >= 0)
        {
            /* remove MAC and check group member*/
            remove_ap_MAC_from_pool(pt, groupIdx, ipIdx);
            //printk("[BR_IGMP_AP_PROC]-> MAC: %X:%X:%X:%X:%X:%X remove !!\n",
            //			*sta_mac_addr,*(sta_mac_addr+1),*(sta_mac_addr+2),*(sta_mac_addr+3),*(sta_mac_addr+4),*(sta_mac_addr+5) );
            check_ap_GROUP_is_empty_and_remove(pt, groupIdx);
        }
        else
        {
            //printk(KERN_INFO "[BR_IGMP_AP_PROC]-> MAC: %X:%X:%X:%X:%X:%X does't exist !!\n",
            //			*sta_mac_addr,*(sta_mac_addr+1),*(sta_mac_addr+2),*(sta_mac_addr+3),*(sta_mac_addr+4),*(sta_mac_addr+5) );
        }
    }
    else
    {
        //	uint8_t *ip8_addr;
        //	trans_32to8(&igmp_group_ip, &ip8_addr);
        //	printk(KERN_INFO "[BR_IGMP_AP_PROC]-> Group IP: %u.%u.%u.%u does't exist !!\n",
        //										*ip8_addr, *(ip8_addr+1), *(ip8_addr+2), *(ip8_addr+3));
    }

    return;
}

static void IGMP_TABLE_CHECK(struct net_bridge *br ,struct sk_buff *skb2, __u32 igmp_group_ip)
{
    struct iphdr *iph1=ip_hdr(skb2);
    uint32_t ip32 = iph1->saddr;//sta's ip
    struct br_mac_ap_table_t *tlist;
    int find = 0;
    int i;
    struct net_bridge_fdb_entry *hit_fdb_entry;
    unsigned char sta_mac_addr[6];
    //uint32_t host_ip32_addr;
//=========	Add and update the Sta's Mac & ip to br_mac_ap_table_t table=====================
    list_for_each_entry(tlist,&(br->br_mac_ap_table.list), list)
    {
        if ( tlist->ip_addr == ip32)
        {
            find =1;
            struct ethhdr * src = eth_hdr(skb2);
            for (i =0; i<6; i++)
                tlist->mac_addr[i] = src->h_source[i];
            break;
        }
    }
    if (find == 0 )
    {
        struct br_mac_ap_table_t * new_entry;
        new_entry = (struct br_mac_ap_table_t *)kmalloc(sizeof(struct br_mac_ap_table_t), GFP_ATOMIC);
        if (new_entry != NULL)
        {
            struct ethhdr * src = eth_hdr(skb2);
            for (i =0; i<6; i++)
                new_entry->mac_addr[i] = src->h_source[i];
            new_entry->ip_addr = ip32;
            list_add(&(new_entry->list), &(br->br_mac_ap_table.list));
        }
        else
        {
            printk("[BR_MAC_AP_PROC]-> alloc new br_mac_ap_table_t fail !!\n");
        }
    }
//==============================================================================================
    if(get_ap_MAC(sta_mac_addr,br,ip32)!=0)
    {
        printk("get_ap_MAC------error\n");
        return;
    }
//printk("---------ip32==%x-------\n",ip32);
//printk("--------sta_mac_addr==%x:%x:%x:%x:%x:%x----\n",sta_mac_addr[0],sta_mac_addr[1],sta_mac_addr[2],sta_mac_addr[3],sta_mac_addr[4],sta_mac_addr[5]);
    hit_fdb_entry = br_fdb_get(br, sta_mac_addr);
    if (hit_fdb_entry != NULL)
    {
        if(atomic_read(&br->br_igmp_ap_table_enable) == 1)
        {
            if(atomic_read(&hit_fdb_entry->dst->ap_wireless_interface) == 1)
            {
                write_lock(&hit_fdb_entry->dst->port_igmp_ap_table_rwlock);
                //send group ip and sta's mac to add table
                add_to_port_igmp_ap_table_t(hit_fdb_entry->dst,&hit_fdb_entry->dst->port_igmp_ap_table,igmp_group_ip,sta_mac_addr);
                write_unlock(&hit_fdb_entry->dst->port_igmp_ap_table_rwlock);
                struct net_bridge_port *p;

                list_for_each_entry_rcu(p, &br->port_list, list)
                {
                    if(hit_fdb_entry->dst->port_no != p->port_no) //port_no -->ath0 or ath1 .....
                    {
                        write_lock(&p->port_igmp_ap_table_rwlock);
                        del_to_port_igmp_ap_table_t(&p->port_igmp_ap_table, igmp_group_ip, sta_mac_addr);
                        write_unlock(&p->port_igmp_ap_table_rwlock);
                    }

                }
            }
            else
            {
                //printk("wireless not enable-----------\n");
                br_fdb_put(hit_fdb_entry);
                return;
            }
        }
        br_fdb_put(hit_fdb_entry);
    }
    else
    {
        printk("error-------------input\n");
        return;
    }
    return;
}

static void IGMP_AP_TABLE_LEAVE(struct net_bridge *br ,struct sk_buff *skb2, __u32 igmp_group_ip)
{
    struct iphdr *iph1=ip_hdr(skb2);
    uint32_t ip32 = iph1->saddr;//sta's ip
    unsigned char sta_mac_addr[6];
    struct net_bridge_fdb_entry *hit_fdb_entry;
    if(get_ap_MAC(sta_mac_addr,br,ip32)!=0)
    {
        //printk("get_ap_MAC------error\n");
    }
    hit_fdb_entry = br_fdb_get(br, sta_mac_addr);//use sta's mac to find it in which port.
    if (hit_fdb_entry != NULL)
    {
        if(atomic_read(&hit_fdb_entry->dst->ap_wireless_interface) == 1)
        {
            write_lock(&hit_fdb_entry->dst->port_igmp_ap_table_rwlock);
            del_to_port_igmp_ap_table_t(&hit_fdb_entry->dst->port_igmp_ap_table, igmp_group_ip, sta_mac_addr);
            write_unlock(&hit_fdb_entry->dst->port_igmp_ap_table_rwlock);
        }
        else // wireless interface not enable in this port
        {
            br_fdb_put(hit_fdb_entry);
            //printk("in IGMP_AP_TABLE_LEAVE wireless not enable-------------- \n");
            return;
        }
        br_fdb_put(hit_fdb_entry);
    }
    else	 // not find the sta in any port
    {
        //printk("error IGMP_AP_TABLE_LEAVE hit_fdb_entry----------- \n");
        return;
    }
    return;
}
static int SHOULD_CHECK_IGMP_TABLE(u_int32_t group)
{
    u_int32_t  system_on_subnet=0xe0000001; //224.0.0.1
    u_int32_t  routers_on_subnet=0xe0000002;//224.0.0.2
    u_int32_t  llmnr_on_subnet=0xe00000fc;	//224.0.0.252
    u_int32_t  ssdp_on_subnet=0xeffffffa;	//239.255.255.250 SSDP, not care

    if(group == system_on_subnet
            ||group == routers_on_subnet
            ||group == llmnr_on_subnet
            ||group == ssdp_on_subnet)
        return false;

    else
        return true;
}

#endif
#ifdef ELBOX_PROGS_PRIV_MDNS_BC2UC
void dispaly_sta_mac(struct net_bridge *br )
{
	   struct br_mac_ap_table_t *tlist;
	   int i=0;
	  //  spin_lock_bh(dnslock);
	  list_for_each_entry(tlist,&(br->br_mac_ap_table.list), list)
	  	{
	  		i++;
	  		printk("MDNS[%d]:%s\n",i,ether_sprintf(tlist->mac_addr));
	  	}
	  return;
	 //    spin_unlock_bh(dnslock);
}
static void ADD_STA_MAC(struct net_bridge *br ,struct sk_buff *skb2)
{
	int i;
	int found=0;
   struct br_mac_ap_table_t *tlist;    
	//=========	Add and update the Sta's Mac & ip to br_mac_ap_table_t table=====================

if(!dnsinit)
	INIT_LIST_HEAD(&(br->br_mac_ap_table.list));
    list_for_each_entry(tlist,&(br->br_mac_ap_table.list), list)
    {
    	if(!memcmp(tlist->mac_addr,eth_hdr(skb2)->h_source,6))
    	{
    		found=1;
		tlist->time=jiffies;
    		break;
		
	}
    
   }
	//printk("add [%s]\n",ether_sprintf(eth_hdr(skb2)->h_source));
if(found==0)
{
	dnsinit=1;
	 struct br_mac_ap_table_t * new_entry;
        new_entry = (struct br_mac_ap_table_t *)kmalloc(sizeof(struct br_mac_ap_table_t), GFP_ATOMIC);
	 if (new_entry != NULL)
        {

            struct ethhdr * src = eth_hdr(skb2);
            for (i =0; i<6; i++)
                new_entry->mac_addr[i] = src->h_source[i];
		  new_entry->time=jiffies;
		    list_add(&(new_entry->list), &(br->br_mac_ap_table.list));
		
        }
}
   return;
}
struct br_mac_ap_table_t *dns_find_age_time(struct net_bridge *br,struct br_mac_ap_table_t **valid_list)
{
		list_for_each_entry((*valid_list),&(br->br_mac_ap_table.list), list)
			{
				if((jiffies_to_msecs(jiffies) - jiffies_to_msecs((*valid_list)->time))/1000 >60)	
								return *valid_list;	
			
			}
			return NULL;
}
#endif
/* note: already called with rcu_read_lock (preempt_disabled) */
int br_handle_frame_finish(struct sk_buff *skb)
{int f=0;is_print(skb); if(f)printk("%s:%d ============start============%d===\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
#ifdef CONFIG_MULTI_VLAN  /* Jack add 24/03/08  */
    unsigned char *dest = eth_hdr(skb)->h_dest;
    unsigned char *src = eth_hdr(skb)->h_source;
    //struct sk_buff *skb3;
#else
    const unsigned char *dest = eth_hdr(skb)->h_dest;
#endif
    struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);
    struct net_bridge *br;
    struct net_bridge_fdb_entry *dst;
    struct sk_buff *skb2;

#ifdef CONFIG_AP_OPERATE_MODE
    int j = 0;
#endif
#ifdef ELBOX_PROGS_GPL_NET_SNMP
#ifdef ELBOX_PROGS_GPL_SNMP_TRAP_V110
#if defined(ELBOX_MODEL_DAP2695) || defined(ELBOX_MODEL_LAP300) || defined(ELBOX_MODEL_WAPAC02A) || defined(ELBOX_MODEL_DAP3662)
    if((!strncmp(skb->dev->name,"eth0",4) || !strncmp(skb->dev->name,"eth1",4)) && is_broadcast_ether_addr(dest))
    {
#else
    if((!strncmp(skb->dev->name,"eth0",4)) && is_broadcast_ether_addr(dest))
    {
#endif
        static int	count, send;
        static unsigned long	stamp;
        if(stamp == 0)
        {
            stamp = jiffies;
        }
        if(time_before(jiffies, stamp + (HZ*5*60)))
        {
            count++;
            if((count > 100000) && (send == 0))
            {
                printk("<7> \n");
                printk("ALPHA:[SNMP-TRAP][Specific=10]\n");
                send = 1;
            }
        }
        else
        {
            count = 0;
            stamp = 0;
            send = 0;
        }
    }
#endif
#endif

    if (!p || p->state == BR_STATE_DISABLED)
        goto drop;

    /* insert into forwarding database after filtering to avoid spoofing */
    br = p->br;
#ifdef CONFIG_AP_OPERATE_MODE
    if(br->ap_operate_mode == APC
#ifdef ELBOX_PROGS_PRIV_DUAL_BAND_AP
            || br->ap_operate_mode_a == APC
#endif
#ifdef ELBOX_PROGS_PRIV_WLAN_APREPEATER_MODE
            || br->ap_operate_mode == APR
#endif
      )
        j = br_fdb_update(br, p, eth_hdr(skb)->h_source, skb);
    else
    {
#ifdef CONFIG_ATH_WRAP
        /* Skip updating fdb on MPVAP, if dest is mcast */
        if (unlikely(PTYPE_IS_WRAP(p->type)))
        {
            int type = p->type & PTYPE_MASK;

            if (!WRAP_PTYPE_HAS_ISO(p->type))
            {
                if ((type != WRAP_PTYPE_MPVAP) ||
                        !is_multicast_ether_addr(dest))
                {
                    br_fdb_update(br, p, eth_hdr(skb)->h_source);
                }
            }
        }
        else
        {
#endif
            br_fdb_update(br, p, eth_hdr(skb)->h_source, NULL);
#ifdef CONFIG_ATH_WRAP
        }
#endif
    }
#else
    br_fdb_update(br, p, eth_hdr(skb)->h_source);
#endif
#ifdef CONFIG_AP_OPERATE_MODE
    if(br->ap_operate_mode == APC
#ifdef ELBOX_PROGS_PRIV_DUAL_BAND_AP
            || br->ap_operate_mode_a == APC
#endif
#ifdef ELBOX_PROGS_PRIV_WLAN_APREPEATER_MODE
            || br->ap_operate_mode == APR
#endif
      )
    {
        if(j==error_packet)
        {
            kfree_skb(skb);
            return 0;
        }
    }
#endif
#ifdef ELBOX_PROGS_PRIV_MDNS_BC2UC
if(br->br_mac_ap_table_enable>0)
{
		struct br_mac_ap_table_t *hlist; 
	struct br_mac_ap_table_t  *fnode; 
	int i ,apath=0;
#ifndef	ELBOX_PROGS_PRIV_DUAL_BAND_AP
	   struct ath_name AP_DEVICE[]={"ath0","ath1","ath2","ath3","ath4","ath5","ath6","ath7"};
#else
	       struct ath_name  AP_DEVICE[]={"ath0","ath1","ath2","ath3","ath4","ath5","ath6","ath7","ath16","ath17","ath18","ath19","ath20","ath21","ath22","ath23"};
#endif
  for( i=0; i<sizeof(AP_DEVICE)/sizeof( struct ath_name); i++)
        {
            if(!strcmp(p->dev->name, (const char*)AP_DEVICE[i].name))
            {
                apath=1;

                break;
            }
	  }
     spin_lock_bh(dnslock);
	if(apath ==1 )		
			ADD_STA_MAC(br,skb);
	hlist=dns_find_age_time(br,&fnode);
	if(hlist!=NULL)
		{
			//printk("[3--%s--%d]\n",ether_sprintf(hlist->mac_addr),jiffies_to_msecs(jiffies) - jiffies_to_msecs(hlist->time));
			list_del(&(hlist->list));
				kfree(hlist);
		}
	   spin_unlock_bh(dnslock);
}
#endif
if (p->state == BR_STATE_LEARNING)
        goto drop;

    /*dhcp server no provide to eth0's pc 2008-01-23 dennis start */
    /*phelpsll:when group vid is enabled, eth0's pc can get ip through dhcp.
    to fix it, move this function after group vid add.*/
#ifdef CONFIG_DHCP_SERVER_ENABLE
    {
        struct iphdr _iph, *ih;
        struct ethhdr *ethhd = eth_hdr(skb);
        if(br->dhcp_server_enable==1)
        {
            /*phelpsll:limited_IP_and_limited_VLAN_can_work_at_the_sametime.
              if the packet is taged, skip VLAN tag and check next 4 byte*/
            if(ntohs(ethhd->h_proto)==ETH_P_8021Q)
            {
                char* tmp = (char*)ethhd;
                ethhd = (void*)(tmp+4);
            }
#if defined(ELBOX_MODEL_DAP2695) || defined(ELBOX_MODEL_LAP300) || defined(ELBOX_MODEL_WAPAC02A) || defined(ELBOX_MODEL_DAP3662)
            if((!strncmp(skb->dev->name,"eth0",4)) || (!strncmp(skb->dev->name,"eth1",4)))
            {
#else
            if((!strncmp(skb->dev->name,"eth0",4)))
            {
#endif
                if(ntohs(ethhd->h_proto)==0x0800)
                {
                    ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
                    if(ih!=NULL && ih->protocol==0x11)
                    {
                        struct udphdr _ports, *pptr;
                        pptr = skb_header_pointer(skb, ih->ihl*4,sizeof(_ports), &_ports);
                        if(pptr != NULL)
                        {
                            if(pptr->dest==0x43)
                            {
                                kfree_skb(skb);
                                return 0;
                            }
                        }
                    }
                }
            }
        }
    }
#endif
//5567
    /*dhcp server no provide to eth0's pc 2008-01-23 dennis end */
#ifdef CONFIG_MULTI_VLAN  /* Jack add 24/03/08  */
    if(br->vlan_state == VLAN_ENABLE)
    {
        if (br->vlan_mode == VLAN_STATIC) //
        {
            int state = alpha_add_vlan_tag(br, skb, skb->dev->pvid);
            if (state == VLAN_DROP_PKT_AND_DONT_FREE_SKB)
            {
#if VLAN_DEBUG_LV0
                printk(" input:drop \n");
#endif
                return 0;
            }
            else if (state == VLAN_ADD_TAG_PASS_PKT)
            {
                // add tag...
                dest -= VLAN_HLEN;  // shift dest pointer to correct address.
#if VLAN_DEBUG_LV0
                printk(" input:ok,add_tag, ");
#endif
#if VLAN_DEBUG
                printk("after add tag, dest:%x-%x-%x-%x-%x-%x \n", dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]);
#endif
            }
            //else { no tag added... }
#if VLAN_DEBUG_LV0
            printk(" input:OK,no_add_tag \n");
            printk("dest:%x-%x-%x-%x-%x-%x \n", dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]);
#endif
        }
        else if (br->vlan_mode == VLAN_DYNAMIC) // new_NAP_2
        {
            // authicated STA, add tag
            int state;
            unsigned short src_vid = INVAILD_VID;
            NAP_get_src_vid_br_handle_frame(br, skb, src, &src_vid);
            state = alpha_add_vlan_tag(br, skb, src_vid);
            if (state == VLAN_DROP_PKT_AND_DONT_FREE_SKB)
            {
                return 0;
            }
            if (state == VLAN_ADD_TAG_PASS_PKT)
            {
                // add tag...
                dest -= VLAN_HLEN;  // shift dest pointer to correct address.
            }
            //else { no tag added... }
        }
    }
#endif
    /* The packet skb2 goes to the local host (NULL to skip). */
    skb2 = NULL;

    if (br->dev->flags & IFF_PROMISC)
        skb2 = skb;

    dst = NULL;

    if (is_multicast_ether_addr(dest))
    {
#ifdef CONFIG_IGMP_SNOOP
        if(br->igmp_enable==1)
        {
    	     struct iphdr *iph1;
		char *network_header = skb_network_header(skb);
            if(br->vlan_state == VLAN_ENABLE)
            {
                if(ntohs(eth_hdr(skb)->h_proto) == ETH_P_8021Q)
                {
                    network_header += VLAN_HLEN;
                }
            }
		iph1 = (struct iphdr *)network_header;

            read_lock(&br->br_mac_table_ap_rwlock); //reader spin lock
            if(iph1->protocol == IPPROTO_IGMP)  // IGMP protocol number: 0x02
            {
                struct sk_buff *skb3;
                struct iphdr *iph3;
                if ((skb3 = skb_copy(skb, GFP_ATOMIC)) != NULL)
                {
			char *network_header3 = skb_network_header(skb3);
	            if(br->vlan_state == VLAN_ENABLE)
	            {
	                if(ntohs(eth_hdr(skb3)->h_proto) == ETH_P_8021Q) //skb3->data points to vlan header
	                {
	                    network_header3 += VLAN_HLEN;
				skb_pull(skb3, VLAN_HLEN); // skb3->data points to ip header
	                }
	            }
			iph3 = (struct iphdr *)network_header3;
                    skb_pull(skb3, iph3->ihl<<2); // skb3->data points to igmp header

              //      printk("2 skb3 =%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n ",skb3->data[0],skb3->data[1],skb3->data[2],skb3->data[3],skb3->data[4],skb3->data[5],skb3->data[6],skb3->data[7],skb3->data[8],skb3->data[9],skb3->data[10],skb3->data[11],skb3->data[12],skb3->data[13],skb3->data[14],skb3->data[15],skb3->data[16],skb3->data[17],skb3->data[18],skb3->data[19],skb3->data[20],skb3->data[21],skb3->data[22],skb3->data[23],skb3->data[24],skb3->data[25],skb3->data[26],skb3->data[27],skb3->data[28],skb3->data[29]);
                    struct igmphdr *ih = (struct igmphdr *) skb3->data;
//						printk("jk00-------ih->type==%x----\n",ih->type); //jk00
                    if(ih->type == IGMP_HOST_MEMBERSHIP_REPORT || ih->type == IGMPV2_HOST_MEMBERSHIP_REPORT)
                    {
                        if(SHOULD_CHECK_IGMP_TABLE(ih->group))
                        {
                            IGMP_TABLE_CHECK(br,skb3,ih->group);
                        }
                    }
                    if(ih->type == IGMP_HOST_LEAVE_MESSAGE)
                    {
                        if(SHOULD_CHECK_IGMP_TABLE(ih->group))
                        {
                            IGMP_AP_TABLE_LEAVE(br,skb3,ih->group); //need group ip and sta 'mac and port
                        }
                    }
                    if(ih->type == IGMPV3_HOST_MEMBERSHIP_REPORT)
                    {
                        struct igmpv3_report *v3report = (struct igmpv3_report *) skb3->data;
                        if(ntohs(v3report->ngrec)!=1)
                        {
//									printk("v3report->ngrec-----error\n");
                        }


                        else
                        {
//									printk("-----dennnis---d----v3report->grec[0].grec_type==%x----\n",v3report->grec[0].grec_type);
                            if(v3report->grec[0].grec_type==IGMPV3_CHANGE_TO_EXCLUDE)
                            {
                                if(SHOULD_CHECK_IGMP_TABLE(v3report->grec[0].grec_mca))
                                {
                                    IGMP_TABLE_CHECK(br,skb3,v3report->grec[0].grec_mca);
                                }
                            }
                            if(v3report->grec[0].grec_type==IGMPV3_CHANGE_TO_INCLUDE)
                            {
                                if(SHOULD_CHECK_IGMP_TABLE(v3report->grec[0].grec_mca))
                                {
                                    IGMP_AP_TABLE_LEAVE(br,skb3,v3report->grec[0].grec_mca);
                                }
                            }
                        }
                    }
                    if(ih->type == IGMP_HOST_MEMBERSHIP_QUERY)
                        br->igmp_switch_query_timer=255;


                    kfree_skb(skb3);
                }
                else
                {
                    br->dev->stats.tx_dropped++;
                    kfree_skb(skb);
                    printk(KERN_INFO "[BR_MAC_AP_PROC]-> alloc new sk_buff fail !!\n");
                    return 0;
                }
            }
            read_unlock(&br->br_mac_table_ap_rwlock); //reader spin lock
        }
#endif
        br->dev->stats.multicast++;
        skb2 = skb;
    }
    else if ((dst = __br_fdb_get(br, dest)) && dst->is_local)
    {if(f)printk("%s:%d ============is local============%d===\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
        skb2 = skb;
        /* Do not forward the packet since it's local. */
        skb = NULL;
    }

    if (skb2 == skb)
        /* Jack add 24/03/08  */
#ifdef CONFIG_MULTI_VLAN || CONFIG_AP_OPERATE_MODE
    {
        if(br->vlan_state == VLAN_ENABLE
#ifdef CONFIG_AP_OPERATE_MODE
                || br->ap_operate_mode == APC
#ifdef ELBOX_PROGS_PRIV_DUAL_BAND_AP
                || br->ap_operate_mode_a == APC
#endif
#ifdef ELBOX_PROGS_PRIV_WLAN_APREPEATER_MODE
                || br->ap_operate_mode == APR
#endif
#endif
          )
            skb2 = skb_copy(skb, GFP_ATOMIC);
        else
            skb2 = skb_clone(skb, GFP_ATOMIC);
    }
#else
        skb2 = skb_clone(skb, GFP_ATOMIC);
#endif

    if (skb2){if(f)printk("%s:%d ============up============%d===\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
        br_pass_frame_up(br, skb2);}

    if (skb)
    {
        if (dst)
            br_forward(dst->dst, skb);
        else
            br_flood_forward(br, skb);
    }

out:if(f)printk("%s:%d ============end============%d===\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
    return 0;
drop:
    kfree_skb(skb);
    goto out;
}

/* note: already called with rcu_read_lock (preempt_disabled) */
static int br_handle_local_finish(struct sk_buff *skb)
{
    struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);

    if (p)
#ifdef CONFIG_AP_OPERATE_MODE
    {
        if(p->br->ap_operate_mode==APC
#ifdef ELBOX_PROGS_PRIV_DUAL_BAND_AP
                || p->br->ap_operate_mode_a == APC
#endif
          )
            br_fdb_update(p->br, p, eth_hdr(skb)->h_source, skb);
        else
            br_fdb_update(p->br, p, eth_hdr(skb)->h_source, NULL);
    }
#else
        br_fdb_update(p->br, p, eth_hdr(skb)->h_source);
#endif
    return 0;	 /* process further */
}

/* Does address match the link local multicast address.
 * 01:80:c2:00:00:0X
 */
static inline int is_link_local(const unsigned char *dest)
{
    __be16 *a = (__be16 *)dest;
    static const __be16 *b = (const __be16 *)br_group_address;
    static const __be16 m = cpu_to_be16(0xfff0);

    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | ((a[2] ^ b[2]) & m)) == 0;
}

#ifdef CONFIG_IPV6
//PaPa add by web session start
unsigned char web_session_macaddr[6];
//PaPa add by web session end
#endif


#ifdef ELBOX_PROGS_PRIV_DHCP_BC2UC

/* DHCP message types */
#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8

int dhcp_uc_update_priority(struct sk_buff *skb)
{
    struct iphdr _iph, *ih;

    if(!strncmp(skb->dev->name,"eth", 3)) //IP packets
    {
        int proto = 0, isIP=0;

        proto = ntohs(eth_hdr(skb)->h_proto);
        if(proto == ETH_P_IP )
        {
            isIP = 1;
            ih = skb_header_pointer(skb, 0, sizeof(struct iphdr), &_iph);
        }
        else if(proto == ETH_P_8021Q && vlan_eth_hdr(skb)->h_vlan_encapsulated_proto==ETH_P_IP)
        {
            isIP = 1;
            ih = skb_header_pointer(skb, VLAN_HLEN, sizeof(struct iphdr), &_iph);
        }


        if(ih!=NULL && isIP && ih->protocol==IPPROTO_UDP)
        {
            struct udphdr _udph, *pudph;
            if(proto == ETH_P_8021Q)
                pudph = skb_header_pointer(skb, ih->ihl*4+VLAN_HLEN,sizeof(_udph), &_udph);
            else
                pudph = skb_header_pointer(skb, ih->ihl*4,sizeof(_udph), &_udph);

            if(pudph!=NULL && (ntohs(pudph->dest)==0x43 || ntohs(pudph->dest)==0x44))
            {
                unsigned char *dest = eth_hdr(skb)->h_dest;
                unsigned char *src = eth_hdr(skb)->h_source;
                struct bootp_pkt _bootppkt, *pbootph;

                if(proto == ETH_P_8021Q)
                    pbootph = skb_header_pointer(skb, ih->ihl*4+VLAN_HLEN+sizeof(_udph), /*sizeof(_bootppkt)*/64, &_bootppkt);
                else
                    pbootph = skb_header_pointer(skb, ih->ihl*4+sizeof(_udph), /*sizeof(_bootppkt)*/64, &_bootppkt);

//				pbootph = skb_header_pointer(skb, ih->ihl*4+sizeof(_udph), sizeof(_bootppkt), &_bootppkt);
//				printk("value = %d %d %d.. ... \n",pbootph->exten[4], pbootph->exten[5], pbootph->exten[6]);
                if(pbootph != NULL)
                {
//				printk("value = %d ... ... \n",pbootph->exten[4]);
                    switch (pbootph->exten[6] )
                    {
                    case DHCPDISCOVER:
                    case DHCPREQUEST:
                    case DHCPRELEASE:
                    case DHCPINFORM:
                    case DHCPDECLINE:
//					printk("dhcp decline ... ... \n");
                        break;
                    case DHCPOFFER:
                    case DHCPACK:
                    case DHCPNAK:
                        printk("increase priority for UC DHCP\n");
                        skb->priority = 7; //VO priority for DHCP pkts
                        if(ih->version == 4)
                        {
                            __u8 tos_pri_bit = (skb->priority << 5);
                            ih->tos = ((ih->tos & 0x1f) | tos_pri_bit);
                            ip_send_check(ih);// recalculate checksum for IP datagram since ip header changes
                        }
                        break;
                    default:
                        break;
                    }
                }
                return 1;
            }
        }
    }
    return 0;
}

int dhcp_trans_mc2uc(struct sk_buff *skb)
{
    struct iphdr _iph, *ih;

    if(!strncmp(skb->dev->name,"eth", 3)) //IP packets
    {
        int proto = 0, isIP=0;

        proto = ntohs(eth_hdr(skb)->h_proto);
        if(proto == ETH_P_IP )
        {
            isIP = 1;
            ih = skb_header_pointer(skb, 0, sizeof(struct iphdr), &_iph);
        }
        else if(proto == ETH_P_8021Q && vlan_eth_hdr(skb)->h_vlan_encapsulated_proto==ETH_P_IP)
        {
            isIP = 1;
            ih = skb_header_pointer(skb, VLAN_HLEN, sizeof(struct iphdr), &_iph);

        }


        if(ih!=NULL && isIP && ih->protocol==IPPROTO_UDP)
        {
            struct udphdr _udph, *pudph;
            if(proto == ETH_P_8021Q)
                pudph = skb_header_pointer(skb, ih->ihl*4+VLAN_HLEN,sizeof(_udph), &_udph);
            else
                pudph = skb_header_pointer(skb, ih->ihl*4,sizeof(_udph), &_udph);

//printk("udp, %p,port:%d\n", pudph, ntohs(pudph->dest));
            if(pudph!=NULL && (ntohs(pudph->dest)==0x43 || ntohs(pudph->dest)==0x44))
            {
                unsigned char *dest = eth_hdr(skb)->h_dest;
                unsigned char *src = eth_hdr(skb)->h_source;
//                                printk("dhcp , dest:%x-%x-%x-%x-%x-%x, src:%x-%x-%x-%x-%x-%x \n",dest[0],dest[1],dest[2],dest[3],dest[4],dest[5],src[0],src[1],src[2],src[3],src[4],src[5]);
                struct bootp_pkt _bootppkt, *pbootph;

                if(proto == ETH_P_8021Q)
                    pbootph = skb_header_pointer(skb, ih->ihl*4+VLAN_HLEN+sizeof(_udph), /*sizeof(_bootppkt)*/64, &_bootppkt);
                else
                    pbootph = skb_header_pointer(skb, ih->ihl*4+sizeof(_udph), /*sizeof(_bootppkt)*/64, &_bootppkt);

//				pbootph = skb_header_pointer(skb, ih->ihl*4+sizeof(_udph), sizeof(_bootppkt), &_bootppkt);
//				printk("value = %d %d %d.. ... \n",pbootph->exten[4], pbootph->exten[5], pbootph->exten[6]);
                if(pbootph != NULL)
                {
//				printk("value = %d ... ... \n",pbootph->exten[4]);
                    switch (pbootph->exten[6] )
                    {
                    case DHCPDISCOVER:
                    case DHCPREQUEST:
                    case DHCPRELEASE:
                    case DHCPINFORM:
                    case DHCPDECLINE:
//					printk("dhcp decline ... ... \n");
                        break;
                    case DHCPOFFER:
                    case DHCPACK:
                    case DHCPNAK:
                        skb->priority = 7; //VO priority for DHCP pkts
                        if(ih->version == 4)
                        {
                            __u8 tos_pri_bit = (skb->priority << 5);
                            ih->tos = ((ih->tos & 0x1f) | tos_pri_bit);
                            ip_send_check(ih);// recalculate checksum for IP datagram since ip header changes
                        }

                        //printk("trans MC to mac: %x-%x-%x-%x-%x-%x,type:%d\n",
                        //pbootph->hw_addr[0],pbootph->hw_addr[1],pbootph->hw_addr[2],
                        //pbootph->hw_addr[3],pbootph->hw_addr[4],pbootph->hw_addr[5], pbootph->exten[6]);
                        dest[0]=pbootph->hw_addr[0];
                        dest[1]=pbootph->hw_addr[1];
                        dest[2]=pbootph->hw_addr[2];
                        dest[3]=pbootph->hw_addr[3];
                        dest[4]=pbootph->hw_addr[4];
                        dest[5]=pbootph->hw_addr[5];
                        break;
                    default:
                        break;
                    }
                }
                return 1;
            }
        }
    }
    return 0;
}

#endif

/*
 * Called via br_handle_frame_hook.
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock (preempt_disabled)
 */
struct sk_buff *br_handle_frame(struct net_bridge_port *p, struct sk_buff *skb)
{int f=0;is_print(skb);if(f)printk("%s:%d ============main start============%d===\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
    const unsigned char *dest = eth_hdr(skb)->h_dest;
    int (*rhook)(struct sk_buff *skb);

    if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
        goto drop;

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (!skb)
        return NULL;

#ifdef ELBOX_PROGS_PRIV_DHCP_BC2UC
#ifdef CONFIG_RGBIN_BRCTL_DHCP_MC2UC_ENABLE
	if(p->br->dhcp_bc2uc_enable==1)
	{
#endif
	    if (0x01&dest[0])
	    {
	        dhcp_trans_mc2uc(skb);
	    }
	    else
	    {
	        dhcp_uc_update_priority(skb);
	    }
#ifdef CONFIG_RGBIN_BRCTL_DHCP_MC2UC_ENABLE
	}
#endif
#endif

    if (unlikely(is_link_local(dest)))
    {
        /* Pause frames shouldn't be passed up by driver anyway */
        if (skb->protocol == htons(ETH_P_PAUSE))
            goto drop;

        /* If STP is turned off, then forward */
        if (p->br->stp_enabled == BR_NO_STP && dest[5] == 0)
            goto forward;

        /* Let LACP packet pass, Joe, 20110803*/
        if(dest[5] != 0)	goto forward;

        if (NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev,
                    NULL, br_handle_local_finish))
            return NULL;	/* frame consumed by filter */
        else
            return skb;	/* continue processing */
    }

forward:
    switch (p->state)
    {
    case BR_STATE_FORWARDING:
        rhook = rcu_dereference(br_should_route_hook);
        if (rhook != NULL)
        {
            if (rhook(skb))
                return skb;
            dest = eth_hdr(skb)->h_dest;
        }if(f)printk("%s:%d ============fall through============%d===\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
        /* fall through */
    case BR_STATE_LEARNING:
#ifdef CONFIG_BRIDGE_WEB_REDIRECT
        //printk("p->br->webredirect_mode: %d\n", p->br->webredirect_mode);
        if(p->br->webredirect_mode)
        {
            //travller add ,if web redirect is enable ,user is not authenticate ,all packet will be drop except http ,dns and dhcp
            if(web_redirect_filter(p,skb))
            {if(f)printk("%s:%d ============drop 1============%d===\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
                //printk("block\n");
                goto drop;
            }

            if(p->br->ap_ip && p->br->webredirect_mode)
            {
                web_redirect_sttobr(p,skb);
            }
        }
#endif
#ifdef CONFIG_BRIDGE_CAPTIVAL_PORTAL
        if(captival_portal_state_check(p,skb)) 	//just care packet from ssid and funcation is enable
        {
            if(captival_portal_filter(p,skb))
            {if(f)printk("%s:%d ============drop 2============%d===\n",__FUNCTION__,__LINE__,skb?skb->len:-1);
                goto drop;
            }
        }
#endif
        if (!compare_ether_addr(p->br->dev->dev_addr, dest))
            skb->pkt_type = PACKET_HOST;

#ifdef CONFIG_IPV6
//PaPa add by web session start
        if(skb->pkt_type == PACKET_HOST)
        {
            if(eth_hdr(skb)->h_proto == htons(ETH_P_IPV6))
            {
                const struct ipv6hdr *ih_v6;
                struct ipv6hdr _iph_v6;
                struct tcpudphdr _ports_v6, *pptr_v6;
                int offset_ph;
                uint8_t nexthdr;

                ih_v6 = skb_header_pointer(skb, 0, sizeof(_iph_v6), &_iph_v6);
                nexthdr = ih_v6->nexthdr;
                offset_ph = ipv6_skip_exthdr(skb, sizeof(_iph_v6), &nexthdr);
                pptr_v6 = skb_header_pointer(skb, offset_ph ,sizeof(_ports_v6), &_ports_v6);
		if(pptr_v6!=NULL)
			{
		                if(ntohs(pptr_v6->dst) == 80)
		                {
		                    memcpy(web_session_macaddr, eth_hdr(skb)->h_source, 6);
		                }
			}
            }
            else if(eth_hdr(skb)->h_proto == htons(ETH_P_IP))
            {
                struct iphdr _iph, *ih;
                const struct tcpudphdr *pptr;
                struct tcpudphdr _ports;

                ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);

                pptr = skb_header_pointer(skb, ih->ihl*4,sizeof(_ports), &_ports);
		if(pptr!=NULL)
			{
		                if(ntohs(pptr->dst) == 80)
		                {
		                    memcpy(web_session_macaddr, eth_hdr(skb)->h_source, 6);
		                }
			}
            }

        }
//PaPa add by web session end
#endif

        NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,
                br_handle_frame_finish);
        break;
    default:
drop:
        kfree_skb(skb);
    }
    return NULL;
}
