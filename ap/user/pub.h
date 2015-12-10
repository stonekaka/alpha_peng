/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     pub.h
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-14 15:52
***************************************************************************/

#ifndef __PUB_H__
#define __PUB_H__

#include <linux/if.h>
#include <linux/if_ether.h>

#define MAX_WLAN_COUNT  6

#define MAX_DOMAIN_LEN 128

/*msg to kernel*/
struct msg_to_ker{
	int type;
	int len;
	char value[0];	
};

enum _msg_to_ker_type{
	M2K_APONLINE,  //ap online notify
	M2K_STACTL, //sta control
	M2K_STA_BLKWHT_SET,  //sta black/white list
	M2K_STA_BLKWHT_CLEAR,
	M2K_DN_BLKWHT_SET, //domain black/white list
	M2K_DN_BLKWHT_CLEAR,
	M2K_PORTAL_CONFIG
};

struct sta_ctl{
	unsigned char mac[ETH_ALEN];
	unsigned int ipaddr;
	char ifname[IFNAMSIZ];
#define STA_ALLOW   1
#define STA_DENY    2
#define STA_KICKOFF 3
#define STA_TIMEOUT 4
#define STA_INIT    5
#define STA_UPDATE_INIT    6
	int action;
};
/**/

struct u_sta_blk_wht{
	unsigned char mac[ETH_ALEN]; 		
	/*ssid map
	 *[0][1][2][3][4][5] --black
	 *[0][1][2][3][4][5] --white
	 * */
#define SSMA_BLK 	0
#define SSMA_WHT	1
	int map[2][MAX_WLAN_COUNT];
};

struct u_dn_blk_wht{
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

struct wlan_arg {
	//char ifname[IFNAMSIZ];
	char portal_url[MAX_DOMAIN_LEN];
	unsigned int portal_ipaddr[8];	
};

#endif

