/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     handle_recv.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-12 10:47
***************************************************************************/

#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <time.h>
#include "base64.h"
#include "cJSON.h"
#include "list.h"
#include "main.h"
#include "pub.h"

extern int g_state;
extern int g_connection_flag;
extern int g_heartbeat_flag;
extern struct ssid_dev g_ssid_dev[];
extern FILE *g_log_fp;
extern char g_ap_label_mac[];

char g_ap_last_config[8192];

int enqueue_msg(char *msg)
{
	if(!msg){
		return -1;
	}
		
	msgdata *node = make_node(msg, strlen(msg));
	pthread_mutex_lock(&mutex);
	list_add_end(&list_head_send, node);
	LOG_INFO("produce: key=%d. total len=%d\n", node->key, list_length(list_head_send));
	pthread_mutex_unlock(&mutex);
	
	return 0;
}

int enqueue_r_msg(char *msg)
{
	if(!msg){
		return -1;
	}

	msgdata *node = make_node(msg, strlen(msg));
	pthread_mutex_lock(&mutex_r);
	list_add_end(&list_head_recv, node);
	LOG_INFO("produce_r: key=%d. total len=%d\n", node->key, list_length(list_head_recv));
	pthread_mutex_unlock(&mutex_r);
	
	return 0;
}

int get_run_state(int *state)
{
	if( g_state >= AP_JOIN_OK && g_state <= AP_RUNNING){
		*state = 1;	
	}else{
		*state = 0;
	}

	return 0;
}

int get_client_list(char *client_list, int len)
{
	/*{"client_mac":"","client_ip":"","auth_state":"","contain_ssid":""},{},{}*/
	char *cmd = "cat /proc/pengwifi/stas | grep -v MAC | awk '{print $2,$3,$4,$5}'";
	char buf[256] = {0};
	FILE *fp = NULL;
	int n = 0, i = 0;
	int wlen = 0;
	
	fp = popen(cmd, "r");
	if(!fp){
		LOG_INFO("%s:Error: exec: %s \n", __FUNCTION__, cmd);
		return -1;
	}

	while(NULL != fgets(buf, sizeof(buf) - 1, fp)){
		char mac[32] = {0}, ip[32] = {0}, state[8] = {0}, ifname[32] = {0}, ssid[64] = {0};
		char tmp[512] = {0};

		clear_crlf(buf);
		n = sscanf(buf, "%s %s %s %s", mac, ip, state, ifname);
		if(n != 4){
			LOG_INFO("%s: buf error: %s\n", __FUNCTION__, buf);
		}

		for(i = 0; i < MAX_WLAN_COUNT; i++){
			//printf("%s: %d: compare: %s %s\n", __FUNCTION__, i, g_ssid_dev[i].dev, dev);
			if(0 == strcmp(g_ssid_dev[i].dev, ifname)){
				snprintf(ssid, len, "%s", g_ssid_dev[i].ssid);
				//printf("%s: dev=%s, ssid=%s\n", __FUNCTION__, dev, ssid);
				break;
			}
		}
		if(!ssid[0]){
			snprintf(ssid, len, "%s", ifname);
		}
		snprintf(tmp, sizeof(tmp) - 1, "{\"client_mac\":\"%s\",\"client_ip\":\"%s\",\"auth_state\":\"%s\","
				"\"contain_ssid\":\"%s\"},", mac, ip, state, ssid);
		wlen += strlen(tmp);		
		if(wlen < len){
			strcat(client_list, tmp);
		}else{
			LOG_INFO("%s: wlen=%d bigger than len=%d, write full\n", __FUNCTION__, wlen, len);
		}
	}

	wlen += strlen("{}");
	if(wlen < len){
		strcat(client_list, "{}");
	}else{
		LOG_INFO("%s_: wlen=%d bigger than len=%d, write full\n", __FUNCTION__, wlen, len);
	}

	pclose(fp);
	
	return 0;
}

int send_apinfo_to_ac(char *wsid, char *from)
{
	char fmt[] = "{\"type\":\"ap_resp\",\"wsid\":\"%s\",\"from\":\"%s\",\"error\":0,\"data\":"
		"{\"ap_mac\":\"%s\",\"ap_id\":\"%s\",\"run_state\":\"%d\",\"up_time\":\"%d\",\"wan_ip\":\"%s\","
		"\"sys_cpu_busy\":\"%d\",\"sys_mem_free\":\"%d\",\"sys_mem_use_rate\":\"%d\",\"sys_load\":\"%s\","
		"\"soft_version\":\"%s\",\"client_list\":[%s]}}";
	char msg[1024] = {0};
	char wan_ip[32] = {0}, sys_load[8] = {0}, soft_ver[32] = {0};
	char client_list[4096] = {0};
	int run_state = 0, uptime = 0, sys_cpu_usage = 0, sys_mem_free = 0, sys_mem_use_rate = 0;
	
	if(!wsid || !from){
		LOG_INFO("%s: arg error.\n", __FUNCTION__);
	}

	get_wan_ip(wan_ip, sizeof(wan_ip));
	get_sys_load(sys_load, sizeof(sys_load));
	get_soft_version(soft_ver, sizeof(soft_ver));
	
	get_run_state(&run_state);
	get_uptime(&uptime);
	get_cpu_usage(&sys_cpu_usage);
	get_mem_free(&sys_mem_free);
	get_mem_use_rate(&sys_mem_use_rate);

	get_client_list(client_list, sizeof(client_list));

	snprintf(msg, sizeof(msg), fmt, wsid, from, g_ap_label_mac, g_ap_label_mac, run_state, uptime, wan_ip, sys_cpu_usage,
		sys_mem_free*1024, sys_mem_use_rate, sys_load, soft_ver, client_list);

	enqueue_msg(msg);			

	return 0;
}

int resolve_url(char *url, unsigned int addrs[], int addr_cnt)
{
	int ret = 0;
	int i = 0;
	struct sockaddr *dst = NULL;
	struct addrinfo *result = NULL;
	struct addrinfo *ptr = NULL;
	struct addrinfo hints;
	char hostname[128] = {0};
	
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;	
		
	if(!url){
		LOG_INFO("%s: arg error.\n", __FUNCTION__);
	}

	if(NULL == strstr(url, "http")){
		sscanf(url, "%[0-9a-zA-Z.-]127s", hostname);
	}else{
		sscanf(url, "http://%[0-9a-zA-Z.-]127s", hostname);
	}

	ret = getaddrinfo(hostname, 0, &hints, &result);	
	if(ret == 0){
		LOG_INFO("resolve domain name success %s.  hostname=%s.\n", url, hostname);
		for(ptr = result, i = 0; ptr != NULL && i < addr_cnt; ptr = ptr->ai_next, i++){
			switch(ptr->ai_family){
				case AF_UNSPEC:
					LOG_INFO("Unspecified\n");
					break;
				case AF_INET:
					LOG_INFO("AF_INET (IPv4)\n");	
					dst = ptr->ai_addr;
					//dst->sa_family = AF_INET;
					LOG_INFO("\tIPv4 address %s\n", inet_ntoa(((struct sockaddr_in *)dst)->sin_addr));
					addrs[i] = ((struct sockaddr_in *)dst)->sin_addr.s_addr;
					break;
				default:
					break;
			}	
		}
	}else{
		LOG_INFO("resolve domain name failed:%s .  hostname=%s.\n", url, hostname);
	}
	
	LOG_INFO("resolve end\n");
	
	return 0;
}

int parse_bw_array(cJSON *bwlist, struct ssid_dev *node, char *type, char *bwflag)
{
	int l = 0, i = 0;
	unsigned char mac[ETH_ALEN];
	cJSON *json_item, *json_elem;
	int max = 0;

	CHECK_JSON(bwlist, cJSON_Array);

	if(!type || !bwflag || !node){
		LOG_INFO("%s: arg is null.\n", __FUNCTION__);
		return -1;	
	}

	if(!strcmp(type, "sta")){
		max = sizeof(node->sta_black)/sizeof(node->sta_black[0]);
	}else if(!strcmp(type, "domain")){
		max = sizeof(node->domain_black)/sizeof(node->domain_black[0]);
	}

	l = cJSON_GetArraySize(bwlist);
	for(i = 0; i < l && i < max; i++){
	
		json_item = cJSON_GetArrayItem(bwlist, i);
		CHECK_JSON(json_item, cJSON_Object);
		
		if(!strcmp(type, "sta")){
			json_elem = cJSON_GetObjectItem(json_item, "mac");

			if(!strcmp(bwflag, "black")){
				ascii2mac(json_elem->valuestring, node->sta_black[i]);
			}else if(!strcmp(bwflag, "white")){
				ascii2mac(json_elem->valuestring, node->sta_white[i]);
			}
		}else if(!strcmp(type, "domain")){
			json_elem = cJSON_GetObjectItem(json_item, "domain");

			if(!strcmp(bwflag, "black")){
				snprintf(node->domain_black[i], sizeof(node->domain_black[i]), "%s", json_elem->valuestring);
				resolve_url(json_elem->valuestring, node->domain_black_ipaddr[i], 
					sizeof(node->domain_black_ipaddr[i])/sizeof(node->domain_black_ipaddr[i][0]));
			}else if(!strcmp(bwflag, "white")){
				snprintf(node->domain_white[i], sizeof(node->domain_white[i]), "%s", json_elem->valuestring);
				resolve_url(json_elem->valuestring, node->domain_white_ipaddr[i], 
					sizeof(node->domain_white_ipaddr[i])/sizeof(node->domain_white_ipaddr[i][0]));
			}
		}
	}

	return 0;
}

int set_portal_nl(struct wlan_arg *wlans)
{
	struct msg_to_ker *m = NULL;
	int len = 0;
	int ret = 0;

	LOG_INFO("start set portal ipaddr to kernel...\n");

	if(!wlans){
		LOG_INFO("%s: arg null\n", __FUNCTION__);
		return -1;
	}

	len = sizeof(struct msg_to_ker) + sizeof(struct wlan_arg) * MAX_WLAN_COUNT;
	m = (struct msg_to_ker *)malloc(len);
	if(!m){
		LOG_INFO("%s: malloc failed\n", __FUNCTION__);
		return -1;
	}

	m->type = M2K_PORTAL_CONFIG;
	m->len = sizeof(struct wlan_arg) * MAX_WLAN_COUNT;
	memcpy(m->value, wlans, sizeof(struct wlan_arg) * MAX_WLAN_COUNT);
		
	ret = send_nl_msg(m, len);

	free(m);

	return 0;
}

int set_sta_bw_nl(struct u_sta_blk_wht sta)
{
	struct msg_to_ker *m = NULL;
	int len = 0;
	int ret = 0;

	len = sizeof(struct msg_to_ker) + sizeof(struct u_sta_blk_wht);
	m = (struct msg_to_ker *)malloc(len);
	if(!m){
		LOG_INFO("%s: malloc failed\n", __FUNCTION__);
		return -1;
	}

	m->type = M2K_STA_BLKWHT_SET;
	m->len = sizeof(struct u_sta_blk_wht);
	memcpy(m->value, &sta, sizeof(struct u_sta_blk_wht));
		
	ret = send_nl_msg(m, len);

	free(m);

	return 0;
}

int set_dn_bw_nl(struct u_dn_blk_wht dn)
{
	struct msg_to_ker *m = NULL;
	int len = 0;
	int ret = 0;

	len = sizeof(struct msg_to_ker) + sizeof(struct u_dn_blk_wht);
	m = (struct msg_to_ker *)malloc(len);
	if(!m){
		LOG_INFO("%s: malloc failed\n", __FUNCTION__);
		return -1;
	}

	m->type = M2K_DN_BLKWHT_SET;
	m->len = sizeof(struct u_dn_blk_wht);
	memcpy(m->value, &dn, sizeof(struct u_dn_blk_wht));
		
	ret = send_nl_msg(m, len);

	free(m);

	return 0;
}

int clear_sta_bw_nl(void)
{
	struct msg_to_ker *m = NULL;
	int len = 0;
	int ret = 0;

	len = sizeof(struct msg_to_ker);
	m = (struct msg_to_ker *)malloc(len);
	if(!m){
		LOG_INFO("%s: malloc failed\n", __FUNCTION__);
		return -1;
	}

	m->type = M2K_STA_BLKWHT_CLEAR;
	m->len = 0;
		
	ret = send_nl_msg(m, len);

	free(m);

	return 0;
}

int clear_dn_bw_nl(void)
{
	struct msg_to_ker *m = NULL;
	int len = 0;
	int ret = 0;

	len = sizeof(struct msg_to_ker);
	m = (struct msg_to_ker *)malloc(len);
	if(!m){
		LOG_INFO("%s: malloc failed\n", __FUNCTION__);
		return -1;
	}

	m->type = M2K_DN_BLKWHT_CLEAR;
	m->len = 0;
		
	ret = send_nl_msg(m, len);

	free(m);

	return 0;
}

int exec_blk_wht_list(void)
{
	int i = 0, j = 0, k = 0, m = 0;
	struct u_sta_blk_wht sta[MAX_WLAN_COUNT*MAX_STA_BW_CNT];
	struct u_dn_blk_wht dn[MAX_WLAN_COUNT*MAX_DN_BW_CNT*MAX_DN_IP];
	unsigned char mac_zero[] = {0,0,0,0,0,0};
	
	memset(sta, 0, sizeof(struct u_sta_blk_wht)*MAX_WLAN_COUNT*MAX_STA_BW_CNT);
			
	for(j = 0; j < MAX_WLAN_COUNT; j++) {
		if(0 == g_ssid_dev[j].ssid[0])continue;

		for(k = 0; k < MAX_STA_BW_CNT; k++){
			if(0 != memcmp(g_ssid_dev[j].sta_black[k], mac_zero, ETH_ALEN)){
				memcpy(sta[i].mac, g_ssid_dev[j].sta_black[k], ETH_ALEN);
				sta[i].map[0][j] = 1;printf("ssid[%d].sta_black[%d] add, sta[%d].mac=%02x\n", j, k, i, sta[i].mac[5]);
				i++;
			}
			if(0 != memcmp(g_ssid_dev[j].sta_white[k], mac_zero, ETH_ALEN)){
				memcpy(sta[i].mac, g_ssid_dev[j].sta_white[k], ETH_ALEN);
				sta[i].map[1][j] = 1;
				i++;
			}
		}
	}

	i = 0;
	memset(dn, 0, sizeof(struct u_dn_blk_wht)*MAX_WLAN_COUNT*MAX_DN_BW_CNT*MAX_DN_IP);
			
	for(j = 0; j < MAX_WLAN_COUNT; j++) {
		if(0 == g_ssid_dev[j].ssid[0])continue;

		for(k = 0; k < MAX_DN_BW_CNT; k++){
			for(m = 0; m < MAX_DN_IP; m++) {
				if(0 == g_ssid_dev[j].domain_black_ipaddr[k][m])continue;

				if(0 != g_ssid_dev[j].domain_black_ipaddr[k][m]){
					dn[i].ipaddr = g_ssid_dev[j].domain_black_ipaddr[k][m];		
					memcpy(dn[i].domain, g_ssid_dev[j].domain_black[k], MAX_DOMAIN_LEN);
					dn[i].map[0][j] = 1;
					i++;
				}
				if(0 != g_ssid_dev[j].domain_white_ipaddr[k][m]){
					dn[i].ipaddr = g_ssid_dev[j].domain_white_ipaddr[k][m];		
					memcpy(dn[i].domain, g_ssid_dev[j].domain_white[k], MAX_DOMAIN_LEN);
					dn[i].map[1][j] = 1;
					i++;
				}
			}
		}
	}

	//merge the same mac
	i = 0;
	while(i < MAX_WLAN_COUNT*MAX_STA_BW_CNT){
		if(0 == memcmp(sta[i].mac, mac_zero, ETH_ALEN)){
			i++;
			continue;
		}

		j = i + 1;
		while(j > i && j < MAX_WLAN_COUNT*MAX_STA_BW_CNT){
			if(0 != memcmp(sta[j].mac, mac_zero, ETH_ALEN)&&
				0 == memcmp(sta[i].mac, sta[j].mac, ETH_ALEN)){
				for(k = 0; k < MAX_WLAN_COUNT; k++){
					sta[i].map[0][k] += sta[j].map[0][k];
				}
				for(k = 0; k < MAX_WLAN_COUNT; k++){
					sta[i].map[1][k] += sta[j].map[1][k];	
				}
					
				memset(&sta[j], 0, sizeof(sta[j]));	
			}
			j++;
		}

		i++;
	}
	
	//merge the same ip
	i = 0;
	while(i < MAX_WLAN_COUNT*MAX_DN_BW_CNT*MAX_DN_IP){
		if(0 == dn[i].ipaddr){
			i++;
			continue;
		}

		j = i + 1;
		while(j > i && j < MAX_WLAN_COUNT*MAX_DN_BW_CNT*MAX_DN_IP){
			if(0 != dn[j].ipaddr &&
				dn[i].ipaddr == dn[j].ipaddr){
				for(k = 0; k < MAX_WLAN_COUNT; k++){
					dn[i].map[0][k] += dn[j].map[0][k];	
				}
				for(k = 0; k < MAX_WLAN_COUNT; k++){
					dn[i].map[1][k] += dn[j].map[1][k];	
				}
				
				memset(&dn[j], 0, sizeof(dn[j]));	
			}
			j++;
		}

		i++;
	}
#if 1
	clear_sta_bw_nl();
	i = 0;
	for(i = 0; i < MAX_WLAN_COUNT*MAX_STA_BW_CNT; i++){
		if(0 == memcmp(sta[i].mac, mac_zero, ETH_ALEN)){
			continue;
		}

		LOG_INFO("%d: mac=%02x:%02x:%02x:%02x:%02x:%02x ", i,
			sta[i].mac[0], sta[i].mac[1], sta[i].mac[2], sta[i].mac[3], sta[i].mac[4], sta[i].mac[5]);
		LOG_INFO("map=%d %d %d %d %d %d   %d %d %d %d %d %d\n", 
			sta[i].map[0][0],sta[i].map[0][1],sta[i].map[0][2],sta[i].map[0][3],sta[i].map[0][4],sta[i].map[0][5],
			sta[i].map[1][0],sta[i].map[1][1],sta[i].map[1][2],sta[i].map[1][3],sta[i].map[1][4],sta[i].map[1][5]
			);
		set_sta_bw_nl(sta[i]);
	}

	clear_dn_bw_nl();
	i = 0;
	for(i = 0; i < MAX_WLAN_COUNT*MAX_DN_BW_CNT*MAX_DN_IP; i++){
		if(0 == dn[i].ipaddr)continue;
		struct in_addr in_ip;
		memset(&in_ip, 0, sizeof(in_ip));
		in_ip.s_addr = dn[i].ipaddr;
		LOG_INFO("%d: ip=%-15s ", i, inet_ntoa(in_ip));
		LOG_INFO("map = %d %d %d %d %d %d   %d %d %d %d %d %d\n",
			dn[i].map[0][0],dn[i].map[0][1],dn[i].map[0][2],dn[i].map[0][3],dn[i].map[0][4],dn[i].map[0][5],
			dn[i].map[1][0],dn[i].map[1][1],dn[i].map[1][2],dn[i].map[1][3],dn[i].map[1][4],dn[i].map[1][5]
			);
		set_dn_bw_nl(dn[i]);
	}
#endif

	return 0;
}

void print_ssid_dev(void)
{
	int i = 0;
	struct in_addr in_ip;
	unsigned char mac_zero[] = {0,0,0,0,0,0};
	struct ssid_dev sz;
	
	memset(&sz, 0, sizeof(sz));
	LOG_INFO("\n======wlan table======\n");
	for(i = 0; i < MAX_WLAN_COUNT; i++){
		
		if(!memcmp(&g_ssid_dev[i], &sz, sizeof(g_ssid_dev[i]))){
			continue;
		}

		LOG_INFO("\n\nssid[%d]: %s\n", i, g_ssid_dev[i].ssid);
		LOG_INFO("dev:        %s\n", g_ssid_dev[i].dev);
		LOG_INFO("portal_url: %s\n", g_ssid_dev[i].portal_url);
		
		int n = 0;
		int portal_addr_cnt = sizeof(g_ssid_dev[i].portal_ipaddr)/sizeof(g_ssid_dev[i].portal_ipaddr[0]);
		for(n = 0; n < portal_addr_cnt; n++){
			if(!g_ssid_dev[i].portal_ipaddr[n])continue;
			memset(&in_ip, 0, sizeof(struct in_addr));
			in_ip.s_addr = g_ssid_dev[i].portal_ipaddr[n];
			LOG_INFO("%s  ", inet_ntoa(in_ip));
		}

		int sta_cnt = sizeof(g_ssid_dev[i].sta_black)/sizeof(g_ssid_dev[i].sta_black[0]);
		LOG_INFO("\nsta black list:\n");
		for(n = 0; n < sta_cnt; n++){
			if(0 == memcmp(g_ssid_dev[i].sta_black[n], mac_zero, ETH_ALEN))continue;
			LOG_INFO("%02x:%02x:%02x:%02x:%02x:%02x  ", g_ssid_dev[i].sta_black[n][0],g_ssid_dev[i].sta_black[n][1],
			g_ssid_dev[i].sta_black[n][2],g_ssid_dev[i].sta_black[n][3],
			g_ssid_dev[i].sta_black[n][4],g_ssid_dev[i].sta_black[n][5]);
		}
		LOG_INFO("\nsta white list:\n");
		for(n = 0; n < sta_cnt; n++){
			if(0 == memcmp(g_ssid_dev[i].sta_white[n], mac_zero, ETH_ALEN))continue;
			LOG_INFO("%02x:%02x:%02x:%02x:%02x:%02x  ", g_ssid_dev[i].sta_white[n][0],g_ssid_dev[i].sta_white[n][1],
			g_ssid_dev[i].sta_white[n][2],g_ssid_dev[i].sta_white[n][3],
			g_ssid_dev[i].sta_white[n][4],g_ssid_dev[i].sta_white[n][5]);
		}
		
		int domain_cnt = sizeof(g_ssid_dev[i].domain_black)/sizeof(g_ssid_dev[i].domain_black[0]);
		LOG_INFO("\ndomain black list:\n");
		for(n = 0; n < domain_cnt; n++){
			if(!g_ssid_dev[i].domain_black[n][0])continue;
			LOG_INFO("%s ", g_ssid_dev[i].domain_black[n]);
			int m = 0;
			for(m = 0; m < sizeof(g_ssid_dev[i].domain_black_ipaddr[0])/sizeof(g_ssid_dev[i].domain_black_ipaddr[0][0]); m++){
				if(!g_ssid_dev[i].domain_black_ipaddr[n][m])continue;
				memset(&in_ip, 0, sizeof(struct in_addr));
				in_ip.s_addr = g_ssid_dev[i].domain_black_ipaddr[n][m];
				LOG_INFO("%s ", inet_ntoa(in_ip));	
			}
		}
		LOG_INFO("\ndomain white list:\n");
		for(n = 0; n < domain_cnt; n++){
			if(!g_ssid_dev[i].domain_white[n][0])continue;
			LOG_INFO("%s ", g_ssid_dev[i].domain_white[n]);
			int m = 0;
			for(m = 0; m < sizeof(g_ssid_dev[i].domain_white_ipaddr[0])/sizeof(g_ssid_dev[i].domain_white_ipaddr[0][0]); m++){
				if(!g_ssid_dev[i].domain_white_ipaddr[n][m])continue;
				memset(&in_ip, 0, sizeof(struct in_addr));
				in_ip.s_addr = g_ssid_dev[i].domain_white_ipaddr[n][m];
				LOG_INFO("%s ", inet_ntoa(in_ip));
			}
		}
	}
	LOG_INFO("\n======wlan   end======\n");

	return;
}

int build_ssid_dev_table(cJSON *json_data)
{
	int len = 0;
	int i = 0;
	//char prefix_2g[16] = {0}, prefix_5g[16] = {0};
	char *fmt = "%s%d";
	char *brlan_prefix = "br-lan";
	struct wlan_arg wlans[MAX_WLAN_COUNT];
	cJSON *json_wlan_array = NULL, *json_g_sta_bw = NULL, *json_g_dn_bw = NULL;
	cJSON *json_def_portal = NULL, *json_def_portal_val = NULL;

	if(!json_data){
		LOG_INFO("%s: arg null.\n", __FUNCTION__);
		return -1;
	}

	json_def_portal = cJSON_GetObjectItem(json_data, "default_portal_url");
	CHECK_JSON_EASY(json_def_portal, cJSON_Object);

	if(json_def_portal){
		json_def_portal_val = cJSON_GetObjectItem(json_def_portal, "url");
		CHECK_JSON_EASY(json_def_portal_val, cJSON_String);
	}

	memset(&wlans, 0, MAX_WLAN_COUNT * sizeof(struct wlan_arg));
	if(json_def_portal_val){
		unsigned int ipaddr[8] = {0};
		resolve_url(json_def_portal_val->valuestring, ipaddr, sizeof(ipaddr));

		for(i = 0; i < MAX_WLAN_COUNT; i++){
			snprintf(wlans[i].portal_url, sizeof(wlans[i].portal_url)-1, "%s", json_def_portal_val->valuestring);
			memcpy(wlans[i].portal_ipaddr, ipaddr, sizeof(ipaddr));

			snprintf(g_ssid_dev[i].portal_url, sizeof(g_ssid_dev[i].portal_url)-1, "%s", json_def_portal_val->valuestring);
			memcpy(g_ssid_dev[i].portal_ipaddr, ipaddr, sizeof(ipaddr));
		}
		
		LOG_INFO("add default portal:  %s: 0x%x\n", wlans[0].portal_url, wlans[i].portal_ipaddr[0]);

		set_portal_nl(wlans);
		
		print_ssid_dev();
	}

	json_wlan_array = cJSON_GetObjectItem(json_data, "wlan");
	CHECK_JSON(json_wlan_array, cJSON_Array);

	json_g_sta_bw = cJSON_GetObjectItem(json_data, "global_client_list");
	CHECK_JSON_EASY(json_g_sta_bw, cJSON_Object);

	json_g_dn_bw = cJSON_GetObjectItem(json_data, "global_domain_list");
	CHECK_JSON_EASY(json_g_dn_bw, cJSON_Object);

	//get_2g_dev_prefix(prefix_2g, sizeof(prefix_2g));
	//get_5g_dev_prefix(prefix_5g, sizeof(prefix_5g));
	memset(&g_ssid_dev, 0, MAX_WLAN_COUNT * sizeof(struct ssid_dev));
	LOG_INFO("g_ssid_dev size = %d\n", MAX_WLAN_COUNT * sizeof(struct ssid_dev));

	len = cJSON_GetArraySize(json_wlan_array);
	for(i = 0; i < len; i++){
		int number = -1, radio_type = -1;
		if(i >= MAX_WLAN_COUNT){
			LOG_INFO("%s: config wlan size=%d bigger than %d\n", __FUNCTION__, len, MAX_WLAN_COUNT);
			break;
		}
		cJSON *json_item, *json_number, *json_radio, *json_ssid;
		cJSON *json_portal, *json_online_time, *json_timeout, *json_up_rate, *json_down_rate;
		cJSON *json_clist, *json_clist_black, *json_clist_white;
		cJSON *json_dlist, *json_dlist_black, *json_dlist_white;

		json_item = cJSON_GetArrayItem(json_wlan_array, i);
		CHECK_JSON(json_item, cJSON_Object);

		json_number = cJSON_GetObjectItem(json_item, "number");
		CHECK_JSON(json_number, cJSON_String);
		json_radio = cJSON_GetObjectItem(json_item, "radio_type");
		CHECK_JSON(json_radio, cJSON_String);
		json_ssid = cJSON_GetObjectItem(json_item, "ssid");
		CHECK_JSON(json_ssid, cJSON_String);

		number = atoi(json_number->valuestring);
		radio_type = atoi(json_radio->valuestring);
		if(number < 1 || number > 6){
			LOG_INFO("%s: invalid ssid number: %d\n", __FUNCTION__, number);
			continue;
		}

		json_portal = cJSON_GetObjectItem(json_item, "portal_url");
		CHECK_JSON_EASY(json_portal, cJSON_String);
		json_online_time = cJSON_GetObjectItem(json_item, "online_control_time");
		CHECK_JSON_EASY(json_online_time, cJSON_String);
		json_timeout = cJSON_GetObjectItem(json_item, "flow_off_time");
		CHECK_JSON_EASY(json_timeout, cJSON_String);
		json_up_rate = cJSON_GetObjectItem(json_item, "up_rate");
		CHECK_JSON_EASY(json_up_rate, cJSON_String);
		json_down_rate = cJSON_GetObjectItem(json_item, "down_rate");
		CHECK_JSON_EASY(json_down_rate, cJSON_String);

		json_clist = cJSON_GetObjectItem(json_item, "client_list");
		CHECK_JSON_EASY(json_clist, cJSON_Object);
		json_dlist = cJSON_GetObjectItem(json_item, "domain_list");
		CHECK_JSON_EASY(json_dlist, cJSON_Object);printf("%d\n", __LINE__);

		if(json_clist){
			json_clist_black = cJSON_GetObjectItem(json_clist, "black");
			CHECK_JSON_EASY(json_clist_black, cJSON_Array);
			json_clist_white = cJSON_GetObjectItem(json_clist, "white");
			CHECK_JSON_EASY(json_clist_white, cJSON_Array);

			parse_bw_array(json_clist_black, &g_ssid_dev[number - 1], "sta", "black");
			parse_bw_array(json_clist_white, &g_ssid_dev[number - 1], "sta", "white");
		}

		if(json_dlist){
			json_dlist_black = cJSON_GetObjectItem(json_dlist, "black");
			CHECK_JSON_EASY(json_dlist_black, cJSON_Array);
			json_dlist_white = cJSON_GetObjectItem(json_dlist, "white");
			CHECK_JSON_EASY(json_dlist_white, cJSON_Array);

			parse_bw_array(json_dlist_black, &g_ssid_dev[number - 1], "domain", "black");
			parse_bw_array(json_dlist_white, &g_ssid_dev[number - 1], "domain", "white");
		}

		snprintf(g_ssid_dev[number - 1].ssid, sizeof(g_ssid_dev[number - 1].ssid) - 1, "%s", json_ssid->valuestring);

		if(json_portal || json_def_portal_val){
			snprintf(g_ssid_dev[number - 1].portal_url, sizeof(g_ssid_dev[number - 1].portal_url) - 1, "%s", 
				json_portal?json_portal->valuestring:json_def_portal_val->valuestring);
			resolve_url(g_ssid_dev[number - 1].portal_url, g_ssid_dev[number - 1].portal_ipaddr, 
				sizeof(g_ssid_dev[number - 1].portal_ipaddr)/sizeof(g_ssid_dev[number - 1].portal_ipaddr[0]));

			snprintf(wlans[number - 1].portal_url, sizeof(wlans[number - 1].portal_url)-1, "%s", g_ssid_dev[number - 1].portal_url);
			memcpy(wlans[number - 1].portal_ipaddr, g_ssid_dev[number - 1].portal_ipaddr, sizeof(wlans[number - 1].portal_ipaddr));
		}

		//printf("build ssid-dev: %d %s %s\n", json_number->valueint, g_ssid_dev[json_number->valueint - 1].ssid, g_ssid_dev[json_number->valueint - 1].dev);
	}

	set_portal_nl(wlans);
	print_ssid_dev();

	return 0;
}

static int handle_wifi_config(char *msg)
{
	/* Get plain: {"token":"123456","account":"14:3d:f2:bd:40:bc","function":"sendConfig","type":"config","subtype":"wifi","data":{"radio":{"2.4g":[],"5g":[]},"wlan":[]}}*/
	cJSON *json;	
	cJSON *json_data, *json_data_radio;
	cJSON *json_data_radio_2g, *json_data_radio_5g;

	if(!msg){
		LOG_INFO("%d: arg is null\n", __LINE__);
		return -1;
	}
	
	if(g_ap_last_config[0] && (0 == strcmp(g_ap_last_config, msg))){
		LOG_INFO("%s: duplicate config !\n", __FUNCTION__);
		dm_log_message(1, "%s: duplicate config !\n", __FUNCTION__);
		return 0;
	}

#if 0
	//char *mm="{\"token\":\"123456\",\"account\":\"14:3d:f2:bd:40:bc\",\"function\":\"sendConfig\",\"type\":\"config\","
	//	"\"subtype\":\"wifi\",\"data\":{\"radio\":{\"2.4g\":[],\"5g\":[]},\"wlan\":[{\"number\":"1",\"radio_type\":"0",\"ssid\":\"pppeeeww\","
	//	"\"client_list\":{\"black\":[{\"mac\":\"00:11:22:33:44:55\"},{\"mac\":\"11:22:33:66:66:66\"}],\"white\":[{\"mac\":\"00:11:22:33:44:55\"},{\"mac\":\"00:11:22:33:44:55\"}]}}]}}";	
	
	FILE *fp = NULL;char mm[4096]={0};
	fp = fopen("/root/c.json", "r");
	if(fp){fread(mm, 1, sizeof(mm)-1, fp);}
	fclose(fp);
	json = cJSON_Parse(mm);
#else
	json = cJSON_Parse(msg);
#endif
	if(!json){
		LOG_INFO("convert msg to json error: %s\n", msg);
		return -1;
	}
	json_data = cJSON_GetObjectItem(json, "data");
	CHECK_JSON(json_data, cJSON_Object);

	json_data_radio = cJSON_GetObjectItem(json_data, "radio");
	CHECK_JSON_EASY(json_data_radio, cJSON_Object);

	LOG_INFO("Parse wifi config success!!!\n");
	memset(g_ap_last_config, 0, sizeof(g_ap_last_config)-1);
	memcpy(g_ap_last_config, msg, sizeof(g_ap_last_config)-1);
	build_ssid_dev_table(json_data);//this function must before cJSON_Delete

	cJSON_Delete(json);

	ap_change_state(AP_RESTART_NETWORK);
	sleep(3);
	exec_wlan_config();
	exec_blk_wht_list();

	return 0;
}

static int handle_ac_call(char *wsid, char *from, char *msg)
{
	/* Get plain: {"token":"123456","account":"14:3d:f2:bd:40:bc","function":"sendConfig","type":"config","subtype":"wifi","data":{"radio":{"2.4g":[],"5g":[]},"wlan":[]}}*/
	cJSON *json;	
	cJSON *json_type, *json_subtype;
	
	if(!msg){
		LOG_INFO("%d: arg is null\n", __LINE__);
		return -1;
	}
	
	json = cJSON_Parse(msg);
	if(!json){
		LOG_INFO("convert msg to json error: %s\n", msg);
		return -1;
	}
	json_type = cJSON_GetObjectItem(json, "type");
	json_subtype = cJSON_GetObjectItem(json, "subtype");
	CHECK_JSON(json_type, cJSON_String);
	CHECK_JSON(json_subtype, cJSON_String);
	
	char tmp[256] = {0};
	snprintf(tmp, sizeof(tmp), "{\"type\":\"router\",\"wsid\":\"%s\",\"from\":\"%s\",\"error\":0,\"data\":{}}",
			wsid, from);

	if(!strcmp(json_type->valuestring, "config") && !strcmp(json_subtype->valuestring, "wifi")){
		enqueue_msg(tmp);
		ap_change_state(AP_CONFIGING);
		sleep(3);
		handle_wifi_config(msg);
		ap_change_state(AP_CONFIG_OK);
		ap_change_state(AP_RUNNING);
	}else if(!strcmp(json_type->valuestring, "getApInfo")){

		send_apinfo_to_ac(wsid, from);		

	}else if(!strcmp(json_type->valuestring, "getSsidInfo")){

	}else if(!strcmp(json_type->valuestring, "reboot")){
		enqueue_msg(tmp);
		ap_change_state(AP_REBOOTING);
		
		//system("sync ;sleep 3 ;reboot");
	}else{

		snprintf(tmp, sizeof(tmp), "{\"type\":\"router\",\"wsid\":\"%s\",\"from\":\"%s\",\"error\":1,\"data\":{}}",
			wsid, from);
		enqueue_msg(tmp);
	}

	return 0;
}

static int handle_msg(char *msg)
{
	int ret = 0;
	int len = 0;
	cJSON *json, *json_type, *json_subtype, *json_data, *json_data_mac, *json_data_action;
	char *type, *subtype;

	if(!msg){
		LOG_INFO("Error: %s arg null\n", __FUNCTION__);
		return -1;
	}
	LOG_INFO("%s: rcv msg: %s\n", __FUNCTION__, msg);				

	json = cJSON_Parse(msg);
	if(!json){
		LOG_INFO("convert msg to json error: %s\n", msg);
		return -1;
	}

	json_type = cJSON_GetObjectItem(json,"type");
	json_data = cJSON_GetObjectItem(json,"data");

	CHECK_JSON(json_type, cJSON_String);
	if(json_data){
		CHECK_JSON(json_data, cJSON_Object);
	}

	if(!strcmp("ap_control", json_type->valuestring)){
		json_data_action = cJSON_GetObjectItem(json_data,"action");
		CHECK_JSON(json_data_action, cJSON_String);

		if(!strcmp("auth_ok", json_data_action->valuestring)){
			ap_change_state(AP_RUNNING);
		}else if(!strcmp("auth_failed", json_data_action->valuestring)){
			sleep(30);
			ap_change_state(AP_AUTH_REQ);
		}
			
	}else if(!strcmp("sta_control", json_type->valuestring)){
		struct msg_to_ker *m = NULL;
		struct sta_ctl sc;
		char sta_ack_fmt[] = "{\"type\":\"sta_control\",\"subtype\":\"upstream\",\"data\":{\"apmac\":\"%s\","
			"\"mac\":\"%s\",\"state\":\"%s\"}}";
		char sta_ack_buf[256] = {0};
		char str_state[32] = {0};

		json_subtype = cJSON_GetObjectItem(json,"subtype");
		CHECK_JSON(json_subtype, cJSON_String);

		json_data_mac = cJSON_GetObjectItem(json_data,"mac");
		json_data_action = cJSON_GetObjectItem(json_data,"action");

		CHECK_JSON(json_data_mac, cJSON_String);
		CHECK_JSON(json_data_action, cJSON_String);

		LOG_INFO("mac=%s, action=%s\n", json_data_mac->valuestring, json_data_action->valuestring);

		memset(&sc, 0, sizeof(sc));
		ascii2mac(json_data_mac->valuestring, sc.mac);
		
		if(!strcmp("access_allow", json_data_action->valuestring)){
			sc.action = STA_ALLOW;
			snprintf(str_state, sizeof(str_state) - 1, "%s", "access_allow_ack");
		}else if(!strcmp("access_deny", json_data_action->valuestring)){
			sc.action = STA_DENY;
			snprintf(str_state, sizeof(str_state) - 1, "%s", "access_deny_ack");
		}else if(!strcmp("kickoff", json_data_action->valuestring)){
			sc.action = STA_KICKOFF;
			snprintf(str_state, sizeof(str_state) - 1, "%s", "kickoff_ack");
		}
			
		snprintf(sta_ack_buf, sizeof(sta_ack_buf) - 1, sta_ack_fmt, g_ap_label_mac, 
			json_data_mac->valuestring, str_state);
		enqueue_msg(sta_ack_buf);

		if(sc.action){
			len = sizeof(struct msg_to_ker) + sizeof(sc);
			m = (struct msg_to_ker *)malloc(len);
			if(!m){
				LOG_INFO("%s: malloc failed\n", __FUNCTION__);
				return -1;
			}

			m->type = M2K_STACTL;
			m->len = sizeof(sc);
			memcpy(m->value, &sc, sizeof(sc));
		
			ret = send_nl_msg(m, len);

			free(m);
		}
	}else if(!strcmp("rest", json_type->valuestring)){
		/*handle_msg: rcv msg: {"type":"rest","wsid":"14:3d:f2:bd:40:bc14454802451266","from":"pppoeRest","error":0,"data":{"apiclass":"net","method":"sendConfig","params":["eyJ0b2tlbiI6IjEyMzQ1NiIsImFjY291bnQiOiIxNDozZDpmMjpiZDo0MDpiYyIsImZ1bmN0aW9uIjoic2VuZENvbmZpZyIsInR5cGUiOiJjb25maWciLCJzdWJ0eXBlIjoid2lmaSIsImRhdGEiOnsicmFkaW8iOnsiMi40ZyI6W10sIjVnIjpbXX0sIndsYW4iOltdfX0="]}}
		 * Get base64: eyJ0b2tlbiI6IjEyMzQ1NiIsImFjY291bnQiOiIxNDozZDpmMjpiZDo0MDpiYyIsImZ1bmN0aW9uIjoic2VuZENvbmZpZyIsInR5cGUiOiJjb25maWciLCJzdWJ0eXBlIjoid2lmaSIsImRhdGEiOnsicmFkaW8iOnsiMi40ZyI6W10sIjVnIjpbXX0sIndsYW4iOltdfX0=
		 * Get plain: {"token":"123456","account":"14:3d:f2:bd:40:bc","function":"sendConfig","type":"config","subtype":"wifi","data":{"radio":{"2.4g":[],"5g":[]},"wlan":[]}}*/
		char buf[4096] = {0};
		cJSON *json_data_method, *json_data_params, *json_array_item;
		cJSON *json_wsid, *json_from;

		json_wsid = cJSON_GetObjectItem(json,"wsid");
		json_from = cJSON_GetObjectItem(json,"from");
		CHECK_JSON(json_wsid, cJSON_String);
		CHECK_JSON(json_from, cJSON_String);

		json_data_method = cJSON_GetObjectItem(json_data,"method");
		CHECK_JSON(json_data_method, cJSON_String);

		if(!strcmp("commercialAP", json_data_method->valuestring)){
			json_data_params = cJSON_GetObjectItem(json_data,"params");
			CHECK_JSON(json_data_params, cJSON_Array);
			json_array_item = cJSON_GetArrayItem(json_data_params, 0);
			CHECK_JSON(json_array_item, cJSON_String);
			LOG_INFO("Get base64: %s\n", json_array_item->valuestring);
			Base64decode(buf, json_array_item->valuestring);
			LOG_INFO("Get plain: %s\n", buf);
			dm_log_message(1, "Get plain: %s\n", buf);

			handle_ac_call(json_wsid->valuestring, json_from->valuestring, buf);
		}
	}else if(!strcmp("ap_heart_beat", json_type->valuestring)){
		json_subtype = cJSON_GetObjectItem(json,"subtype");
		CHECK_JSON(json_subtype, cJSON_String);
		if(!strcmp(json_subtype->valuestring, "ping")){
			char pong[] = "{\"type\":\"ap_heart_beat\",\"subtype\":\"pong\"}";	
			g_heartbeat_flag = 0;
			enqueue_msg(pong);
		}
	}

	cJSON_Delete(json);

	return ret;
}

void *pthread_recv(void *arg)
{
	int ret = 0;

	while(1){
		usleep(1000*200);
		if(1 != g_connection_flag)
			continue;
			
		pthread_mutex_lock(&mutex_r);
		msgdata *node = NULL;
		for(node = list_head_recv; node != NULL;node = node->next){
			if(0 == node->consumed){
				ret = handle_msg(node->msg);
				if(ret < 0) {
					fprintf(stderr, "%d: write error.\n", __LINE__);	
				}else{
					LOG_INFO("recv list: key=%d consumed.\n", node->key);
					dm_log_message(1, "recv list: key=%d consumed.\n", node->key);
					node->consumed = 1;
					free_all_consumed_node(&list_head_recv);
					LOG_INFO("clean result: recv list len = %d\n", list_length(list_head_recv));
				}
				break;
			}
		}
		pthread_mutex_unlock(&mutex_r);

	}
}

