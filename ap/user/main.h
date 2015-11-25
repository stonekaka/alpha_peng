/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     main.h
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-10 16:53
***************************************************************************/
#ifndef _MAIN_H_
#define _MAIN_H_
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pub.h"
#include "util.h"
#include "list.h"

enum _ap_state{
	AP_IDLE = 1,
	AP_DISCOVERY,
	AP_JOIN_S1,
	AP_JOIN_S2,
	AP_JOIN_S3,
	AP_JOIN_S4,
	AP_JOIN_OK,
	AP_AUTH_REQ,
	AP_CONFIGING,
	AP_RESTART_NETWORK,
	AP_CONFIG_OK,
	AP_RUNNING,
	AP_REBOOTING,
	AP_UPGRADING,
	AP_RESET_FACTORY,
	AP_OFFLINE
};

void *pthread_netlink(void *arg);
void *pthread_recv(void *arg);
void *pthread_httpserver(void *arg);
int send_nl_msg(struct msg_to_ker *msg_body, int msg_body_len);
int set_ap_online(int flag);
int lbps_discovery(void *arg);

void ap_change_state(int state);
int get_ap_label_mac(char *out, int outlen, int nocol);
int get_staid_by_mac(char *staid, int len, char *mac);
int get_ssid_portal_by_dev(char *ssid, int slen, char *portal, int plen, char *dev);

pthread_mutex_t mutex;
pthread_mutex_t mutex_r;

#define MAX_MSG_SIZE  8192
#define MAX_NAME_SIZE 256
#define MAX_STA_MSG_SIZE 512

#define CHECK_JSON(_key, _type) do{if(!_key || _key->type != _type){printf("%d: error json type %d\n", __LINE__, _type);return -1;}}while(0)
#define CHECK_JSONS(_key, _type1, _type2) do{if(!_key || ((_key->type != _type1) && (_key->type != _type2))){printf("%d: error json type %d\n", __LINE__,_type);return -1;}}while(0)
#define CHECK_JSON_EASY(_key, _type) do{if(_key && _key->type != _type){printf("%d: error json type %d\n", __LINE__, _type);return -1;}}while(0)

struct ssid_dev {
	char ssid[64];
	char dev[32];
	char portal_url[128];
	unsigned int portal_ipaddr[8];	
#define MAX_STA_BW_CNT 64
	unsigned char sta_black[MAX_STA_BW_CNT][ETH_ALEN];
	unsigned char sta_white[MAX_STA_BW_CNT][ETH_ALEN];
#define MAX_DN_BW_CNT 64
#define MAX_DN_IP     8
	char domain_black[MAX_DN_BW_CNT][MAX_DOMAIN_LEN];
	char domain_white[MAX_DN_BW_CNT][MAX_DOMAIN_LEN];
	unsigned int domain_black_ipaddr[MAX_DN_BW_CNT][8];
	unsigned int domain_white_ipaddr[MAX_DN_BW_CNT][8];
	int sta_timeout;
	int sta_max_time;
	int hidden;
	int enc_type;
	char enc_key[64];
	int radio_type;
};

struct radio_config {
	int hwmode;
	int htmode;
	int channel;
	int txpower;
	int enabled;
};

void
dm_log_message(int priority, const char *format, ...);
int dm_open_log(void);
void dm_close_log(void);

int enqueue_msg(char *msg);
int enqueue_r_msg(char *msg);

int exec_wlan_config(void);
int exec_radio_config(void);
int init_ssid_ifname(void);

#define LOG_INFO(format, ...) do{fprintf(stdout, format, ##__VA_ARGS__);dm_log_message(1, format, ##__VA_ARGS__);}while(0)

#define DEFAULT_PORTAL "http://portal-router.test.pengwifi.com/Auth?"

#endif
