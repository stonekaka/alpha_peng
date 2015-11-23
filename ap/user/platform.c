/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     platform.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-22 16:01
***************************************************************************/
#include <stdio.h>
#include <string.h>
#include "main.h"
#include "util.h"

extern struct ssid_dev **g_ssid_dev;

int get_wan_mac(char *mac, int len)
{
	char *cmd = "ifconfig br0 | grep HWaddr |awk '{print $5}' | tr '[A-Z]' '[a-z]'";
	FILE *fp = NULL;

	fp = popen(cmd, "r");
	if(fp){
		fgets(mac, len, fp);
		clear_crlf(mac);
	}else{
		return -1;
	}

	pclose(fp);
	return 0;
}

int get_wan_ip(char *ip, int len)
{
	char *cmd = "ifconfig br0 | grep \"inet addr\" |awk '{print $2}' | awk -F: '{print $2}'";
	FILE *fp = NULL;

	fp = popen(cmd, "r");
	if(fp){
		fgets(ip, len, fp);
		clear_crlf(ip);
	}else{
		return -1;
	}

	pclose(fp);
	return 0;
}

int get_2g_dev_prefix(char *prefix, int len)
{
	char *s = "ra";

	strncpy(prefix, s, len > strlen(s)?strlen(s):len);

	return 0;	
}

int get_5g_dev_prefix(char *prefix, int len)
{
	char *s = "rai";

	strncpy(prefix, s, len > strlen(s)?strlen(s):len);
	
	return 0;
}

int get_ap_label_mac(char *out, int outlen, int nocol)
{
	char *cmd = "ifconfig br0 | grep \"HWaddr\" | awk '{print $5}' | sed 's/://g' | tr '[A-Z]' '[a-z]'";
	char *cmd2 = "ifconfig br0 | grep \"HWaddr\" | awk '{print $5}' | tr '[A-Z]' '[a-z]'";
	FILE *fp = NULL;
	
	if(!out){
		printf("%d:Error: bad arg\n", __LINE__);
		return -1;
	}

	if(nocol)
		fp = popen(cmd, "r");
	else
		fp = popen(cmd2, "r");
	if(!fp){
		printf("%s:Error: exec: %s \n", __FUNCTION__, cmd);
		return -1;
	}

	if(fgets(out, outlen, fp)){
		clear_crlf(out);		
	}

	pclose(fp);

	return 0;
}

/*int exec_wlan_config(void)
{
	int i = 0;
	int ret = 0;
	char fmt[] = "uci set wireless.@wifi-iface[1].ssid=%s && uci commit wireless;wifi";
	char cmd[256] = {0};
	
	for(i = 0; i < MAX_WLAN_COUNT; i++){
		if(g_ssid_dev[i].ssid[0]){
			snprintf(cmd, sizeof(cmd)-1, fmt, g_ssid_dev[i].ssid);
			printf("exec: %s\n", cmd);
			ret = system(cmd);
			if(!ret){
				printf("%d: exec error: %s\n", __LINE__, cmd);
			}
		}
	}
	
	return 0;
}*/

int translate_enctype(int input)
{
	int ret = 0;

		

	return ret;
}

int exec_wlan_config(void)
{
#define SET_WLAN_PRIM  "rgdb -s /wlan/inf:%d/%%s"
#define SET_WLAN_SUB   "rgdb -s /wlan/inf:%d/multi/index:%d/%%s"
#define SAVE_SET       "/etc/scripts/misc/profile.sh put"
#define ACTIVE_SET     "submit WLAN"

#define DM_SYSTEM(cmd) do{LOG_INFO(cmd);/*system(cmd);*/}while(0)

	int i = 0;
	int f = 0;
	int ret = 0;
	char cmd[256] = {0};
	char prefix[128] = {0};
	char ssid_str[80] = {0};
	char hidden_str[20] = {0};
	char enc_type_str[20] = {0};
	char enc_value_str[60] = {0};
	int radio_index = 0;

	for(i = 0; i < MAX_WLAN_COUNT; i++){
		if(0 == i)f = 1;

		memset(prefix, 0, sizeof(prefix));
		memset(ssid_str, 0, sizeof(ssid_str));
		memset(hidden_str, 0, sizeof(hidden_str));
		memset(enc_type_str, 0, sizeof(enc_type_str));
		memset(enc_value_str, 0, sizeof(enc_value_str));
		radio_index = 0;

		if(g_ssid_dev[i]->ssid[0]){
			if(0 == g_ssid_dev[i]->radio_type){
				radio_index = 1;
			}else{
				radio_index = 2;
			}

			snprintf(ssid_str, sizeof(ssid_str)-1, "ssid %s", g_ssid_dev[i]->ssid);
			snprintf(hidden_str, sizeof(hidden_str)-1, "ssidhidden %d", g_ssid_dev[i]->hidden);
			if(f){
				snprintf(enc_type_str, sizeof(enc_type_str)-1, "authentication %d", translate_enctype(g_ssid_dev[i]->enc_type));
			}else{
				snprintf(enc_type_str, sizeof(enc_type_str)-1, "auth %d", translate_enctype(g_ssid_dev[i]->enc_type));
			}
			snprintf(enc_value_str, sizeof(enc_value_str), "wpa/wpapsk %s", g_ssid_dev[i]->enc_key);

			if(f){
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_PRIM, radio_index);
			}else{
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_SUB, radio_index, i);
			}

			snprintf(cmd, sizeof(cmd)-1, prefix, ssid_str);
			DM_SYSTEM(cmd);
			snprintf(cmd, sizeof(cmd)-1, prefix, hidden_str);
			DM_SYSTEM(cmd);
			snprintf(cmd, sizeof(cmd)-1, prefix, enc_type_str);
			DM_SYSTEM(cmd);
			if(g_ssid_dev[i]->enc_type != 0){
				snprintf(cmd, sizeof(cmd)-1, prefix, enc_value_str);
				DM_SYSTEM(cmd);
			}
			DM_SYSTEM(SAVE_SET);
		}
		
		f = 0;
	}

	DM_SYSTEM(ACTIVE_SET);
	
	return ret;
}

