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
extern struct radio_config radio_2g, radio_5g;

#define SAVE_SET       "/etc/scripts/misc/profile.sh put"
#define ACTIVE_SET     "submit WLAN"

#define DM_SYSTEM(cmd) do{LOG_INFO(cmd);LOG_INFO("\n");system(cmd);}while(0)

int init_ssid_ifname(void)
{
	int i = 0;

	for(i = 0; i < MAX_WLAN_COUNT; i++) {
		snprintf(g_ssid_dev[i]->dev, sizeof(g_ssid_dev[i]->dev)-1, "ath%d_ath%d_", i, i+16);
	}	

	return 0;
}

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


int exec_radio_config(void)
{
#define SET_2G "rgdb -s /wlan/inf:1/"		
#define SET_5G "rgdb -s /wlan/inf:2/"		
	char hwmode_str[64] = {0};
	char htmode_str[64] = {0};
	char autochannel_str[64] = {0};
	char channel_str[64] = {0};
	char txpower_str[64] = {0};
	char enabled_str[64] = {0};

	snprintf(htmode_str, sizeof(htmode_str)-1, SET_2G"wlmode %d", 1);printf("====%s===\n", htmode_str);
	if(radio_2g.htmode == 3){
		snprintf(htmode_str, sizeof(htmode_str)-1, SET_2G"cwmmode %d", 1);
	}else if(radio_2g.htmode == 2){
		snprintf(htmode_str, sizeof(htmode_str)-1, SET_2G"cwmmode %d", 2);
	}else if(radio_2g.htmode == 1){
		snprintf(htmode_str, sizeof(htmode_str)-1, SET_2G"cwmmode %d", 3);
	}

	if(radio_2g.channel == 0){
		snprintf(autochannel_str, sizeof(autochannel_str)-1, SET_2G"autochannel %d", 1);
	}else if(radio_2g.channel > 0 && radio_2g.channel <= 13){
		snprintf(autochannel_str, sizeof(autochannel_str)-1, SET_2G"autochannel %d", 0);
		snprintf(channel_str, sizeof(channel_str)-1, SET_2G"channel %d", radio_2g.channel);
	}

	if(radio_2g.txpower == 255){//auto txpower
		snprintf(txpower_str, sizeof(txpower_str)-1, SET_2G"txpower %d", 20);//?????	
	}else if(radio_2g.txpower >=0 && radio_2g.txpower <= 30){
		snprintf(txpower_str, sizeof(txpower_str)-1, SET_2G"txpower %d", radio_2g.txpower);
	}

	snprintf(enabled_str, sizeof(enabled_str)-1, SET_2G"enabled %d", radio_2g.enabled);

	LOG_INFO("set radio 2.4g start...\n");
	DM_SYSTEM(htmode_str);
	DM_SYSTEM(autochannel_str);
	DM_SYSTEM(channel_str);
	DM_SYSTEM(txpower_str);
	DM_SYSTEM(enabled_str);
	LOG_INFO("set radio 2.4g end\n");

	/****start set 5g radio****/
	memset(autochannel_str, 0, sizeof(autochannel_str));
	memset(channel_str, 0, sizeof(channel_str));
	memset(txpower_str, 0, sizeof(txpower_str));
	memset(enabled_str, 0, sizeof(enabled_str));

	if(radio_5g.channel == 0){
		snprintf(autochannel_str, sizeof(autochannel_str)-1, SET_5G"autochannel %d", 1);
	}else if(radio_5g.channel > 0 && radio_5g.channel <= 165){
		snprintf(autochannel_str, sizeof(autochannel_str)-1, SET_5G"autochannel %d", 0);
		snprintf(channel_str, sizeof(channel_str)-1, SET_5G"channel %d", radio_5g.channel);
	}

	if(radio_5g.txpower == 255){//auto txpower
		snprintf(txpower_str, sizeof(txpower_str)-1, SET_5G"txpower %d", 20);//?????	
	}else if(radio_5g.txpower >=0 && radio_5g.txpower <= 30){
		snprintf(txpower_str, sizeof(txpower_str)-1, SET_5G"txpower %d", radio_5g.txpower);
	}
	
	snprintf(enabled_str, sizeof(enabled_str)-1, SET_5G"enabled %d", radio_5g.enabled);

	LOG_INFO("set radio 5g start...\n");
	DM_SYSTEM(autochannel_str);
	DM_SYSTEM(channel_str);
	DM_SYSTEM(txpower_str);
	DM_SYSTEM(enabled_str);
	LOG_INFO("set radio 5g end\n");

	//save and active at wlan config

	return 0;
}

int translate_enctype(int input)
{
	int ret = 0;

	if(0 == input){
		ret = 0;
	}else{
		ret = 7;
	}

	return ret;
}

int exec_wlan_config(void)
{
#define SET_WLAN_PRIM  "rgdb -s /wlan/inf:%d/%%s"
#define SET_WLAN_SUB   "rgdb -s /wlan/inf:%d/multi/index:%d/%%s"
	int i = 0, j = 0;
	int f = 0;
	int ret = 0;
	char cmd[256] = {0};
	char prefix[128] = {0};
	char delete_str[20] = {0};
	char ssid_str[80] = {0};
	char hidden_str[20] = {0};
	char enc_type_str[20] = {0};
	char enc_value_str[60] = {0};
	char enc_value_add_str[20] = {0};
	int radio_index = 0;

	LOG_INFO("start disable all ssid ...\n");
	for(i = 0; i < MAX_WLAN_COUNT; i++){
		if(0 == i){
			f = 1;
		}else{
			f = 0;
		}

		memset(prefix, 0, sizeof(prefix));
		memset(delete_str, 0, sizeof(delete_str));

		for(j = 1; j <= 2; j++){
			if(f){
				snprintf(delete_str, sizeof(delete_str)-1, "ssid \"\"");
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_PRIM, j);

				snprintf(cmd, sizeof(cmd)-1, prefix, delete_str);
				DM_SYSTEM(cmd);

				snprintf(delete_str, sizeof(delete_str)-1, "enable %d", 0);
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_PRIM, j);
			}else{
				snprintf(delete_str, sizeof(delete_str)-1, "state %d", 0);
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_SUB, j, i);
			}
			snprintf(cmd, sizeof(cmd)-1, prefix, delete_str);
			DM_SYSTEM(cmd);
		}
	}

	LOG_INFO("start config ssid ...\n");
	for(i = 0; i < MAX_WLAN_COUNT; i++){
		if(0 == i){
			f = 1;
		}else{
			f = 0;
		}

		memset(prefix, 0, sizeof(prefix));
		memset(delete_str, 0, sizeof(delete_str));
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

			/**do nothing if radio is disable**/
			if((radio_index == 1 && !radio_2g.enabled) || (radio_index == 2 && !radio_5g.enabled)){
				continue;
			}

			snprintf(ssid_str, sizeof(ssid_str)-1, "ssid %s", g_ssid_dev[i]->ssid);
			if(f){
				snprintf(hidden_str, sizeof(hidden_str)-1, "ssidhidden %d", g_ssid_dev[i]->hidden);
				snprintf(enc_type_str, sizeof(enc_type_str)-1, "authentication %d", translate_enctype(g_ssid_dev[i]->enc_type));
				if(g_ssid_dev[i]->enc_type){
					snprintf(enc_value_str, sizeof(enc_value_str), "wpa/wpapsk %s", g_ssid_dev[i]->enc_key);
				}
			}else{
				snprintf(hidden_str, sizeof(hidden_str)-1, "ssid_hidden %d", g_ssid_dev[i]->hidden);
				snprintf(enc_type_str, sizeof(enc_type_str)-1, "auth %d", translate_enctype(g_ssid_dev[i]->enc_type));
				if(g_ssid_dev[i]->enc_type){
					snprintf(enc_value_str, sizeof(enc_value_str)-1, "passphrase %s", g_ssid_dev[i]->enc_key);	
					snprintf(enc_value_add_str, sizeof(enc_value_add_str)-1, "%s", "passphraseformat 1");	
				}
			}

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

			if(f){
				snprintf(delete_str, sizeof(delete_str)-1, "enable %d", 1);
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_PRIM, radio_index);
				if(g_ssid_dev[i]->enc_type != 0){
					snprintf(cmd, sizeof(cmd)-1, prefix, enc_value_str);
					DM_SYSTEM(cmd);
				}
			}else{
				snprintf(delete_str, sizeof(delete_str)-1, "enable %d", 1);
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_PRIM, radio_index);
				snprintf(cmd, sizeof(cmd)-1, prefix, delete_str);
				DM_SYSTEM(cmd);

				snprintf(delete_str, sizeof(delete_str)-1, "state %d", 1);
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_SUB, radio_index, i);

				if(g_ssid_dev[i]->enc_type){
					snprintf(cmd, sizeof(cmd)-1, prefix, enc_value_str);
					DM_SYSTEM(cmd);
					snprintf(cmd, sizeof(cmd)-1, prefix, enc_value_add_str);
					DM_SYSTEM(cmd);
				}
			}
			snprintf(cmd, sizeof(cmd)-1, prefix, delete_str);
			DM_SYSTEM(cmd);

			DM_SYSTEM(SAVE_SET);
		}
		
		f = 0;
	}

	DM_SYSTEM(ACTIVE_SET);
	LOG_INFO("end config ssid\n ");
	
	return ret;
}

