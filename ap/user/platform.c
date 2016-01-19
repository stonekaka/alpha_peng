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
char *g_wlan_ifname[MAX_WLAN_COUNT][2]={{"ath0","ath16"},{"ath1","ath17"},{"ath2","ath18"},{"ath3","ath19"},{"ath4","ath20"},{"ath5","ath21"}};

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
#ifdef AP200_XML	
#define XMLSET_WLAN_SSID_PRIM  "/wlan/inf:%d/ssid"	
#define XMLSET_WLAN_SSID_SUB   "/wlan/inf:%d/multi/index:%d/ssid"
#endif	
#define SET_WLAN_PRIM  "rgdb -s /wlan/inf:%d/%%s"
#define SET_WLAN_SUB_ENABLE   "rgdb -s /wlan/inf:%d/multi/%%s"
#define SET_WLAN_SUB   "rgdb -s /wlan/inf:%d/multi/index:%d/%%s"
	int i = 0, j = 0;
	int f = 0;
	int ret = 0;
	char cmd[256] = {0};
	char prefix[128] = {0};
#ifdef AP200_XML	
	char xml_prefix[128] = {0};
#endif	
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
#ifdef AP200_XML
		memset(xml_prefix, 0, sizeof(xml_prefix));
#endif	
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
#ifdef AP200_XML
				snprintf(xml_prefix, sizeof(xml_prefix)-1, XMLSET_WLAN_SSID_PRIM, radio_index);
#endif	
			}else{
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_SUB, radio_index, i);
#ifdef AP200_XML
				snprintf(xml_prefix, sizeof(prefix)-1, XMLSET_WLAN_SSID_SUB, radio_index, i);
#endif	
			}

#ifdef AP200_XML
			xmldbc_set(NULL,0, xml_prefix, g_ssid_dev[i]->ssid);
			LOG_INFO("xmldbc_set: %s, %s.\n", xml_prefix, g_ssid_dev[i]->ssid);
#else
			snprintf(cmd, sizeof(cmd)-1, prefix, ssid_str);
			DM_SYSTEM(cmd);
#endif	
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
				snprintf(prefix, sizeof(prefix)-1, SET_WLAN_SUB_ENABLE, radio_index);
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

int get_soft_version(char *ver, int len)
{
	//return get_string_from_cmd(ver, len, "cat /version/v.json | awk -F\\\" '{print $20}'");
	return get_string_from_cmd(ver, len, "cat /etc/config/buildver | awk '{print $1}'");
}

int exec_bandwidth_limit(void)
{
#define BW_SET_CMD "\
		rgdb -s /tc_monitor/state 1;\
		rgdb -s /tc_monitor/mssid:%d/name ath%d;\
		rgdb -s /tc_monitor/mssid:%d/nameindex %d;\
		rgdb -s /tc_monitor/mssid:%d/band 0;\
		rgdb -s /tc_monitor/mssid:%d/state 4;\
		rgdb -s /tc_monitor/mssid:%d/downrate %d;\
		rgdb -s /tc_monitor/mssid:%d/uprate %d;\
		rgdb -s /tc_monitor/mssid:%d/upratetype 1;\
		rgdb -s /tc_monitor/mssid:%d/downratetype 1;\
		 /etc/scripts/misc/profile.sh put;\
		 submit QOS_TC_TM\
		"
#define  BW_CLEAR_CMD "rgdb -s /tc_monitor/mssid:%d/state 0"

	int i = 0;
	char cmd[512] = {0};
	int mid = 0, athid = 0;
	
	/*
	 *[mssid:x]:
	 *  1~8  map to  ath0~ath7
	 *  9~16 map to  ath16~ath23
	 *
	 */

	for(i = 0; i < MAX_WLAN_COUNT; i++){
		mid = i+1;
		snprintf(cmd, sizeof(cmd)-1, BW_CLEAR_CMD, mid);
		DM_SYSTEM(cmd);
		mid = i+1+8;
		snprintf(cmd, sizeof(cmd)-1, BW_CLEAR_CMD, mid);
		DM_SYSTEM(cmd);
	}

	for(i = 0; i < MAX_WLAN_COUNT; i++){
		if(g_ssid_dev[i]->up_rate == 0 && g_ssid_dev[i]->up_rate == 0)continue;

		if(0 == g_ssid_dev[i]->radio_type){
			mid = i+1;
			athid = i;
		}else{
			mid = i+1+8;
			athid = i+1+16;
		}

		snprintf(cmd, sizeof(cmd)-1, BW_SET_CMD, 
						mid, athid,
						mid, athid,
						mid,
						mid,
						mid, g_ssid_dev[i]->up_rate*8, 
						mid, g_ssid_dev[i]->down_rate*8,
						mid,
						mid);
		DM_SYSTEM(cmd);
	}

	return 0;
}

int get_ssid_status(char *ifname, struct ssid_status *node)
{
	struct freq_s{
		int channel;
		char freq[8];
	}freq_list[]={{1,"2.412"},{2,"2.417"},{3,"2.422"},{4,"2.427"},{5,"2.432"},
	{6,"2.437"},{7,"2.442"},{8,"2.447"},{9,"2.452"},{10,"2.457"},{11,"2.462"},
	{36,"5.18"},{40,"5.2"},{44,"5.22"},{48,"5.24"},{149,"5.745"},{153,"5.765"},{157,"5.785"},
	{161,"5.805"},{165,"5.825"}};
	int i = 0;
	char fmt_ssid[] = "iwconfig %s | grep ESSID | awk -F\\\" '{print $2}'";
	char fmt_channel[] = "iwconfig %s | grep Frequency | awk '{print $2}' | awk -F: '{print $2}'";
	char fmt_txpower[] = "iwconfig %s | grep Tx-Power | awk '{print $4}' | awk -F: '{print $2}'"; 
	char fmt_encrypt[] = "iwconfig %s | grep \"Encryption key\" | awk '{print $2}'";
	char cmd[128] = {0};
	char ssid[64] = {0};
	char freq[32] = {0};
	int channel = 0;
	int txpower = 0;
	char encrypt_str[64] = {0};
	int encrypt_type = 0;

	if(!ifname){
		return -1;
	}

	snprintf(cmd, sizeof(cmd) - 1, fmt_ssid, ifname);
	get_string_from_cmd(ssid, sizeof(ssid) - 1, cmd);
	snprintf(node->ssid, sizeof(node->ssid)-1, "%s", ssid);

	snprintf(cmd, sizeof(cmd) - 1, fmt_channel, ifname);
	get_string_from_cmd(freq, sizeof(freq) - 1, cmd);
	printf("%s", freq);
	for(i = 0; i < sizeof(freq_list)/sizeof(struct freq_s); i++) {
		if(0 == strcmp(freq, freq_list[i].freq)){
			node->channel = freq_list[i].channel;
			break;	
		}
	}

	snprintf(cmd, sizeof(cmd) - 1, fmt_txpower, ifname);
	get_int_from_cmd(&txpower, cmd);
	printf("%d", txpower);
	node->txpower = txpower;

	snprintf(cmd, sizeof(cmd) - 1, fmt_encrypt, ifname);
	get_string_from_cmd(encrypt_str, sizeof(encrypt_str) - 1, cmd);
	if(NULL == strstr(encrypt_str, "key:off")){
		node->encrypt = 5;
	}else{
		node->encrypt = 0;
	}

	return 0;
}

int get_all_ssid_status(struct ssid_status *ssid_list)
{
	int i = 0;

	for(i = 0; i < MAX_WLAN_COUNT; i++){
		if(g_ssid_dev[i]->radio_type == 0){
			get_ssid_status(g_wlan_ifname[i][0], &ssid_list[i]);
		}else{
			get_ssid_status(g_wlan_ifname[i][1], &ssid_list[i]);
		}
		ssid_list[i].hidden = g_ssid_dev[i]->hidden;
	}
	return 0;
}

int fw_upgrade(char *url, char *md5)
{
#define FW_FILENAME	"/tmp/pwf_upgrade.bin"
#define FW_UPGRADE "cat "FW_FILENAME" > /dev/mtdblock/1 && echo \"1\">/proc/rebootm"
	int ret = 0;
	char smd5[64] = {0};
	char cmd[128] = {0};
	
	if(!url || !md5){
		return -1;
	}

	LOG_INFO("%s: url=%s, md5=%s\n", __FUNCTION__, url, md5);
	download_file(url, FW_FILENAME);
	get_file_md5(FW_FILENAME, smd5, sizeof(smd5) - 1);
	if(0 != strcasecmp(md5, smd5)){
		LOG_INFO("%s: fw md5 not match: told:real  -%s:%s-\n", __FUNCTION__, md5, smd5);
		return -1;
	}
	LOG_INFO("%s:fw md5 is match: told:real  -%s:%s-\n", __FUNCTION__, md5, smd5);

	LOG_INFO("%s: exec: %s.\n", __FUNCTION__, FW_UPGRADE);
	system(FW_UPGRADE);

	return ret;
}

