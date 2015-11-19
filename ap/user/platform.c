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

extern struct ssid_dev g_ssid_dev[];

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

int exec_wlan_config(void)
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
}

