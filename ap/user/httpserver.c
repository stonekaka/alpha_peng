/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     httpserver.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-09-21 17:15
***************************************************************************/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <error.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#include "main.h"

#define HTTP_PORT 8012
#define MAX_CONNECTION 200

extern int g_state;
extern char *g_acname;
extern struct ssid_dev **g_ssid_dev;
extern char g_ap_label_mac_nocol[];

extern char g_auth_code[];

int get_user_mac_dev_by_ip(char *ip, char *mac, int maclen, char *dev, int devlen)
{
	//char *cmd = "cat /proc/net/arp | grep \"%s \" | awk '{print $3,$4,$6}' | grep \"^0x2\" | sed 's/://g'";
	char *cmd = "cat /proc/pengwifi/stas | grep \"%s \" | awk '{print $2,$5}'";
	char cmd_e[128] = {0};
	char buf[256] = {0};
	FILE *fp = NULL;
	int n = 0;
	
	if(!ip || !mac || !dev){
		printf("%d:Error: bad arg\n", __LINE__);
		return -1;
	}

	snprintf(cmd_e, sizeof(cmd_e)-1, cmd, ip);
	fp = popen(cmd_e, "r");
	if(!fp){
		LOG_INFO("%s:Error: exec: %s \n", __FUNCTION__, cmd_e);
		return -1;
	}

	if(fgets(buf, sizeof(buf) - 1, fp)){
		clear_crlf(buf);		
		n = sscanf(buf, "%s %s", mac, dev);
		if(n != 2){
			LOG_INFO("%s: buf error: %s\n", __FUNCTION__, buf);
		}
	}
	
	//printf("%s: ip=%s, mac=%s, dev=%s\n", __FUNCTION__, ip, mac, dev);

	pclose(fp);

	return 0;
}

int get_staid_by_mac(char *staid, int len, char *mac)
{
	unsigned int hash = 0;
	struct in_addr in;

	if(!staid || !mac){
		LOG_INFO("%s:Error: bad arg\n", __FUNCTION__);
		return -1;
	}

	get_hash_by_mac(mac, &hash);
	in.s_addr = hash;
	snprintf(staid, len, "%s", inet_ntoa(in));

	return 0;
}

int get_ssid_portal_by_dev(char *ssid, int slen, char *portal, int plen, char *dev)
{
	int i = 0;
	char ifname[32] = {0};

	if(!ssid || !dev || !portal){
		LOG_INFO("%d:Error: bad arg\n", __LINE__);
		return -1;
	}

	for(i = 0; i < MAX_WLAN_COUNT; i++){
		snprintf(ifname, sizeof(ifname)-1, "%s_", dev);
		printf("%s: %d: compare: [s]-%s- [r]-%s- [i]-%s-\n", __FUNCTION__, i, g_ssid_dev[i]->dev, dev, ifname);
		if(strstr(g_ssid_dev[i]->dev, ifname)){
			snprintf(ssid, slen, "%s", g_ssid_dev[i]->ssid);
			snprintf(portal, plen, "%s", g_ssid_dev[i]->portal_url);
			printf("%s: get dev=%s, ssid=%s, portal_url=%s\n", __FUNCTION__, dev, ssid, portal);
			break;
		}
	}

	if(!portal[0]){ //must have portal, avoid redirect loop
		snprintf(portal, plen, "%s", DEFAULT_PORTAL);
	}
	printf("=============get portal: %s=====\n", portal);
	return 0;
}

int _i=0;
void sighandle(int sig)
{
	if (sig == SIGCHLD) {
		pid_t pid;
		while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {_i--;
			//printf("SIGCHLD pid %d\n", pid);
		}
	}
}

void * pthread_httpserver(void *arg)
{
    int server_sock;
    int client_sock;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    pid_t pid;
    char buf[512] = {0};
	char *client_ip_str = NULL;
	
    memset(&server_addr,0,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(HTTP_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	while(1){
		if((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    	{
        	perror("socket");
			sleep(30);
        	continue;
    	}

    	if(bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        	perror("bind");
			sleep(30);
        	continue;
    	}

    	if(listen(server_sock, MAX_CONNECTION) < 0){
        	perror("listen");
			sleep(30);
        	continue;
    	}
		sleep(1);
		break;
	}
	
	LOG_INFO("----------------------------------------\n");
	LOG_INFO("httpserver successful created ...\n");	
	LOG_INFO("----------------------------------------\n");

	signal(SIGCHLD, sighandle);
	while(1) {

		if(AP_RUNNING != g_state){
			sleep(3);
			continue;
		}

		unsigned int clientlen = sizeof(client_addr);
		if((client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &clientlen)) < 0){
			perror("accept");
			return NULL;
		}
		
		char mac[32] = {0}, ifname[32] = {0}, ssid[64] = {0}, portal[128] = {0};
		char staid[32] = {0};
		int ret1 = 0, ret2 = 0, ret3 = 0;
		client_ip_str = inet_ntoa(client_addr.sin_addr);
		ret1 = get_user_mac_dev_by_ip(client_ip_str, mac, sizeof(mac) - 1, ifname, sizeof(ifname) - 1);
		ret2 = get_staid_by_mac(staid, sizeof(staid) - 1, mac);
		ret3 = get_ssid_portal_by_dev(ssid, sizeof(ssid), portal, sizeof(portal), ifname);
		if(ret1 || ret2 || ret3){
			goto close;
		}
		if((pid = fork()) == 0){
			if(read(client_sock, buf, sizeof(buf) - 1) < 0){
				perror("read data from client");
				exit(1);	
			}
			printf("%d:buf=%s\n", __LINE__, buf);

			if(strncasecmp(buf, "GET ", 4) == 0
				|| strncasecmp(buf, "POST ", 5) == 0
				|| strncasecmp(buf, "HEAD ", 5) == 0){//printf("%d\n", __LINE__);

				memset(&buf,0,sizeof(buf));
				sprintf(buf, "HTTP/1.1 302 Moved Temporarily\r\n"
							"Server: %s\r\n"
							"Content-Type: text/html\r\n"
							"Connection: keep-alive\r\n"
							"Location: %sgw_id=%s&wlanuserip=%s&wlanacname=%s&wlanapmac=%s&wlanusermac=%s&ssid=%s\r\n"
							"\r\n", "pengwifi", portal, g_auth_code, staid, url_encode(g_acname), g_ap_label_mac_nocol/*"14144b60d311"*/, mac, ssid);
				LOG_INFO(buf);
				write(client_sock, buf, strlen(buf));
				close(client_sock);
				close(server_sock);
			}
			exit(0);
		}else{_i++;}
		
		if(_i && (_i%100 == 0)){
			LOG_INFO("httpserver handle times: %d.\n", _i);
			dm_log_message(1, "httpserver handle times: %d.\n", _i);
		}
close:
		close(client_sock);
	}

	close(server_sock);

	return NULL;
}

