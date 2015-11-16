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
#include <linux/can/error.h>
#include <errno.h>

#include <sys/types.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#define HTTP_PORT 8012
#define MAX_CONNECTION 200

int get_ap_label_mac(char *out, int outlen)
{
	int ret = 0;
	char *cmd = "ifconfig br-lan | grep \"HWaddr\" | awk '{print $5}' | sed 's/://g'";
	char *buf = NULL;
	FILE *fp = NULL;
	
	if(!out){
		printf("%d:Error: bad arg\n", __LINE__);
		return -1;
	}

	fp = popen(cmd, "r");
	if(!fp){
		printf("%d:Error: fp null\n", __LINE__);
		return -1;
	}

	if(fgets(out, outlen, fp)){
		clear_crlf(out);		
	}

	pclose(fp);

	return 0;
}

int get_user_mac_by_ip(char *ip, char *out, int outlen)
{
	int ret = 0;
	char *cmd = "cat /proc/net/arp | grep \"%s \" | awk '{print $4}' | sed 's/://g'";
	char cmd_e[128] = {0};
	char *buf = NULL;
	FILE *fp = NULL;
	
	if(!ip || !out){
		printf("%d:Error: bad arg\n", __LINE__);
		return -1;
	}

	sprintf(cmd_e, cmd, ip);
	fp = popen(cmd_e, "r");
	if(!fp){
		printf("%d:Error: fp null\n", __LINE__);
		return -1;
	}

	if(fgets(out, outlen, fp)){
		clear_crlf(out);		
	}

	pclose(fp);

	return 0;
}

int i=0;
void sighandle(int sig)
{
	if (sig == SIGCHLD) {
		pid_t pid;
		while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {i--;
			printf("SIGCHLD pid %d\n", pid);
		}
	}
}

int main(void)
{
    int server_sock;
    int client_sock;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    pid_t pid;
    char buf[512] = {0};
	char *client_ip_str = NULL;
	char ap_mac[32] = {0};
	
	get_ap_label_mac(ap_mac, sizeof(ap_mac) - 1);

    memset(&server_addr,0,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(HTTP_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        exit(1);
    }

    if(bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        perror("bind");
        exit(1);
    }

    if(listen(server_sock, MAX_CONNECTION) < 0){
        perror("listen");
        exit(1);
    }
	
	printf("httpserver successful created ...\n");	

	signal(SIGCHLD, sighandle);
	while(1) {
		unsigned int clientlen = sizeof(client_addr);
		if((client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &clientlen)) < 0){
			perror("accept");
			exit(1);
		}
		
		if((pid = fork()) == 0){
			if(read(client_sock, buf, sizeof(buf) - 1) < 0){
				perror("read data from client");
				exit(1);	
			}printf("%d:buf=%s\n", __LINE__, buf);

			char mac[32] = {0};
			client_ip_str = inet_ntoa(client_addr.sin_addr);			
			get_user_mac_by_ip(client_ip_str, mac, sizeof(mac) - 1);

			if(strncasecmp(buf, "GET ", 4) == 0
				|| strncasecmp(buf, "POST ", 5) == 0
				|| strncasecmp(buf, "HEAD ", 5) == 0){printf("%d\n", __LINE__);

				memset(&buf,0,sizeof(buf));
				sprintf(buf, "HTTP/1.1 302 Moved Temporarily\r\n"
							"Server: %s\r\n"
							"Content-Type: text/html\r\n"
							"Connection: keep-alive\r\n"
							"Location: http://portal-router.test.pengwifi.com/Auth?wlanuserip=%s&wlanacname=60.106.36.144&wlanapmac=%s&wlanusermac=%s&ssid=pengwifi\r\n"
							"\r\n", "pengwifi", client_ip_str, "525400B5C696", mac);
				write(client_sock, buf, strlen(buf));
				close(client_sock);
				close(server_sock);
			}
			exit(0);
		}else{i++;}
		close(client_sock);
	}

	close(server_sock);

	return 0;
}

