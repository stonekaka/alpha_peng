/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     probe.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-12-17 11:19
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
#include "main.h"

#define NETLINK_QCAWIFI 27
#define MAX_PAYLOAD 1024 // maximum payload size

extern struct probe_config g_conf;
int g_nlpid = 0;
int sock_fd = 0;

struct sta_msg {
	unsigned char mac[6];
	char ssid[64];
	int channel;
	int rssi;
	int noisefloor;
};

int parse_wifi_probe_msg(void *data)
{
	unsigned char mac[6] = {0};
	char ssid[64] = {0};
	int len = 0;
	int len_ssid = 0;
	struct sta_msg sta;

	if(!data)
		return -1;
	
	/*|<-   mac  ->|<-  ssid ->|*/
	/*[xxxxxxxxxxxx][ssid......]*/
	//len = strlen(data);
	//len_ssid = len - sizeof(mac);

	/*memcpy(mac, data, sizeof(mac));
	memcpy(ssid, data + sizeof(mac), len_ssid > sizeof(ssid)?sizeof(ssid):len_ssid);
	printf("%02x:%02x:%02x:%02x:%02x:%02x, %s\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], ssid);*/
	//printf("data=%s.\n", data);
	memset(&sta, 0, sizeof(struct sta_msg));
	memcpy(&sta, data, sizeof(struct sta_msg));
	printf("%02x:%02x:%02x:%02x:%02x:%02x, %s  chn=%d  rssi=%d noise=%d\n", 
			sta.mac[0],sta.mac[1],sta.mac[2],sta.mac[3],sta.mac[4],sta.mac[5],
			sta.ssid, sta.channel, sta.rssi, sta.noisefloor
			);
	
	return 0;
}

void *pthread_probe(void *arg)
{
    int state;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int retval;
    int state_smg = 0;
	int nl_type;

	nl_type = NETLINK_QCAWIFI;

    // Create a socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, nl_type);
    if(sock_fd == -1){
        printf("error getting socket: %s", strerror(errno));
        return NULL;
    }

    // To prepare binding
    memset(&msg,0,sizeof(msg));
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // self pid
    src_addr.nl_groups = 0; // multi cast

    retval = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(retval < 0){
        printf("bind failed: %s", strerror(errno));
        close(sock_fd);
        return NULL;
    }

    // To prepare recvmsg

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh){
        printf("malloc nlmsghdr error!\n");
        close(sock_fd);
        return NULL;
    }

    memset(&dest_addr,0,sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid(); // self pid
	g_nlpid = nlh->nlmsg_pid;
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh),"Hello you!");

    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    // iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
   
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("state_smg\n");
    state_smg = sendmsg(sock_fd,&msg,0);

    if(state_smg == -1)
    {
        printf("get error sendmsg = %s\n",strerror(errno));
    }

    memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
    printf("waiting received!\n");
    // Read message from kernel

    while(1){
		if(!g_conf.enable){
			set_probe_enable(0);
			sleep(10);
			continue;
		}else{
			set_probe_enable(1);
		}

        //printf("In while recvmsg\n");
        state = recvmsg(sock_fd, &msg, 0);
        if(state<0)
        {
            printf("state<1");
        }
        //printf("In while\n");
        //printf("[USER] Received message: %s\n",(char *) NLMSG_DATA(nlh));
		if(NETLINK_QCAWIFI == nl_type){
			parse_wifi_probe_msg((void *) NLMSG_DATA(nlh));
		}else{
			printf("Error: nl_type error: %d.\n", nl_type);
		}
    }
    close(sock_fd);

    return 0;
}

