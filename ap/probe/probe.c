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

int parse_wifi_probe_msg(void *data)
{
	unsigned char mac[6] = {0};
	char ssid[64] = {0};
	int len = 0;
	int len_ssid = 0;
	struct sta_msg sta;

	if(!data)
		return -1;
	
	memset(&sta, 0, sizeof(struct sta_msg));
	memcpy(&sta, data, sizeof(struct sta_msg));

    sta.rssi -= 95;
    if(sta.noisefloor > 128 || sta.noisefloor < -127){
        sta.noisefloor = -95;
    }

    switch (sta.channel){
        case 2412:
            sta.channel = 1;
            break;
        case 2417:
            sta.channel = 2;
            break;
        case 2422:
            sta.channel = 3;
            break;
        case 2427:
            sta.channel = 4;
            break;
        case 2432:
            sta.channel = 5;
            break;
        case 2437:
            sta.channel = 6;
            break;
        case 2442:
            sta.channel = 7;
            break;
        case 2447:
            sta.channel = 8;
            break;
        case 2452:
            sta.channel = 9;
            break;
        case 2457:
            sta.channel = 10;
            break;
        case 2462:
            sta.channel = 11;
            break;
        case 2467:
            sta.channel = 12;
            break;
        case 2472:
            sta.channel = 13;
            break;
        default:
            break;
    }
	/*printf("%02x:%02x:%02x:%02x:%02x:%02x, %s  chn=%d  rssi=%d noise=%d\n", 
			sta.mac[0],sta.mac[1],sta.mac[2],sta.mac[3],sta.mac[4],sta.mac[5],
			sta.ssid, sta.channel, sta.rssi, sta.noisefloor
			);*/
	add_mu(sta, 0);
	
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
	int flag_enable = 0;
	int flag_disable = 0;

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
			flag_disable++;
			if(flag_disable <= 1){
				set_probe_enable(0);
				flag_enable = 0;
			}
			sleep(10);
			continue;
		}else{
			flag_enable++;
			if(flag_enable <= 1){
				set_probe_enable(1);
				flag_disable = 0;
			}
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

