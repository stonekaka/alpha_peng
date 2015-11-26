/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     nl.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-12 10:50
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include "list.h"
#include "main.h"
#include "pub.h"

#define NETLINK_TEST 22
#define NETLINK_QCAWIFI 23
#define NETLINK_PENGWIFI 25
//#define NETLINK_TEST NETLINK_GENERIC
#define MAX_PAYLOAD 2048 // maximum payload size

extern int g_state;
extern int g_connection_flag;
extern char g_ap_label_mac[];

static int nlpid;

struct __nl_sock_fd{
	int fd;
	bool ready;
}nl_sock_fd;


int create_nl_msg(struct msghdr *msg, struct iovec *iov, struct sockaddr_nl *dest_addr, void *msg_body, int msg_body_len)
{
    struct nlmsghdr *nlh = NULL;

	if(!msg || !iov || !dest_addr){
		LOG_INFO("Error: arg null!!\n");
		return -1;
	}

    memset(dest_addr,0,sizeof(struct sockaddr_nl));
    dest_addr->nl_family = AF_NETLINK;
    dest_addr->nl_pid = 0;
    dest_addr->nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh){
        LOG_INFO("malloc nlmsghdr error!\n");
        //close(sock_fd);
        return -1;
    }
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = nlpid; // self pid
    nlh->nlmsg_flags = 0;
	if(msg_body_len > 0 && msg_body){
    	memcpy(NLMSG_DATA(nlh), msg_body, msg_body_len > MAX_PAYLOAD?MAX_PAYLOAD:msg_body_len);
	}

    iov->iov_base = (void *)nlh;
    iov->iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    // iov.iov_len = nlh->nlmsg_len;

    memset(msg, 0, sizeof(struct msghdr));
   
    msg->msg_name = (void *)&(*dest_addr);
    msg->msg_namelen = sizeof(struct sockaddr_nl);
    msg->msg_iov = &(*iov);
    msg->msg_iovlen = 1;

	return 0;
}

void free_nl_msg(const struct iovec *iov)
{
	if(iov->iov_base){
		free(iov->iov_base);
	}
}

int send_nl_msg(struct msg_to_ker *msg_body, int msg_body_len)
{
	int ret = 0;
    struct msghdr msg;
    struct sockaddr_nl dest_addr;
    struct iovec iov;

	if(msg_body_len > MAX_PAYLOAD){
		LOG_INFO("Error: msg too long, max=%d, input=%d\n", MAX_PAYLOAD, msg_body_len);
		return -1;
	}
	if(!msg_body || !msg_body_len){
		LOG_INFO("Error: msg input error.\n");
		return -1;
	}

	if(!nl_sock_fd.ready){
		LOG_INFO("Error: sock not ready\n");
		return -1;
	}

	if(create_nl_msg(&msg, &iov, &dest_addr, msg_body, msg_body_len) < 0){
		LOG_INFO("Error: create_nl_msg\n");
		return -1;
	}
	//strncpy(NLMSG_DATA((struct nlmsghdr *)(iov.iov_base)), msg_body, msg_body_len > MAX_PAYLOAD?MAX_PAYLOAD:msg_body_len);
    ret = sendmsg(nl_sock_fd.fd,&msg,0);
	if(ret < 0){
		LOG_INFO("Error; sendmsg failed.\n");
	}

	free_nl_msg(&iov);

	return ret;
}

int set_ap_online(int flag)
{
	struct msg_to_ker *m = NULL;
    int state_smg = 0;
	int len = 0;

	if(!nl_sock_fd.ready){
		LOG_INFO("Error: sock not ready\n");
		return -1;
	}

	len = sizeof(struct msg_to_ker) + sizeof(int);
	m = (struct msg_to_ker *)malloc(len);
	if(!m){
		LOG_INFO("Error: %s malloc failed.\n", __FUNCTION__);
		return NULL;
	}
	m->type = M2K_APONLINE;
	m->len = sizeof(int);
	memcpy(m->value, &flag, sizeof(int));
   	state_smg = send_nl_msg(m, len);

	free(m);
	LOG_INFO("/*************/\nset ap online to %d.\n/*************/\n", flag);
   	if(state_smg == -1)
   	{
       	LOG_INFO("set ap online get error sendmsg = %s\n",strerror(errno));
	}
	return state_smg;
}

void *pthread_netlink(void *arg)
{
    int state;
    struct sockaddr_nl src_addr;
    struct msghdr msg;
    int retval;
	int nlret = 0;
	int nl_type;
    struct iovec iov;
    struct sockaddr_nl dest_addr;

	LOG_INFO("%s start\n", __FUNCTION__);
	
	nl_type = NETLINK_PENGWIFI;

    // Create a socket
    nl_sock_fd.fd = socket(AF_NETLINK, SOCK_RAW, nl_type);
    if(nl_sock_fd.fd == -1){
        LOG_INFO("error getting socket: %s", strerror(errno));
        return NULL;
    }
	
    nlpid = getpid();

    // To prepare binding
    memset(&msg,0,sizeof(msg));
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = nlpid; // self pid
    src_addr.nl_groups = 0; // multi cast

    retval = bind(nl_sock_fd.fd, (struct sockaddr*)&src_addr, sizeof(src_addr));printf("========pid=%d\n",src_addr.nl_pid);
    if(retval < 0){
        LOG_INFO("bind failed: %s", strerror(errno));
        close(nl_sock_fd.fd);
        return NULL;
    }else{
        LOG_INFO("nl sock bind success.\n");
		nl_sock_fd.ready = true;
	}

	while(1){
		usleep(1000*200);
		if(!(AP_RUNNING == g_state && 1 == g_connection_flag))
			continue;

		nlret = set_ap_online(1);
    	if(nlret == -1)
    	{
        	LOG_INFO("get error sendmsg = %s\n",strerror(errno));
    	}else{
			break;//send running flag to kernel success
		}
		sleep(10);
	}
#if 0
    // To prepare recvmsg
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh){
        printf("malloc nlmsghdr error!\n");
        //close(sock_fd);
        return ;
    }
    memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
#endif
	create_nl_msg(&msg, &iov, &dest_addr, NULL, 0);	
    LOG_INFO("waiting received!\n");
    // Read message from kernel

    while(1){
        //printf("In while recvmsg\n");
        state = recvmsg(nl_sock_fd.fd, &msg, 0);
        if(state<0)
        {
            LOG_INFO("state<1");
        }
        //printf("In while\n");
        //printf("[USER] Received message: %s\n",(char *) NLMSG_DATA((struct nlmsghdr *)(msg.msg_iov->iov_base)));
		
		if(!(AP_RUNNING == g_state && 1 == g_connection_flag))
			continue;

        if(NETLINK_PENGWIFI == nl_type){
        	char *p = (char *)NLMSG_DATA(msg.msg_iov->iov_base);
        	if(p){
				struct msg_to_ker *m = NULL;
				char msg[256] = {0};
				struct sta_ctl sc;
				struct in_addr in;
				char s[32] = {0}, ssid[64] = {0}, staid[16] = {0}, tmp_mac[32] = {0}, portal[128]={0};
				int len = 0;
				
        		LOG_INFO("parse kernel msg\n");
				len = sizeof(struct msg_to_ker) + sizeof(struct sta_ctl);
				m = (struct msg_to_ker *)malloc(len);
				memcpy(m, p, len);
				memset(&in, 0, sizeof(struct in_addr));
				memcpy(&sc, m->value, m->len);
				in.s_addr = sc.ipaddr;
				if(STA_INIT == sc.action){
					strcpy(s, "init");
				}else if(STA_TIMEOUT == sc.action){
					strcpy(s, "idle_timeout");
				}

				snprintf(tmp_mac, sizeof(tmp_mac) - 1, "%02x:%02x:%02x:%02x:%02x:%02x", 
					sc.mac[0], sc.mac[1], sc.mac[2], sc.mac[3], sc.mac[4], sc.mac[5]);
				get_staid_by_mac(staid, sizeof(staid)-1, tmp_mac);
				get_ssid_portal_by_dev(ssid, sizeof(ssid), portal, sizeof(portal), sc.ifname);
				if(!ssid[0]){
					snprintf(ssid, sizeof(ssid)-1, "%s", sc.ifname);
				}
				snprintf(msg, sizeof(msg)-1, 
				          "{\"type\":\"sta_control\",\"subtype\":\"upstream\","
				          "\"data\":{\"apmac\":\"%s\",\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ip\":\"%s\","
						  "\"ssid\":\"%s\",\"staid\":\"%s\",\"state\":\"%s\"}}", 
						  g_ap_label_mac,
				          sc.mac[0], sc.mac[1], sc.mac[2], sc.mac[3], sc.mac[4], sc.mac[5],
				          inet_ntoa(in), ssid, staid, s);LOG_INFO("mmm=%s\n", msg);
				enqueue_msg(msg);
				/*msgdata *node = make_node(msg, strlen(msg));
				pthread_mutex_lock(&mutex);
				list_add_end(&list_head_send, node);
				printf("produce: key=%d. msg=%s. total len=%d\n", node->key, node->msg,list_length(list_head_send));
				pthread_mutex_unlock(&mutex);*/
				if(list_length(list_head_send) > 100)sleep(3);
				/*char *iii = "{\"type\":\"sta_control\",\"subtype\":\"downstream\",\"data\":{\"mac\":\"c8:1f:66:21:1a:53\",\"action\":\"access_allow\",\"msg\":\"Welcome!\",\"staIP\":\"83.26.62.174\"}}";
				enqueue_r_msg(iii);*/
			} else {
				LOG_INFO("%s: get null\n", __FUNCTION__);
			}
		}else if(NETLINK_QCAWIFI == nl_type){

		}
    }

    close(nl_sock_fd.fd);
	nl_sock_fd.ready = false;
	free_nl_msg(&iov);

    return NULL;
}

