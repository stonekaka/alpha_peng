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
#include <stdbool.h>

#include "main.h"

#define NETLINK_PROBE 27
//#define NETLINK_TEST NETLINK_GENERIC
#define MAX_PAYLOAD 2048 // maximum payload size

extern int g_nlpid;
extern int sock_fd;

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
    nlh->nlmsg_pid = g_nlpid; // self pid
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

	/*if(!nl_sock_fd.ready){
		LOG_INFO("Error: sock not ready\n");
		return -1;
	}*/

	if(create_nl_msg(&msg, &iov, &dest_addr, msg_body, msg_body_len) < 0){
		LOG_INFO("Error: create_nl_msg\n");
		return -1;
	}
	//strncpy(NLMSG_DATA((struct nlmsghdr *)(iov.iov_base)), msg_body, msg_body_len > MAX_PAYLOAD?MAX_PAYLOAD:msg_body_len);
    ret = sendmsg(sock_fd,&msg,0);
	if(ret < 0){
		LOG_INFO("Error; sendmsg failed.\n");
	}

	free_nl_msg(&iov);

	return ret;
}

int set_probe_enable(int flag)
{
	struct msg_to_ker *m = NULL;
    int state_smg = 0;
	int len = 0;

	/*if(!nl_sock_fd.ready){
		LOG_INFO("Error: sock not ready\n");
		return -1;
	}*/

	len = sizeof(struct msg_to_ker) + sizeof(int);
	m = (struct msg_to_ker *)malloc(len);
	if(!m){
		LOG_INFO("Error: %s malloc failed.\n", __FUNCTION__);
		return -1;
	}
	m->type = M2K_PROBE_ENABLE;
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

/*
int create_nl(void)
{
    struct sockaddr_nl src_addr;
    int retval;
	int nl_type;
    struct iovec iov;
    struct sockaddr_nl dest_addr;

	nl_type = NETLINK_PROBE;
    nlpid = getpid();

    // Create a socket
    nl_sock_fd.fd = socket(AF_NETLINK, SOCK_RAW, nl_type);
    if(nl_sock_fd.fd == -1){
        LOG_INFO("error getting socket: %s", strerror(errno));
        return -1;
    }

    // To prepare binding
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = nlpid; // self pid
    src_addr.nl_groups = 0; // multi cast

    retval = bind(nl_sock_fd.fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(retval < 0){
        LOG_INFO("bind failed: %s", strerror(errno));
        close(nl_sock_fd.fd);
        return -1;
    }else{
        LOG_INFO("nl sock bind success.\n");
		nl_sock_fd.ready = true;
	}

	return 0;
}
*/

