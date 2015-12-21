/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     udp.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-12-18 15:06
***************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

int send_udp_data(void *data, int len, char *server, int port)
{
    int ret = 0;
    int fd = -1;
    struct hostent *hp;
    struct sockaddr_in servaddr;
    struct in_addr in;

    if(!data || 0 == len){
        printf("arg error.\n");
        return -1;
    }

    printf("send [%d] data to  [%s]:[%d]\n", len, server, port);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("cannot create socket");
        return -1;
    }

    memset((char*)&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    hp = gethostbyname(server);
    if (!hp) {
        fprintf(stderr, "could not obtain address of %s\n", server);
        inet_aton(server, &in);
        servaddr.sin_addr.s_addr = in.s_addr;
    }else{
        memcpy((void *)&servaddr.sin_addr, hp->h_addr_list[0], hp->h_length);
    }

    if (sendto(fd, data, len, 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("sendto failed");
        return 0;
    }else{
        printf("send success.\n");
    }
    
    close(fd);

    return ret;
}

