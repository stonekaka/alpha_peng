/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     main.h
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-12-17 13:56
***************************************************************************/

#ifndef __MAIN_H__
#define __MAIN_H__
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include "util.h"
#include "uthash.h"

#define DEFAULT_SERVER "118.144.162.15"
#define DEFAULT_PORT 8488

#define LOG_INFO printf

#define MAX_WLAN_COUNT 6

/*msg to kernel*/
struct msg_to_ker{
	int type;
	int len;
	char value[0];	
};

enum _msg_to_ker_type{
	M2K_PROBE_ENABLE,
};

struct probe_config {
	int enable;
	char server[64];
	int port;
	int interval;
};

struct sta_msg {
	unsigned char mac[6];
	char ssid[64];
	int channel;
	int rssi;
	int noisefloor;
};

void *pthread_probe(void *arg);
int set_probe_enable(int flag);
int add_mu(struct sta_msg sta, int is_associate);
int upload_mu(void);
int send_udp_data(void *data, int len, char *server, int port);

#endif

