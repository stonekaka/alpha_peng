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
#include "util.h"

#define LOG_INFO printf


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

void *pthread_probe(void *arg);
int set_probe_enable(int flag);

#endif

