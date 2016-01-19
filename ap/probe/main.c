/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     enable.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-12-17 12:10
***************************************************************************/
#include <pthread.h>
#include "main.h"

int g_pthread_init = 0;
struct probe_config g_conf;
unsigned char g_apmac[6];
pthread_rwlock_t g_lock;

int pthread_init(void)
{
	pthread_t pid_probe;
	pthread_attr_t attr;
	size_t stacksize;
	int ret = 0;

	pthread_attr_init(&attr);
	stacksize = (double) 300*1024;
	
	ret = pthread_attr_setstacksize (&attr, stacksize);
	if (ret != 0) {
		LOG_INFO("pthread_attr: error\n");
	}
	
	pthread_create(&pid_probe, &attr, pthread_probe, NULL);
	pthread_detach(pid_probe);

	g_pthread_init = 1;

	return 0;
}

int get_probe_conf(void)
{
	int ret = 0;
	int n = 0;
	FILE *fp = NULL;
	char buf[128] = {0};

	fp = fopen("/tmp/pwf_probe", "r");
	if(NULL == fp){
		//LOG_INFO("fopen error.\n");
		return -1;
	}else{
		LOG_INFO("probe: read config ok.\n");
	}
	
	/*enable=1 server=1.1.1.1 port=8084 interval=0*/
	if(fgets(buf, sizeof(buf) - 1, fp)){

		fclose(fp);
		clear_crlf(buf);

		memset(&g_conf, 0, sizeof(struct probe_config));

		n = sscanf(buf, "enable=%d server=%s port=%d interval=%d", 
					&g_conf.enable, g_conf.server, &g_conf.port, &g_conf.interval);
		LOG_INFO("n=%d; enable=%d, server=%s, port=%d, interval=%d\n", 
					n, g_conf.enable, g_conf.server, g_conf.port, g_conf.interval);
	}else{
		LOG_INFO("fgets error\n");
	}

    if(0 == strcmp("0.0.0.0", g_conf.server) || strlen(g_conf.server) == 0){
        snprintf(g_conf.server, sizeof(g_conf.server) - 1, "%s",  DEFAULT_SERVER);
    }

    if(g_conf.port <= 0 || g_conf.port >= 65535){
        g_conf.port = DEFAULT_PORT;
    }

	return 0;
}

int get_ap_mac(unsigned char *ret_mac, int len)
{
	char *cmd = "ifconfig br0 | grep HWaddr |awk '{print $5}' | tr '[A-Z]' '[a-z]'";
	FILE *fp = NULL;
    char mac[24]={0};
    int ret = 0;

	fp = popen(cmd, "r");
	if(fp){
		fgets(mac, sizeof(mac)-1, fp);
		clear_crlf(mac);
        ascii2mac(mac, ret_mac);
        if(strlen(mac) < strlen("xx:xx:xx:xx:xx:xx")){
            ret = -1;
        }
	}else{
		return -1;
	}

	pclose(fp);
	return ret;
}

int main(void)
{
	int interval = 0;
	
	if(get_ap_mac(g_apmac, sizeof(g_apmac))){
#if 1	
	    unsigned char mmac[6] = {1,1,1,1,1,1};
	    memcpy(g_apmac, mmac, 6);
#endif	
    }

    if (pthread_rwlock_init(&g_lock, NULL) != 0) {
        printf("0 can't create rwlock");
        return -1;
    }

	while(1){
		//LOG_INFO("main loop\n");
		if(0 == g_pthread_init){
			pthread_init();
		}

		get_probe_conf();

		interval = 10;
		if(g_conf.interval >= 3 && g_conf.interval <= 72 * 3600){
			interval = g_conf.interval;
		}
	
		if(!g_conf.enable){
			
			sleep(interval);
			continue;
		}
	
        upload_mu();

		sleep(interval);
	}

	return 0;
}

