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
		LOG_INFO("fopen error.\n");
		return -1;
	}
	
	/*enable=1, server=1.1.1.1, port=8084*/
	fgets(buf, sizeof(buf) - 1, fp);

	fclose(fp);
	clear_crlf(buf);

	memset(&g_conf, 0, sizeof(struct probe_config));

	n = sscanf(buf, "enable=%d, server=%s, port=%d, interval=%d", 
					&g_conf.enable, g_conf.server, &g_conf.port, &g_conf.interval);
	LOG_INFO("n=%d; enable=%d, server=%s, port=%d, interval=%d", 
					n, g_conf.enable, g_conf.server, g_conf.port, g_conf.interval);

	if(n == 3) {
		ret = g_conf.enable;
	}

	return ret;
}

int main(void)
{
	int interval = 0;
		
	while(1){
		LOG_INFO("main loop\n");
		if(0 == g_pthread_init){
			pthread_init();
		}

		get_probe_conf();

		interval = g_conf.interval?g_conf.interval:10;
	
		if(!g_conf.enable){
			
			sleep(interval);
			continue;
		}
	
		sleep(interval);
	}

	return 0;
}

