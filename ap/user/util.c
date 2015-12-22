/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     util.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-14 16:18
***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>

int ascii2mac(const char *addr, unsigned char *res)
{
	int ret = 0;
	unsigned int conv[6];
	ret = sscanf(addr, "%x:%x:%x:%x:%x:%x",
				&conv[0], &conv[1], &conv[2], &conv[3], &conv[4],
				&conv[5]);

	if (ret != 6)
		return -1;

	/* convert from unsigned int to unsigned char */
	res[0] = (unsigned char)conv[0];
	res[1] = (unsigned char)conv[1];
	res[2] = (unsigned char)conv[2];
	res[3] = (unsigned char)conv[3];
	res[4] = (unsigned char)conv[4];
	res[5] = (unsigned char)conv[5];

	return 0;
}

int ascii2mac_nocol(const char *addr, unsigned char *res)
{
	int ret = 0;
	unsigned int conv[6];
	ret = sscanf(addr, "%02x%02x%02x%02x%02x%02x",
				&conv[0], &conv[1], &conv[2], &conv[3], &conv[4],
				&conv[5]);

	if (ret != 6)
		return -1;

	/* convert from unsigned int to unsigned char */
	res[0] = (unsigned char)conv[0];
	res[1] = (unsigned char)conv[1];
	res[2] = (unsigned char)conv[2];
	res[3] = (unsigned char)conv[3];
	res[4] = (unsigned char)conv[4];
	res[5] = (unsigned char)conv[5];

	return 0;
}

int is_big_endian(void)
{
	union u
	{
		int a;
		char b;
	}c;
	
	c.a = 1;

	return (c.b != 1);
}

int get_hash_by_mac(const char *addr, unsigned int *hash)
{
	int ret = -1;
	union un{
		int a;
		unsigned char b[4];
	}u;
	unsigned char mac[6] = {0};

	if(!addr){
		printf("%s: arg error.\n", __FUNCTION__);
		return -1;
	}
	
	u.a = 0;
	
	if(strchr(addr, ':')){
		ret = ascii2mac(addr, mac);
	}else{
		ret = ascii2mac_nocol(addr, mac);
	}

	if(0 == ret){
		memcpy(u.b, mac + 2, 4);
		u.b[0] = u.b[0] ^ mac[0];
		u.b[1] = u.b[1] ^ mac[1];
		if(is_big_endian()){
			//printf("is big endian\n");
			/*to get same result with AC*/
			unsigned char p;
			
			p = u.b[0];
			u.b[0] = u.b[3];
			u.b[3] = p;
			p = u.b[1];
			u.b[1] = u.b[2];
			u.b[2] = p;
		
			*hash = htonl(u.a);	
		}else{
			//printf("is little endian\n");
			*hash = htonl(u.a);
		}
	}

	return 0;
}

void clear_crlf(char *str)
{
	if(!str)
		return;
	
	while(*str++ != '\0'){
		if(*str == '\n')
			*str ='\0';
	}

	return;
}

int get_int_from_cmd(int *result, char *cmd)
{
	char buf[32] = {0};
	FILE *fp = NULL;
	
	if(!result || !cmd){
		printf("%s: input error.\n", __FUNCTION__);
		return -1;
	}

	fp = popen(cmd, "r");
	if(fp){
		fgets(buf, sizeof(buf)-1, fp);
		clear_crlf(buf);
		*result = atoi(buf);
	}else{
		printf("%s: exec error.\n", __FUNCTION__);
		return -1;
	}

	pclose(fp);

	return 0;
}

int get_string_from_cmd(char *result, int len, char *cmd)
{
	FILE *fp = NULL;
	
	if(!result || !cmd){
		printf("%s: input error.\n", __FUNCTION__);
		return -1;
	}

	fp = popen(cmd, "r");
	if(fp){
		fgets(result, len, fp);
		clear_crlf(result);
	}else{
		printf("%s: exec error.\n", __FUNCTION__);
		return -1;
	}

	pclose(fp);

	return 0;
}

int get_uptime(int *uptime)
{
	return get_int_from_cmd(uptime, "cat /proc/uptime | awk -F. '{print $1}'");
}

int get_sys_load(char *loadavg, int len)
{
	return get_string_from_cmd(loadavg, len, "cat /proc/loadavg | awk '{print $1}'");
}

int get_mem_free(int *memfree)
{
	return get_int_from_cmd(memfree, "free | grep Mem | awk '{print $4}'");
}

int get_mem_use_rate(int *rate)
{
	int total, free;
	
	get_int_from_cmd(&total, "free | grep Mem | awk '{print $2}'");
	get_int_from_cmd(&free, "free | grep Mem | awk '{print $4}'");

	*rate = 100 * (total - free)/total;

	return 0;
}

int get_cpu_usage(int *cpu_use)
{
	*cpu_use = 0;
	return 0;
}

void init_daemon(void)
{
	int pid;
	int i;

	if(0 != (pid=fork()))
		exit(0);
	else if(pid < 0)
		exit(1);

	setsid();

	if(0 != (pid=fork()))
		exit(0);
	else if(pid < 0)
		exit(1);

	for(i = 0; i < 3; ++i)
		close(i);
	chdir("/tmp");
	umask(0);

	return;
}

int get_file_md5(char *filename, char *md5, int len)
{
	unsigned char c[MD5_DIGEST_LENGTH];
	int i, j = 0;
	FILE *fp = NULL;
	MD5_CTX mdContext;
	int bytes;
	unsigned char data[1024];
	char tmp[8] = {0};

	if(!filename || !md5 || len <= 0){
		printf("%s: arg error\n", __FUNCTION__);
		return -1;
	}

	fp = fopen(filename, "rb");
	if(NULL == fp){
		printf("%s:fopen error.\n", __FUNCTION__);
		return -1;
	}
	
	MD5_Init(&mdContext);
	while ((bytes = fread (data, 1, 1024, fp)) != 0)
		MD5_Update (&mdContext, data, bytes);
	MD5_Final (c,&mdContext);
	//printf("\n");
	//for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", c[i]);
	//printf("\n");

	fclose(fp);
	
	for(i = 0; i < MD5_DIGEST_LENGTH; i++){
		memset(tmp, 0, sizeof(tmp));
		snprintf(tmp, sizeof(tmp) - 1, "%02x", c[i]);
		strcat(md5, tmp);
	}

	return 0;
}

