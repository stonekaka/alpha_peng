/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     sta.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-09-25 18:29
***************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>

#define FILE_LOG  "/var/log/dm.log"
#define LOG_MAX_SIZE  500000 
int log_level = 5;

FILE *g_log_fp;

int dm_open_log(void)
{
	g_log_fp = fopen(FILE_LOG, "a+");
	if(g_log_fp == NULL){
		fprintf(stderr, "open %s error.\n", FILE_LOG);
		return -1;
	}

	return 0;
}

void dm_close_log(void)
{
	if(g_log_fp){
		fclose(g_log_fp);
	}
}

int size_check(void)
{
	struct stat buf;

	if(0 == fstat(fileno(g_log_fp), &buf)){
		if(buf.st_size <= LOG_MAX_SIZE){
			return 0;
		}else{
			return 1;	
		}
	}else{
		return -1;
	}

	return 0;	
}

void
dm_log_message(int priority, const char *format, ...)
{
	va_list vl;
	time_t timep;
	char tm[48] = {0};
	
	if (priority > log_level)
		return;

	if(size_check() == 1){
		fprintf(stderr, "log size reach max.\n");
		ftruncate(fileno(g_log_fp), 0);					
	}

	va_start(vl, format);

	time(&timep);
	//fprintf(g_log_fp, "%s ", asctime(gmtime(&timep)));
	snprintf(tm, sizeof(tm) - 1, "%s", asctime(localtime(&timep)));
	if(tm[0]){
		tm[strlen(tm) - 1] = '\0';
	}
	fputs(tm, g_log_fp);
	fputs(" ", g_log_fp);

//	if (use_syslog)
//		vsyslog(log_class[priority], format, vl);
//	else
		vfprintf(g_log_fp, format, vl);
	va_end(vl);

	fflush(g_log_fp);
}

/*int main(void)
{
	dm_open_log();	
	dm_log_message(1, "log is %s\n", "aaa");
	dm_close_log();

	return 0;
}*/


