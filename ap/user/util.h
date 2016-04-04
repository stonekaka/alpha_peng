/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     util.h
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-11-04 10:46
***************************************************************************/

#ifndef __UTIL_H__
#define __UTIL_H__

int get_wan_mac(char *mac, int len);
int get_wan_ip(char *ip, int len);

int ascii2mac(const char *addr, unsigned char *res);
int ascii2mac_nocol(const char *addr, unsigned char *res);
void clear_crlf(char *str);
int get_uptime(int *uptime);
int get_sys_load(char *loadavg, int len);
int get_cpu_usage(int *cpu_use);
int get_mem_free(int *memfree);
int get_mem_use_rate(int *rate);
int get_soft_version(char *ver, int len);
int get_hash_by_mac(const char *addr, unsigned int *hash);
void init_daemon(void);
int get_string_from_cmd(char *result, int len, char *cmd);
int get_int_from_cmd(int *result, char *cmd);
int get_uci_opt_value(char *filename, char *section, char *option, char *value, int val_len);

#endif

