/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     list.h
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-09 15:50
***************************************************************************/

#ifndef __LIST_H__
#define __LIST_H__

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

typedef struct _msgdata{
	char msg[4096];
	int consumed;
	int trys;
#define MSGDATA_MAX_TRYS 3
	int key;
	struct _msgdata *next;
}msgdata;

msgdata *list_head_send;
msgdata *list_head_recv;

msgdata *list_add_end(msgdata **h_ead, msgdata *node);
int list_length(msgdata *head);

msgdata *make_node(char *msg, int msg_len);
msgdata *free_all_consumed_node(msgdata **_head);
msgdata *consume_all_node(msgdata **_head);

#endif

