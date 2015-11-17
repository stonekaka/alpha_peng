/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     list.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-09 15:47
***************************************************************************/

#include "main.h"
#include "list.h"

int g_msg_seq = 0;
int g_msg_seq_r = 0;

msgdata *list_add_end(msgdata **_head, msgdata *node)
{
	msgdata *phead;
	msgdata *head = *_head;

	if(NULL == node){
		LOG_INFO("%s: input error\n", __FUNCTION__);
		*_head = head;
		return head;
	}

	if(NULL == head){
		head = node;
		*_head = head;
		return head;
	}

	phead = head;
	while(phead->next != NULL){
		phead = phead->next;
	}
	phead->next = node;

	*_head = head;
	return head;
}

int list_length(msgdata *head)
{
	int length = 0;
	msgdata *phead;

	phead = head;
	while(phead){
		phead = phead->next;
		length++;
	}

	return length;
}

msgdata *make_node(char *msg, int msg_len)
{
	msgdata *node;

	node = (msgdata *)malloc(sizeof(msgdata));
	if(NULL == node)
	{
		LOG_INFO("%s:malloc failed\n", __FUNCTION__);
		return NULL;
	}

	memset(node, 0, sizeof(msgdata));

	memcpy(node->msg, msg, sizeof(node->msg)>msg_len?msg_len:sizeof(node->msg));
	node->consumed = 0;
	node->trys = 0;
	node->key = g_msg_seq++;
	node->next = NULL;

	if(g_msg_seq >= 1 << 16){
		g_msg_seq = 0;
	}

	return node;
}

msgdata *free_node(msgdata **_head, int key)
{
	msgdata *node, *phead;
	msgdata *head = *_head;
	node = head;
	phead = head;

	while(phead){
		if(key == head->key){
			node = head->next;
			free(head);
			head = NULL;
			head = node;
			if(head != NULL){
				*_head = head;
				return head;
			}else{
				return NULL;
			}
		}
		if(key == phead->key){
			node->next = phead->next;
			free(phead);
			phead = NULL;
			return head;
		}else{
			node = phead;
			phead = phead->next;
		}
	}

	return NULL;
}

msgdata *free_all_consumed_node(msgdata **_head)
{
	msgdata *node, *phead;

	node = *_head;
	phead = *_head;

	while(phead){
		if((phead != *_head) && (1 == phead->consumed)){ //free all but head
			node->next = phead->next;
			free(phead);
			phead = NULL;
		}else{
			node = phead;
			phead = phead->next;
		}
	}

	return NULL;
}

msgdata *consume_all_node(msgdata **_head)
{
	msgdata *node, *phead;

	node = *_head;
	phead = *_head;

	while(phead){
		phead->consumed = 1;
		phead = phead->next;
	}

	return NULL;
}

