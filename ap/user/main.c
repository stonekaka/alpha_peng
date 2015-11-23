/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     test-client.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-10-08 17:30
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "cJSON.h"
#include "lws_config.h"
#include "libwebsockets.h"
#include "list.h"
#include "main.h"
#include "pub.h"

static unsigned int opts;
static int was_closed;
static int deny_deflate;
static int deny_mux;
static struct libwebsocket *g_wsi;
static volatile int force_exit = 0;
static int longlived = 0;

int g_pthread_init = 0;
extern FILE *g_log_fp;

int g_state;
int g_connection_flag = 0;
int g_idle_cnt = 3;
#define WS_SERVICE_INTERVAL  50 //ms

int g_heartbeat_flag = 0;
#define MAX_HEARTBEAT_TRYS 3
#define HEARTBEAT_INTERVAL   30 //seconds

char *g_acname;
char *g_test_acname;
char *g_acpath;
int g_acport;

char g_ap_label_mac[32] = {0};
char g_ap_label_mac_nocol[32] = {0};
struct ssid_dev **g_ssid_dev;
/*struct ssid_dev g_ssid_dev[MAX_WLAN_COUNT]={
	{.dev="ra0", .portal_url="http://portal-router.test.pengwifi.com/Auth?"},
	{.dev="ra1", .portal_url="http://portal-router.test.pengwifi.com/Auth?"},
	{.dev="ra2", .portal_url="http://portal-router.test.pengwifi.com/Auth?"},
	{.dev="ra3", .portal_url="http://portal-router.test.pengwifi.com/Auth?"},
	{.dev="ra4", .portal_url="http://portal-router.test.pengwifi.com/Auth?"},
	{.dev="ra5", .portal_url="http://portal-router.test.pengwifi.com/Auth?"},
	};
*/

char *str_ap_state[] = {"","AP_IDLE","AP_DISCOVERY","AP_JOIN_S1","AP_JOIN_S2","AP_JOIN_S3","AP_JOIN_S4",
	"AP_JOIN_OK","AP_AUTH_REQ","AP_CONFIGING","AP_RESTART_NETWORK","AP_CONFIG_OK","AP_RUNNING","AP_REBOOTING","AP_UPGRADING","AP_RESET_FACTORY",
	"AP_OFFLINE"}; //must equal to enum AP_STATE

extern int g_msg_seq;
extern int g_msg_seq_r;
extern char *g_ap_last_config;

enum demo_protocols {

	PROTOCOL_LWS_KEEPALIVE,

	/* always last */
	DEMO_PROTOCOL_COUNT
};

struct pthread_routine_tool {
	struct libwebsocket_context *context;
	struct libwebsocket *wsi;
};

static int websocket_write_back(struct libwebsocket *wsi_in, char *str, int str_size_in) 
{
	if (str == NULL || wsi_in == NULL)
		return -1;

	int n;
	int len;
	char *out = NULL;

	if (str_size_in < 1) 
		len = strlen(str);
	else
		len = str_size_in;

	out = (char *)malloc(sizeof(char)*(LWS_SEND_BUFFER_PRE_PADDING + len + LWS_SEND_BUFFER_POST_PADDING));
	if(!out){
		LOG_INFO("error: malloc failed.\n");
		return -1;
	}
	//* setup the buffer*/
	memcpy (out + LWS_SEND_BUFFER_PRE_PADDING, str, len );
	//* write out*/
	n = libwebsocket_write(g_wsi, (unsigned char *)out + LWS_SEND_BUFFER_PRE_PADDING, len, LWS_WRITE_TEXT);

	LOG_INFO("[websocket_write_back] %s\n", str);
	//* free the buffer*/
	free(out);

	return n;
}

void ws_log(char *msg)
{
	if(msg)
		LOG_INFO(msg);
}

int init_global_mem(void)
{
	int i = 0;

	g_ssid_dev = (struct ssid_dev **)malloc(MAX_WLAN_COUNT * sizeof(struct ssid_dev *));
	if(NULL == g_ssid_dev){
		printf("%d\n",__LINE__);
		return -1;
	}

	for(i = 0; i < MAX_WLAN_COUNT; i++){
		struct ssid_dev *p = NULL;printf("%d\n",__LINE__);
		p = (struct ssid_dev *) malloc(sizeof(struct ssid_dev));	
		if(p == NULL){
			LOG_INFO("malloc failed., i=%d\n", i);
			//todo: free malloced memory
			return -1;
		}

		memset(p, 0, sizeof(struct ssid_dev));
		snprintf(p->dev, sizeof(p->dev) - 1, "ath%d", i);
		snprintf(p->portal_url, sizeof(p->portal_url) - 1, "%s", DEFAULT_PORTAL);
		
		g_ssid_dev[i] = p;printf("%d:: portal[%d]=%s\n",__LINE__, i, g_ssid_dev[i]->portal_url);
	}

	if(NULL == g_ap_last_config){
		g_ap_last_config = (char *)malloc(MAX_MSG_SIZE);
		if(!g_ap_last_config){
			LOG_INFO("g_ap_last_config malloc failed.\n");
			return -1;	
		}
		memset(g_ap_last_config, 0, MAX_MSG_SIZE);
	}

	g_acname = (char *)malloc(sizeof(char) * MAX_NAME_SIZE);
	g_test_acname = (char *)malloc(sizeof(char) * MAX_NAME_SIZE);
	g_acpath = (char *)malloc(sizeof(char) * MAX_NAME_SIZE);
	if(!g_acname || !g_test_acname || !g_acpath){
		LOG_INFO("vals malloc failed.\n");
		return -1;	
	}

	return 0;
}

void ap_change_state(int state)
{
	char msg[256]={0};
	char s[32] = {0};
	char ip[32] = {0};
		
	switch(state){
		case AP_IDLE:
			g_state = AP_IDLE;
			break;
		case AP_DISCOVERY:
			g_state = AP_DISCOVERY;
			break;
		case AP_JOIN_S4:
		case AP_JOIN_OK:
			g_state = AP_JOIN_OK;
			strncpy(s, "join_ok", sizeof(s)-1);
			break;
		case AP_AUTH_REQ:
			g_state = AP_AUTH_REQ;
			strncpy(s, "auth_req", sizeof(s)-1);
			break;
		case AP_CONFIGING:
			g_state = AP_CONFIGING;
			strncpy(s, "configing", sizeof(s)-1);
			break;
		case AP_RESTART_NETWORK:
			g_state = AP_RESTART_NETWORK;
			strncpy(s, "restart_network", sizeof(s)-1);
			break;
		case AP_CONFIG_OK:
			g_state = AP_CONFIG_OK;
			strncpy(s, "config_ok", sizeof(s)-1);
			break;
		case AP_RUNNING:
			g_state = AP_RUNNING;
			strncpy(s, "running", sizeof(s)-1);
			break;
		case AP_REBOOTING:
			g_state = AP_REBOOTING;
			strncpy(s, "rebooting", sizeof(s)-1);
			break;
		case AP_UPGRADING:
			g_state = AP_UPGRADING;
			strncpy(s, "upgrading", sizeof(s)-1);
			break;
		case AP_RESET_FACTORY:
			g_state = AP_RESET_FACTORY;
			strncpy(s, "reset_factory", sizeof(s)-1);
			break;
		case AP_OFFLINE:
			g_state = AP_OFFLINE;
			break;
		default :
			break;
	}

	LOG_INFO("*********************************************************\n");
	LOG_INFO("*     ap state change to   %-29s*\n",  str_ap_state[g_state]);
	LOG_INFO("*********************************************************\n");

	if(g_state >= AP_OFFLINE || g_state <= AP_AUTH_REQ){
		set_ap_online(0);	
	}else{
		set_ap_online(1);	
	}
	
	if(g_state == AP_OFFLINE){
		pthread_mutex_lock(&mutex);
		consume_all_node(&list_head_send);
		pthread_mutex_unlock(&mutex);

		pthread_mutex_lock(&mutex_r);
		consume_all_node(&list_head_recv);
		pthread_mutex_unlock(&mutex_r);
	}

	if(!s[0]){
		return;
	}

	get_wan_ip(ip, sizeof(ip)-1);
	snprintf(msg, sizeof(msg)-1, 
	          "{\"type\":\"ap_control\",\"subtype\":\"upstream\","
	          "\"data\":{\"mac\":\"%s\",\"ip\":\"%s\",\"state\":\"%s\"}}", 
	          g_ap_label_mac, ip, s);

	enqueue_msg(msg);

	return;
}

void handle_ac_msg(struct libwebsocket_context *context, struct libwebsocket *wsi, void *_in, size_t _len)
{
	int n = 0;
	char *rcv = NULL;

	if(!_in){
		LOG_INFO("%s: input error.\n", __FUNCTION__);
		return;		
	}	
	
	rcv = (char *)_in;

	if(!strncmp("\{\"token\"", rcv, strlen("\{\"token\""))){
		g_state = AP_JOIN_S1;
		libwebsocket_callback_on_writable(context, wsi);
	}else if(!strncmp("{\"message\":\"connected\"}", rcv, strlen("{\"message\":\"connected\"}"))){
		g_state = AP_JOIN_S3;
		libwebsocket_callback_on_writable(context, wsi);
	}else if(!strncmp("{\"type\":\"conifg\"", rcv, strlen("{\"type\":\"conifg\""))){
		//g_state = AP_CONFIG;	
		//printf("%d: state change to %d\n", __LINE__, g_state);
		LOG_INFO("get config: %s\n", rcv);
	}else if(!strncmp("{\"type\":\"rest\"", rcv, strlen("{\"type\":\"rest\""))){
		LOG_INFO("%s: rcv : %s\n", __FUNCTION__, rcv);
		dm_log_message(1, "%s: rcv : %s\n", __FUNCTION__, rcv);
		
		if(g_state < AP_JOIN_OK){
			cJSON *json;
			json = cJSON_Parse(rcv);
			char *wsid = cJSON_GetObjectItem(json,"wsid")->valuestring;
			char *from = cJSON_GetObjectItem(json,"from")->valuestring;

			char tmp[256] = {0};
			snprintf(tmp, sizeof(tmp), "{\"type\":\"router\",\"wsid\":\"%s\",\"from\":\"%s\",\"error\":0,\"data\":{}}",
				wsid, from);
			n = websocket_write_back(wsi, tmp, strlen(tmp));
			if (n < 0){
				LOG_INFO("%d: libwebsocket_write() error\n", __LINE__);
				//return -1;
			}
			cJSON_Delete(json);
		}else{

			enqueue_r_msg(rcv);
		}
		/*msgdata *node = make_node(rcv, strlen(rcv));
		pthread_mutex_lock(&mutex_r);
		list_add_end(&list_head_recv, node);
		printf("produce_r: key=%d. total len=%d\n", node->key, list_length(list_head_recv));
		pthread_mutex_unlock(&mutex_r);*/
	}else{
		LOG_INFO("%s: rcv unknown: %s\n", __FUNCTION__, rcv);
		dm_log_message(1, "%s: rcv unknown: %s\n", __FUNCTION__, rcv);

		enqueue_r_msg(rcv);
		/*msgdata *node = make_node(rcv, strlen(rcv));
		pthread_mutex_lock(&mutex_r);
		list_add_end(&list_head_recv, node);
		printf("produce_r: key=%d. total len=%d\n", node->key, list_length(list_head_recv));
		pthread_mutex_unlock(&mutex_r);*/
	}

	return;
}

static void *pthread_nl_consume(void *tool_in)
{
	struct pthread_routine_tool *tool = tool_in;
	int n = 0;
#if 0
		char *rcv = "{\"type\":\"rest\",\"wsid\":\"14:3d:f2:bd:40:bc14454802451266\",\"from\":\"pppoeRest\",\"error\":0,\"data\":{\"apiclass\":\"net\",\"method\":\"conmmercialAP\",\"params\":[\"eyJ0b2tlbiI6IjEyMzQ1NiIsImFjY291bnQiOiIxNDozZDpmMjpiZDo0MDpiYyIsImZ1bmN0aW9uIjoic2VuZENvbmZpZyIsInR5cGUiOiJjb25maWciLCJzdWJ0eXBlIjoid2lmaSIsImRhdGEiOnsicmFkaW8iOnsiMi40ZyI6W10sIjVnIjpbXX0sIndsYW4iOltdfX0=\"]}}";
		/*char *rcv = "{\"type\":\"rest\",\"wsid\":\"14:3d:f2:bd:40:bc14458515182318\",\"from\":\"pppoeRest\",\"error\":0,\"data\":{\"apiclass\":\"net\",\"method\":\"conmmercialAP\",\"params\":[\"eyJ0eXBlIjoiZ2V0QXBJbmZvIiwic3VidHlwZSI6IndpZmkiLCJkYXRhIjpbXX0=\"]}}";*/
		enqueue_r_msg(rcv);
		/*msgdata *node = make_node(rcv, strlen(rcv));
		pthread_mutex_lock(&mutex_r);
		list_add_end(&list_head_recv, node);
		printf("produce_r: key=%d. total len=%d\n", node->key, list_length(list_head_recv));
		pthread_mutex_unlock(&mutex_r);*/
#endif		
	//* waiting for connection with server done.*/
	while (1) {
		n = 0;
		usleep(1000*20);
		if(!(/*(AP_RUNNING == g_state || AP_REBOOTING == g_state || AP_AUTH_REQ == g_state ||
			  AP_CONFIGING == g_state ) */
			  (g_state >= AP_JOIN_OK && g_state < AP_OFFLINE && g_state != AP_RESTART_NETWORK)
			&& 1 == g_connection_flag))
			continue;
		//printf("consumer lock ....\n");
		pthread_mutex_lock(&mutex);
		msgdata *node = NULL;
		for(node = list_head_send; node != NULL;node = node->next){
			if(0 == node->consumed){
				n = websocket_write_back(tool->wsi, node->msg, strlen(node->msg));
				if(n < 0) {
					LOG_INFO("%d: write error. trys=%d\n", __LINE__, node->trys);	
					if(node->trys++ > MSGDATA_MAX_TRYS){
						LOG_INFO("reach max trys. key=%d consumed.\n", node->key);
						node->consumed = 1;
						free_all_consumed_node(&list_head_send);
						LOG_INFO("reach max trys. clean result: send list len = %d\n", list_length(list_head_send));
					 }
					 sleep(10);
				}else{
					LOG_INFO("key=%d consumed.\n", node->key);
					node->consumed = 1;
					free_all_consumed_node(&list_head_send);
					LOG_INFO("clean result: send list len = %d\n", list_length(list_head_send));
				}
				break;
			}
		}
		pthread_mutex_unlock(&mutex);
		//printf("consumer unlock ....\n");

		/*collect sta msg and store it, wait callback to use it*/
		//collect_sta_msg();

		//printf("[pthread_routine] call on writable.\n");	
		//libwebsocket_callback_on_writable(tool->context, tool->wsi);
	}
	return NULL;
}

void handle_send_to_ac(struct libwebsocket *wsi)
{
	int n;

	if(AP_DISCOVERY == g_state || AP_IDLE == g_state || AP_OFFLINE == g_state){
		
		char fmt[] = "{\"type\":\"auth\",\"idcode\":\"%s\",\"mac\":\"%s\"}";
		char buf[128] = {0};

		snprintf(buf, sizeof(buf)-1, fmt, g_ap_label_mac, g_ap_label_mac);

		n = libwebsocket_write(wsi, (unsigned char *)buf, strlen(buf), opts | LWS_WRITE_TEXT);

		if (n < 0){
			LOG_INFO("%d: libwebsocket_write() error\n", __LINE__);
			//return -1;
		}
	}else if(AP_JOIN_S1 == g_state){

		char tmp[512] = {0};
		char fmt[] = "{\"type\":\"connect\",\"token\":\"12345678\",\"idcode\":\"%s\",\"deviceIp\":\"192.168.3.105\",\"pppoeId\":\"%s\",\"passwd\":\"11111\",\"c_type\":\"router\",\"mac\":\"%s\",\"wifimac\":\"%s\",\"hwtype\":\"DW33D\"}";

		snprintf(tmp, sizeof(tmp)-1, fmt, g_ap_label_mac, g_ap_label_mac,
			g_ap_label_mac, g_ap_label_mac);

		LOG_INFO("%d, msg=%s\nlen=%d\n", __LINE__, tmp, strlen(tmp));
		libwebsocket_write(wsi, (unsigned char *)tmp, strlen(tmp), opts | LWS_WRITE_TEXT);
		g_state = AP_JOIN_S2;
	}else if(AP_JOIN_S3 == g_state){
		char tmp[] = "{\"type\":\"notification\",\"wsid\":\"888\",\"from\":\"7OL6J42GN\",\"data\":{\"msgtype\":\"reboot\",\"message\":\"路由器上线成功\"}}";
		LOG_INFO("%d, msg=%s\nlen=%d\n", __LINE__, tmp, strlen(tmp));
		libwebsocket_write(wsi, (unsigned char *)tmp, strlen(tmp), opts | LWS_WRITE_TEXT);	
		g_state = AP_JOIN_S4;	
		//...
		ap_change_state(AP_JOIN_S4);
		ap_change_state(AP_AUTH_REQ);
		//ap_change_state(AP_RUNNING);
	}else if(AP_RUNNING == g_state){
		//check local stored sta msg, send it to ac
			
	}

	return;
}

int pthread_init(struct libwebsocket *wsi, struct libwebsocket_context *context)
{
	g_pthread_init = 1;
	struct pthread_routine_tool tool;
	tool.wsi = wsi;
	tool.context = context;

	pthread_t pid, pid_nl, pid_recv, pid_hser;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	size_t stacksize;
	stacksize = (double) 300*1024;

	int res = pthread_attr_setstacksize (&attr, stacksize);
	if (res != 0) {
		LOG_INFO("pthread_attr: error\n");
	}

	pthread_mutex_init(&mutex, NULL);
	pthread_mutex_init(&mutex_r, NULL);
	pthread_create(&pid, &attr, pthread_nl_consume, &tool);
	pthread_detach(pid);

	stacksize = (double) 800*1024;

	res = pthread_attr_setstacksize (&attr, stacksize);
	if (res != 0) {
		LOG_INFO("pthread_attr 2: error\n");
	}
	pthread_create(&pid_nl, &attr, pthread_netlink, NULL);
	pthread_detach(pid_nl);
	pthread_create(&pid_recv, &attr, pthread_recv, NULL);
	pthread_detach(pid_recv);
	pthread_create(&pid_hser, &attr, pthread_httpserver, NULL);
	pthread_detach(pid_recv);

	return 0;
}

static int
callback_lws_keepalive(struct libwebsocket_context *context,
			struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{

	switch (reason) {

	case LWS_CALLBACK_CLIENT_ESTABLISHED:

		fprintf(stderr, "LWS_CALLBACK_CLIENT_ESTABLISHED\n");
		ws_log("LWS_CALLBACK_CLIENT_ESTABLISHED\n");

		libwebsocket_callback_on_writable(context, wsi);
		g_connection_flag = 1;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		fprintf(stderr, "Connect with server error.\n");
		ws_log("Connect with server error.\n");
		g_idle_cnt++;
		g_connection_flag = 0;
		break;

	case LWS_CALLBACK_CLOSED:
		g_connection_flag = 0;
		fprintf(stderr, "LWS_CALLBACK_CLOSED\n");
		ws_log("LWS_CALLBACK_CLOSED\n");
		wsi = NULL;
		ap_change_state(AP_OFFLINE);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		fprintf(stderr, "LWS_CALLBACK_CLIENT_RECEIVE\n");
		fprintf(stderr, "rx %d bytes '%s'\n", (int)len, (char *)in); 
		ws_log("LWS_CALLBACK_CLIENT_RECEIVE\n");
		handle_ac_msg(context, wsi, in, len);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		fprintf(stderr, "LWS_CALLBACK_CLIENT_WRITEABLE\n");
		ws_log("LWS_CALLBACK_CLIENT_WRITEABLE\n");
		handle_send_to_ac(wsi);
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {
	{
		//"fake-nonexistant-protocol,lws-mirror-protocol",
		NULL,
		callback_lws_keepalive,
		0,
		4096,
	},
	{ NULL, NULL, 0, 0 } /* end */
};

void sighandler(int sig)
{
	force_exit = 1;
}

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",      required_argument,      NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "version",	required_argument,	NULL, 'v' },
	{ "remote server",	required_argument,	NULL, 'r' },
	{ "undeflated",	no_argument,		NULL, 'u' },
	{ "nomux",	no_argument,		NULL, 'n' },
	{ "longlived",	no_argument,		NULL, 'l' },
	{ NULL, 0, 0, 0 }
};


int main(int argc, char **argv)
{
	int n = 0;
	int ret = 0;
	int port = 7681;
	int use_ssl = 0;
	struct libwebsocket_context *context = NULL;
	int ietf_version = -1; /* latest */
	struct lws_context_creation_info info;
	int svc_cnt = 0;
	int forground = 0;

	memset(&info, 0, sizeof info);

	if(init_global_mem()){
		return -1;
	}
	
	if (argc < 2)
		goto usage;

	while (n >= 0) {
		n = getopt_long(argc, argv, "r:nuv:hsp:d:lf", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'r':
			snprintf(g_test_acname, MAX_NAME_SIZE, "%s", optarg);
			printf("cmd input %s, %s\n", g_test_acname, optarg);
			break;
		case 'd':
			lws_set_log_level(atoi(optarg), NULL);
			break;
		case 's':
			use_ssl = 2; /* 2 = allow selfsigned */
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'l':
			longlived = 1;
			break;
		case 'v':
			ietf_version = atoi(optarg);
			break;
		case 'u':
			deny_deflate = 1;
			break;
		case 'n':
			deny_mux = 1;
			break;
		case 'f':
			forground = 1;
			break;
		case 'h':
			goto usage;
		}
	}

	if(!forground){
		init_daemon();
	}

	dm_open_log();	
	dm_log_message(1, "%s %s\n", argv[0], "Start ...");

	/*if (optind >= argc)
		goto usage;
		*/

	signal(SIGINT, sighandler);

	get_ap_label_mac(g_ap_label_mac, sizeof(g_ap_label_mac) - 1, 0);
	get_ap_label_mac(g_ap_label_mac_nocol, sizeof(g_ap_label_mac_nocol) - 1, 1);
	
	/*
	 * create the websockets context.  This tracks open connections and
	 * knows how to route any traffic and which protocol version to use,
	 * and if each connection is client or server side.
	 *
	 * For this client-only demo, we tell it to not listen on any port.
	 */

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
	//info.extensions = libwebsocket_get_internal_extensions();
#endif
	info.gid = -1;
	info.uid = -1;

	while(!force_exit){
		pthread_mutex_lock(&mutex);
		consume_all_node(&list_head_send);
		free_all_consumed_node(&list_head_send);
		pthread_mutex_unlock(&mutex);

		pthread_mutex_lock(&mutex_r);
		consume_all_node(&list_head_recv);
		free_all_consumed_node(&list_head_recv);
		pthread_mutex_unlock(&mutex_r);

		if(context){
			libwebsocket_context_destroy(context);
		}

		context = NULL;
		context = libwebsocket_create_context(&info);
		if (context == NULL) {
			LOG_INFO("Creating libwebsocket context failed\n");
			ap_change_state(AP_IDLE);
			sleep(30);
			g_idle_cnt++;
			continue;
		}

		printf("compare: %d:%s\n", g_idle_cnt, g_acname);
		if((g_idle_cnt >= 1) || (0 == g_acname[0])){
			ap_change_state(AP_DISCOVERY);
			if(g_test_acname[0]){
				snprintf(g_acname, MAX_NAME_SIZE-1, "%s", g_test_acname);
				snprintf(g_acpath, MAX_NAME_SIZE-1, "%s", "/perception");
				g_acport=8080;
			}else{

				//discovery websocket server
				lbps_discovery(NULL);
			}
		}

		/* create a client websocket */
		LOG_INFO("acname:%s, acport:%d, acpath:%s\n", g_acname, g_acport, g_acpath);
		g_wsi = NULL;
		g_wsi = libwebsocket_client_connect(context,
			g_acname, g_acport, use_ssl, g_acpath,
			g_acname, g_acname,
			protocols[PROTOCOL_LWS_KEEPALIVE].name, ietf_version);

		if (g_wsi == NULL) {
			LOG_INFO("libwebsocket "
				      " connect failed\n");
			ret = 1;
			ap_change_state(AP_IDLE);
			sleep(30);
			g_idle_cnt++;
			continue;
		}

		g_idle_cnt = 0;

		if(0 == g_pthread_init){
			pthread_init(g_wsi, context);	
		}

		LOG_INFO("Waiting for connect...\n");
		n = 0;
		svc_cnt = 0;
		g_heartbeat_flag = 0;
		while (n >= 0 && !was_closed && !force_exit) {
			n = libwebsocket_service(context, WS_SERVICE_INTERVAL);
			svc_cnt++;	
			if(svc_cnt >= 65534 ){
				svc_cnt = 0;
			}
			if((g_state > AP_DISCOVERY) && (g_state < AP_OFFLINE)){
				if(0 == g_connection_flag){
					ap_change_state(AP_IDLE);
					sleep(30);

					break;
				}
			}

			if((svc_cnt >= (HEARTBEAT_INTERVAL * 1000 / WS_SERVICE_INTERVAL)) &&
			    (0 == (svc_cnt % (HEARTBEAT_INTERVAL * 1000 / WS_SERVICE_INTERVAL)))){ //start at the first 30 second, and every 30 seconds
				g_heartbeat_flag += 1;
				LOG_INFO("g_heartbeat_flag=%d\n", g_heartbeat_flag);
			}
		
			if(g_heartbeat_flag > MAX_HEARTBEAT_TRYS){
				LOG_INFO("reach max heart beat trys\n");

				break;	
			}

			if(g_state == AP_OFFLINE){
				break;
			}
		}

		sleep(15);
	}

	LOG_INFO("Exiting\n");


	dm_close_log();
	return ret;

usage:
	LOG_INFO("Usage: %s "
				"<server address> [--port=<p>] "
				"[--ssl] [-k] [-v <ver>] "
				"[-d <log bitfield>] [-l]\n", argv[0]);
	dm_close_log();
	return 1;
}

