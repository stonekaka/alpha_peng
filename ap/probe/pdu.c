/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     pdu.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-12-18 10:07
***************************************************************************/

#include "main.h"
#include "pdu.h"

struct sta_info {
	unsigned char mac[6];
	MU node;
	UT_hash_handle hh;
};

char *g_wlan_ifname[MAX_WLAN_COUNT][2]={{"ath0","ath16"},{"ath1","ath17"},{"ath2","ath18"},{"ath3","ath19"},{"ath4","ath20"},{"ath5","ath21"}};

struct sta_info *stas = NULL;
extern unsigned char g_apmac[6];
extern struct probe_config g_conf;
extern pthread_rwlock_t g_lock;
int g_reqid = 0;

int add_mu(struct sta_msg sta, int is_associated)
{
	int ret = 0;
	struct sta_info *e;
	struct sta_info *s;

	s = malloc(sizeof(struct sta_info));
	if(!s){
		LOG_INFO("%s:malloc failed\n", __FUNCTION__);
		return -1;
	}	

	memset(s, 0, sizeof(struct sta_info));
	
	memcpy(s->mac, sta.mac, 6);
	memcpy(s->node.mu_mac, sta.mac, 6);
	s->node.channel = sta.channel;
	s->node.rssi = sta.rssi;
	s->node.noise_floor = sta.noisefloor;
	memcpy(s->node.ap_mac, g_apmac, 6);
	s->node.is_associated = is_associated?0x01:0x02;
    s->node.mu_type = 0x02;

    s->node.header.header = 0xCC83;
    s->node.header.request_id = g_reqid;
    s->node.header.code = 0xD6;
    s->node.header.sub_code = 0;
    s->node.header.data_len = sizeof(MU);

    if (pthread_rwlock_wrlock(&g_lock) != 0) LOG_INFO("1 can't get wrlock");
	HASH_FIND_PTR(stas, &sta.mac, e);

#if 0
    printf("=== %02x:%02x:%02x:%02x:%02x:%02x  %02x:%02x:%02x:%02x:%02x:%02x rssi=%d~%d channel=%d~%d, noise=%d~%d\n", 
            sta.mac[0],sta.mac[1],sta.mac[2],sta.mac[3],sta.mac[4],sta.mac[5],
            s->node.mu_mac[0], s->node.mu_mac[1], s->node.mu_mac[2],
            s->node.mu_mac[3], s->node.mu_mac[4], s->node.mu_mac[5], s->node.rssi, sta.rssi, s->node.channel, sta.channel,
            s->node.noise_floor, sta.noisefloor);
#endif    
	if(e){
		memcpy(&e->node, &s->node, sizeof(MU));
		free(s);
	}else{
		HASH_ADD_PTR(stas, mac, s);
	}
    pthread_rwlock_unlock(&g_lock);

	return ret;
}

int get_associate_stas(void)
{
    int ret = 0;
    FILE *fp = NULL;
    int i = 0, j = 0;
    char buf[128] = {0};
    char cmd[128] = {0};
    char *fmt = "wlanconfig %s list 2>/dev/null| awk 'NR>1' | awk '{print $1,$3,$6}'"; //mac, channel, rssi
    char mac[20] = {0};
    unsigned char umac[6] = {0};
    int channel = 0;
    int rssi = 0;
    struct sta_msg sta;
    
    for(i = 0; i < MAX_WLAN_COUNT; i++){
        for(j = 0; j < 2; j++) {
            snprintf(cmd, sizeof(cmd) - 1, fmt, g_wlan_ifname[i][j]);
            fp = popen(cmd, "r");
            if(fp){
                while(fgets(buf, sizeof(buf)-1, fp)){
                    channel = 0;
                    rssi = 0;
                    memset(mac, 0, sizeof(mac));
                    memset(umac, 0, sizeof(umac));
                    clear_crlf(buf); 
                    if(3 == sscanf(buf, "%s %d %d", mac, &channel, &rssi)){
                        ascii2mac(mac, umac);
                        memset(&sta, 0, sizeof(struct sta_msg));
                        memcpy(sta.mac, umac, sizeof(sta.mac));
                        sta.channel = channel;
                        sta.rssi = rssi;
                        add_mu(sta, 1);
                    }
                }
                pclose(fp);
            }
        }
    }

    return ret;
}

void delete_all() 
{
    struct sta_info *current_node, *tmp;

    HASH_ITER(hh, stas, current_node, tmp) {
        HASH_DEL(stas, current_node);  /* delete; users advances to next */
        free(current_node);            /* optional- if you want to free  */
    }
}

int upload_mu(void)
{
    struct sta_info *s, *tmp;
    COM_PDU *com;
    int i = 0;
    int send_len = 0;

    com = malloc(sizeof(COM_PDU));
    if(!com){
		LOG_INFO("%s:malloc failed\n", __FUNCTION__);
		return -1;
    }

    get_associate_stas();

    memset(com, 0, sizeof(COM_PDU));
    if (pthread_rwlock_rdlock(&g_lock) != 0) LOG_INFO("2 can't get rdlock");
    HASH_ITER(hh, stas, s, tmp){
        printf("%02x:%02x:%02x:%02x:%02x:%02x channel=%d rssi=%d noise=%d, is_asso=%d\n", s->node.mu_mac[0], s->node.mu_mac[1], s->node.mu_mac[2],
                s->node.mu_mac[3], s->node.mu_mac[4], s->node.mu_mac[5],
                s->node.channel, s->node.rssi, s->node.noise_floor, s->node.is_associated);
        memcpy(&com->MU[i], &s->node, sizeof(MU));
        i++;
    }
    pthread_rwlock_unlock(&g_lock);
    
    com->mu_count = i;
    com->header.header = 0xCC83;
    com->header.request_id = g_reqid++;
    if(g_reqid > 65535){
        g_reqid = 0;
    }
    com->header.code = 0xD8;
    com->header.sub_code = 0;
    com->header.data_len = 4 + i * sizeof(MU);
	
    send_len = sizeof(com->header) + com->header.data_len;

    send_udp_data((void *)com, send_len, g_conf.server, g_conf.port );

    free(com);

    if (pthread_rwlock_wrlock(&g_lock) != 0) LOG_INFO("3 can't get wrlock");
    delete_all();
    pthread_rwlock_unlock(&g_lock);

	return 0;
}

