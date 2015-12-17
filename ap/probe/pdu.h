/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     pdu.h
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-12-17 11:18
***************************************************************************/

#ifndef __PDU_H__
#define __PDU_H__

#pragma pack(1)
#define MU_TOTAL 100

typedef struct pdu_header{
	short header;
	short request_id;
	char code;
	char sub_code;
	short data_len;
}PDU_H;

typedef struct mu{ // code 0xD6
	PDU_H header;
	char ap_mac[6];
	short vendor_id;
	char mu_mac[6];
	char radio_type;
	char channel;
	char is_associated;
	char associated_ap[6];
	char mu_type;
	char rssi;
	char noise_floor;
	short age;
	int mu_ip;//4 bytes
	char reserved[8];
}__attribute__((packed)) MU;

typedef struct compounded_pdu{ // code 0xD8
	PDU_H header;
	short mu_count;
	char reserved[2];
	MU MU[MU_TOTAL];
}__attribute__((packed)) COM_PDU;

#endif

