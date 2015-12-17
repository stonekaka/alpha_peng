/* 
 * File:   main.c
 * Author: tianshuai
 *
 * Created on 2011Âπ?1Êú?9Êó? ‰∏ãÂçà10:34
 */

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int port=8480;
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


void dumphex(char *buf1, int len)
{
	int addr = 0;
	int i;
	unsigned char buf[16];
	printf("bytes: %d\n", len);
	while (len > 0) {
		memcpy(buf, buf1, 16);
		printf("%08x  %02x %02x %02x %02x %02x %02x %02x %02x  "
				"%02x %02x %02x %02x %02x %02x %02x %02x    ", 
				addr, buf[0], buf[1], buf[2], buf[3], buf[4],
				buf[5], buf[6], buf[7], buf[8], buf[9],
				buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
		for (i = 0; i < 16; i++) {
			printf("%c", isprint(buf[i]) ? buf[i] : '.');
			if (i == 7)
				printf(" ");
		}
		printf("\n");

		buf1 += 16;
		len -= 16;
		addr += 16;
	}
}

int MacToStr(char *macAddr, char *str) {
   if ( macAddr == NULL ) return -1;
   if ( str == NULL ) return -1;
   sprintf(str, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
           (unsigned char ) macAddr[0], (unsigned char ) macAddr[1], (unsigned char ) macAddr[2],
           (unsigned char ) macAddr[3], (unsigned char ) macAddr[4], (unsigned char ) macAddr[5]);
   return 0;
}
int main(int argc, char** argv) {

    int sin_len,buf_len;
    char message[40960]={0};

	COM_PDU compounded_pdu;
	char ap_mac[32] = {0};
	char mu_mac[32] = {0};

    int socket_descriptor;
    struct sockaddr_in sin;
	int pdu_len = sizeof(PDU_H);
	int mu_len = sizeof(MU);
	int cpdu_len = sizeof(COM_PDU);
    printf("Waiting for data form sender pdu_len :%d mu_len :%d cpdu_len : %d int :%d \n",pdu_len,mu_len,cpdu_len,sizeof(int));

    bzero(&sin,sizeof(sin));
    sin.sin_family=AF_INET;
    sin.sin_addr.s_addr=htonl(INADDR_ANY);
    sin.sin_port=htons(port);
    sin_len=sizeof(sin);

    socket_descriptor=socket(AF_INET,SOCK_DGRAM,0);
    bind(socket_descriptor,(struct sockaddr *)&sin,sizeof(sin));

    while(1)
    {
		memset(&compounded_pdu,0,sizeof(COM_PDU));
        //buf_len = recvfrom(socket_descriptor,message,sizeof(message),0,(struct sockaddr *)&sin,&sin_len);
		buf_len = recvfrom(socket_descriptor,&compounded_pdu,sizeof(message),0,(struct sockaddr *)&sin,&sin_len);
		int mu_count = ntohs(compounded_pdu.mu_count);
		//unsigned int comm_pdu = compounded_pdu.header.code;
		char str[3] = {0};
		sprintf(str,"%2.2x",(unsigned char)compounded_pdu.header.code);
		unsigned int comm_pdu_header = ntohs(compounded_pdu.header.header);
		printf("###### mu_count %d comm_pdu %s comm_pdu_header %d \n",mu_count,str,comm_pdu_header);
		int i = 0;
		for(i = 0;i<mu_count;i++ ){
			int rssi = compounded_pdu.MU[i].rssi;
			MacToStr((char *)(compounded_pdu.MU[i].ap_mac),(char *)ap_mac);
			MacToStr((char *)(compounded_pdu.MU[i].mu_mac),(char *)mu_mac);
			int mu_type = compounded_pdu.MU[i].mu_type;
		    //unsigned int mucode = compounded_pdu.MU[i].header.code;
			sprintf(str,"%2.2x",(unsigned char)compounded_pdu.MU[i].header.code);
			unsigned int mu_header = ntohs(compounded_pdu.MU[i].header.header);
			//if(mu_type == 2)
			//printf("buf_len : %d mu_count %d rssi : %d buf:%s\n",buf_len,mu_count,rssi,(char*)(&compounded_pdu));
			printf("****** rssi[%d] : %d ap_mac %s mu_mac :%s mu_type %d mucode %s mu_header %d\n",i,rssi,ap_mac,mu_mac,mu_type,str,mu_header);
		}
		dumphex((char *)(&compounded_pdu),buf_len);
        if(strncmp(message,"stop",4) == 0)//Êé•ÂèóÂà∞ÁöÑÊ∂àÊÅØ‰∏?‚Äústop‚Ä?
        {
            printf("Sender has told me to end the connection\n");
            break;
        }
    }

    close(socket_descriptor);
    exit(0);

    return (EXIT_SUCCESS);
}
