#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <time.h>

#define NETLINK_TEST 22
#define NETLINK_QCAWIFI 27
//#define NETLINK_TEST NETLINK_GENERIC
#define MAX_PAYLOAD 1024 // maximum payload size

int parse_msg(char *uri)
{
	char cmd[256] = {0};
	FILE *fp = NULL;
	char buf[1024] = {0};

	if(!uri)
		return -1;

	if(!strstr(uri, "cache")) //web access
		snprintf(cmd, sizeof(cmd), "curl %s 2>/dev/null | grep \"<title>\"", uri);
	else //box access
		snprintf(cmd, sizeof(cmd), "curl %s 2>/dev/null | awk -v k=\"text\" "
			"'{n=split($0,a,\",\"); for (i=1; i<=n; i++) print a[i]}' | grep -E \"^\\\"vid|^\\\"vn\"", uri);
	
	//printf("%s\n", cmd);
	fp = popen(cmd, "r");
	if(NULL == fp){
		printf("curl result error!\n");
		return -1;
	}

	while(NULL != fgets(buf, sizeof(buf), fp)) {
		printf("%s ", buf);
	}
	printf("\n");

	if(buf[0] == '\0'){
		printf("read result error!\n");	
	}

	return 0;
}

int parse_wifi_probe_msg(char *data)
{
	unsigned char mac[6] = {0};
	char ssid[64] = {0};
	int len = 0;
	int len_ssid = 0;

	if(!data)
		return -1;
	
	/*|<-   mac  ->|<-  ssid ->|*/
	/*[xxxxxxxxxxxx][ssid......]*/
	len = strlen(data);
	len_ssid = len - sizeof(mac);

	/*memcpy(mac, data, sizeof(mac));
	memcpy(ssid, data + sizeof(mac), len_ssid > sizeof(ssid)?sizeof(ssid):len_ssid);
	printf("%02x:%02x:%02x:%02x:%02x:%02x, %s\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], ssid);*/
	printf("data=%s.\n", data);
	
	return 0;
}

int main(int argc, char* argv[])
{
    int state;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int sock_fd, retval;
    int state_smg = 0;
	FILE *fp = NULL;
	int nl_type;

	if(argc == 2 && !strcmp(argv[1], "dpi")){
		nl_type = NETLINK_TEST;
	}else if (argc == 2 && !strcmp(argv[1], "wifi")){
		nl_type = NETLINK_QCAWIFI;
	}else{
		printf("Usage: %s <dpi | wifi>\n", argv[0]);
		exit(1);
	}
	

    // Create a socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, nl_type);
    if(sock_fd == -1){
        printf("error getting socket: %s", strerror(errno));
        return -1;
    }

    // To prepare binding
    memset(&msg,0,sizeof(msg));
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // self pid
    src_addr.nl_groups = 0; // multi cast

    retval = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(retval < 0){
        printf("bind failed: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    // To prepare recvmsg

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh){
        printf("malloc nlmsghdr error!\n");
        close(sock_fd);
        return -1;
    }

    memset(&dest_addr,0,sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid(); // self pid
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh),"Hello you!");

    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    // iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
   
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("state_smg\n");
    state_smg = sendmsg(sock_fd,&msg,0);

    if(state_smg == -1)
    {
        printf("get error sendmsg = %s\n",strerror(errno));
    }

    memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
    printf("waiting received!\n");
    // Read message from kernel

	fp = fopen("/mnt/sdcard/dpi.log", "a+");	
    while(1){
        //printf("In while recvmsg\n");
        state = recvmsg(sock_fd, &msg, 0);
        if(state<0)
        {
            printf("state<1");
        }
        //printf("In while\n");
        //printf("[USER] Received message: %s\n",(char *) NLMSG_DATA(nlh));
        if(NETLINK_TEST == nl_type){
        	char *p = (char *)NLMSG_DATA(nlh);
        	if(p){
				time_t now;
				struct tm *timenow;
				char buf[64] = {0};
			
				time(&now);
				timenow = localtime(&now);
			
				snprintf(buf, sizeof(buf), "\ntime=%s", asctime(timenow));
				fwrite(buf, strlen(buf), 1, fp);
				fwrite(p, strlen(p), 1, fp);
			} else {
				printf("get null\n");
			}

			fflush(fp);
			//parse_msg((char *) NLMSG_DATA(nlh));
		}else if(NETLINK_QCAWIFI == nl_type){
			parse_wifi_probe_msg((char *) NLMSG_DATA(nlh));
		}
    }
	fclose(fp);	
    close(sock_fd);

    return 0;
}

