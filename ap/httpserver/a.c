#include <stdio.h>

int main()
{
	char *cmd = "cat /proc/net/arp | grep \"%s \" | awk '{print $4}' | sed 's/://g'";
	FILE *fp = NULL;
	char cmd_e[128] = {0};

	char buf[128] = {0};
	sprintf(cmd_e, cmd, "192.168.10.233");
	printf("cmd=%s\n", cmd_e);	
	fp = popen(cmd_e, "r");
	fgets(buf, 127, fp);
	printf("buf=%s\n", buf);

	return 0;
}

