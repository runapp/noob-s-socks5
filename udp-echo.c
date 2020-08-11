#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define d(x) printf("%d <- %s\n",(x),#x)

int main() {
	int s;
	d(s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
	struct sockaddr_in* saddr = (struct sockaddr_in*)malloc(128);
	memset(saddr, 0, 128);
	saddr->sin_family = AF_INET;
	saddr->sin_addr.s_addr = htonl(INADDR_ANY);
	saddr->sin_port = htons(8987);
	d(bind(s, (struct sockaddr*)saddr, sizeof(struct sockaddr_in)));
	while (1) {
		char buf[2048];
		int slen = sizeof(saddr), rlen;
		d(rlen = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)saddr, &slen));
		printf("From; %s:%d    slen=%d\n", inet_ntoa(saddr->sin_addr), ntohs(saddr->sin_port), slen);
		if (ntohs(saddr->sin_port) == 8987) {
			printf("Loopback detected.\n");
		}
		else {
			d(sendto(s, buf, rlen, 0, (struct sockaddr*)saddr, slen));
		}
	}
	return 0;
}
