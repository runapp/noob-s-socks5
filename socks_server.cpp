#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#pragma comment(lib,"ws2_32")
#include "getopt.h"
#include "socks5_protocol.h"

void* socks_alloc(int len) { return malloc(len); }
void socks_free(void* p) { free(p); }

#define BUFSIZE 2048
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_INIT    {0}

unsigned short int port = 1080;
int daemon_mode = 0;
int auth_type;
FILE* log_file;
//pthread_mutex_t lock;
CRITICAL_SECTION log_lock;

struct IP_REVERSE_MAP_ITEM {
	unsigned int ipv4;
	const char* domain;
};
int IP_REVERSE_MAP_NUM = 0;
const char* IP_REVERSE_MAP_TEXT[][2] = {
	{"eu.wargaming.net","92.223.19.61"},
	{"eu.wargaming.net","92.223.19.57"},
	{"uistats.worldofwarships.eu","92.223.18.33"},
	{"xmpp-wows-eu.wargaming.net","92.223.23.138"},
};
IP_REVERSE_MAP_ITEM IP_REVERSE_MAP[100];

void init_domain_reverse_map() {
	int i;
	for (i = 0; i < ARRAY_SIZE(IP_REVERSE_MAP_TEXT); i++) {
		if (inet_pton(AF_INET, IP_REVERSE_MAP_TEXT[i][1], &IP_REVERSE_MAP[i].ipv4) <= 0) {
			printf("Error while converting %d reverse map.\n", i);
			exit(1);
		}
		IP_REVERSE_MAP[i].domain = IP_REVERSE_MAP_TEXT[i][0];
	}
	IP_REVERSE_MAP_NUM = i;
}


typedef DWORD pthread_t;
inline pthread_t pthread_self() {
	return GetCurrentThreadId();
}

void log_message(const char* message, ...)
{
	if (daemon_mode) {
		return;
	}

	char vbuffer[255];
	va_list args;
	va_start(args, message);
	vsnprintf(vbuffer, ARRAY_SIZE(vbuffer), message, args);
	va_end(args);

	time_t now;
	time(&now);
	char date[256];
	ctime_s(date, sizeof(date), &now);
	date[strlen(date) - 1] = '\0';

	pthread_t self = pthread_self();

	//DWORD errno = GetLastError();
	DWORD err = GetLastError(), werr = WSAGetLastError();
	if (err || werr) {
		EnterCriticalSection(&log_lock);//pthread_mutex_lock(&lock);
		fprintf(log_file, "[%s][%lu] Critical: %s - %d\nWSAError=%d\n", date, self, vbuffer, err, werr);
		errno = 0;
		LeaveCriticalSection(&log_lock); //pthread_mutex_unlock(&lock);
	}
	else {
		fprintf(log_file, "[%s][%lu] Info: %s\n", date, self, vbuffer);
	}
	fflush(log_file);
}

extern int readn(SOCKET fd, char* buf, int n)
{
	char* oribuf = buf;
	int nread, left = n;
	while (left > 0) {
		if ((nread = recv(fd, buf, left, 0)) < 0) {
			DWORD werr = WSAGetLastError();
			if (werr == WSAEINTR) {
				continue;
			}
			else {
				printf("[readn] Werr=%d\n", werr);
				buf[0] = 0;
				return 0;
			}
		}
		else {
			if (nread == 0) {
				buf[0] = 0;
				return 0;
			}
			else {
				left -= nread;
				buf += nread;
			}
		}
	}
	return n;
}

extern int writen(SOCKET fd, const char* buf, int n)
{
	int nwrite, left = n;
	while (left > 0) {
		if ((nwrite = send(fd, buf, left, 0)) == -1) {
			if (WSAGetLastError() == WSAEINTR) {
				continue;
			}
		}
		else {
			if (nwrite == n) {
				return 0;
			}
			else {
				left -= nwrite;
				buf += nwrite;
			}
		}
	}
	return n;
}

void app_thread_exit(DWORD ret, SOCKET fd)
{
	closesocket(fd);
	ExitThread(ret);
}
void app_thread_exit(DWORD ret, SOCKET fd, SOCKET fd2)
{
	closesocket(fd);
	app_thread_exit(ret, fd);
}

SOCKADDR_STORAGE gen_saddr(socks_address_type type, const char* ip, unsigned short port)
{
	SOCKADDR_STORAGE remote;
	ZeroMemory(&remote, sizeof(remote));

	if (type == IPV4) {
		int i;
		for (i = 0; i < IP_REVERSE_MAP_NUM; i++) {
			if (IP_REVERSE_MAP[i].ipv4 == *(unsigned int*)ip) {
				break;
			}
		}
		if (i < IP_REVERSE_MAP_NUM) {
			log_message("reverse map: %hhu.%hhu.%hhu.%hhu to %s:%d", ip[0], ip[1], ip[2], ip[3], IP_REVERSE_MAP[i].domain, htons(port));
			type = DOMAIN;
			ip = IP_REVERSE_MAP[i].domain;
		}
		else {
			sockaddr_in* remote4 = (sockaddr_in*)&remote;
			remote4->sin_family = AF_INET;
			memcpy(&remote4->sin_addr, ip, 4);
			remote4->sin_addr.S_un.S_un_b.s_b1 = ip[0];
			remote4->sin_addr.S_un.S_un_b.s_b2 = ip[1];
			remote4->sin_addr.S_un.S_un_b.s_b3 = ip[2];
			remote4->sin_addr.S_un.S_un_b.s_b4 = ip[3];
			remote4->sin_port = port;
		}
	}
	else if (type == IPV6) {
		sockaddr_in6* remote6 = (sockaddr_in6*)&remote;
		remote6->sin6_family = AF_INET6;
		memcpy(&remote6->sin6_addr, ip, 16);
		remote6->sin6_port = port;
	}
	// no "else" on purpose!
	if (type == DOMAIN) {
		struct addrinfo* res;
		char portstr[6];
		snprintf(portstr, ARRAY_SIZE(portstr), "%d", htons(port));
		log_message("getaddrinfo: %s %s", ip, portstr);
		int ret = getaddrinfo(ip, portstr, NULL, &res);
		if (ret == EAI_NODATA) {
			return remote;
		}
		else if (ret == 0) {
			struct addrinfo* r;
			for (r = res; r != NULL; r = r->ai_next) {
				if (r->ai_family == AF_INET || r->ai_family == AF_INET6) {
					memcpy(&remote, r->ai_addr, r->ai_addrlen);
					break;
				}
			}
		}
		freeaddrinfo(res);
	}

	return remote;
}


void tcp_bidirectional_forward(SOCKET fd0, SOCKET fd1)
{
	int maxfd, ret;
	fd_set rd_set;
	size_t nread;
	char buffer_r[BUFSIZE];

	log_message("Connecting two sockets");

	maxfd = (fd0 > fd1) ? fd0 : fd1;
	while (1) {
		FD_ZERO(&rd_set);
		FD_SET(fd0, &rd_set);
		FD_SET(fd1, &rd_set);
		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
		if (ret == 0 || ret < 0 && WSAGetLastError() == WSAEINTR) {
			continue;
		}

		if (FD_ISSET(fd0, &rd_set)) {
			nread = recv(fd0, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd1, (const char*)buffer_r, nread, 0);
		}

		if (FD_ISSET(fd1, &rd_set)) {
			nread = recv(fd1, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd0, (const char*)buffer_r, nread, 0);
		}
	}
}

void print_saddr4(const sockaddr_in sa) {
	char addrstr[256];
	inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr));
	printf("%s:%d", addrstr, htons(sa.sin_port));
}

void udp_relay(SOCKET control_fd, SOCKET local_fd) {
	int maxfd, ret;
	SOCKET remote_fd = INVALID_SOCKET;
	fd_set rd_set;
	maxfd = max(control_fd, local_fd);

	while (1) {
		FD_ZERO(&rd_set);
		FD_SET(control_fd, &rd_set);
		FD_SET(local_fd, &rd_set);
		if (remote_fd != INVALID_SOCKET)FD_SET(remote_fd, &rd_set);
		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
		if (ret == 0 || ret < 0 && WSAGetLastError() == WSAEINTR) {
			continue;
		}

		if (FD_ISSET(control_fd, &rd_set)) {
			break;
		}

		if (FD_ISSET(local_fd, &rd_set)) {
			char payload[2048 + 22];
			int payload_len = recv(local_fd, payload, sizeof(payload), 0);
			const char* addr; unsigned short port;
			if (!payload[2]) {
				char* p = payload + 3;
				socks_address_type addr_typ = socks5_address_from_buf(&p, &addr, &port);
				if (remote_fd == INVALID_SOCKET)
					remote_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
				SOCKADDR_STORAGE saddr_remote = gen_saddr(addr_typ, addr, port);

				//print_saddr4(*(sockaddr_in*)&saddr_remote);

				int rlen, slen = payload_len - (p - payload);
				if ((rlen = sendto(remote_fd, p, slen, 0, (sockaddr*)&saddr_remote, sizeof(saddr_remote))) < slen) {
					printf("Warning! [Ur<-] sent %d bytes, %d expected.\n", rlen, payload_len);
				}
			}
		}

		if (remote_fd != INVALID_SOCKET && FD_ISSET(remote_fd, &rd_set)) {
			SOCKADDR_STORAGE saddr_remote;
			int slen = sizeof(saddr_remote);
			char payload[2048 + 22];
			int rlen = recvfrom(remote_fd, payload + 22, sizeof(payload) - 22, 0, (sockaddr*)&saddr_remote, &slen);
			if (rlen > 0) {
				char* payload_real_start = NULL;
				if (saddr_remote.ss_family == AF_INET) {
					sockaddr_in* s4 = (sockaddr_in*)&saddr_remote;
					payload_real_start = payload + 12;
					*(unsigned short*)(payload_real_start + 8) = s4->sin_port;
					memcpy(payload_real_start + 4, &s4->sin_addr, 4);
					payload_real_start[3] = (char)IPV4;
					memset(payload_real_start, 0, 3);
				}
				else if (saddr_remote.ss_family == AF_INET6) {
					sockaddr_in6* s6 = (sockaddr_in6*)&saddr_remote;
					payload_real_start = payload;
					*(unsigned short*)(payload_real_start + 20) = s6->sin6_port;
					memcpy(payload_real_start + 4, &s6->sin6_addr, 16);
					payload_real_start[3] = (char)IPV6;
					memset(payload_real_start, 0, 3);
				}
				else {
					printf("Warning! Dropping incoming UDP packet with af=%d\n", saddr_remote.ss_family);
				}
				if (payload_real_start) {
					const int slen2 = payload + 22 + rlen - payload_real_start;
					int rlen2 = send(local_fd, payload_real_start, slen2, 0);
					if (rlen2 != slen2) {
						printf("Warning! [Ur->] sent %d bytes, %d expected.\n", rlen2, slen2);
					}
				}
			}
		}
	}
	if (remote_fd != INVALID_SOCKET)closesocket(remote_fd);

}

void socks5_send_ip_response(SOCKET fd, const SOCKADDR* saddr)
{
	switch (saddr->sa_family) {
	case AF_INET: {
		sockaddr_in* local4 = (sockaddr_in*)saddr;
		socks5_ipv4_send_response(fd, (char*)&local4->sin_addr, local4->sin_port);
		break;
	}
	case AF_INET6: {
		sockaddr_in6* local6 = (sockaddr_in6*)saddr;
		socks5_ipv6_send_response(fd, (char*)&local6->sin6_addr, local6->sin6_port);
		break;
	}
	default: {
		printf("Warning! sending 0.0.0.0 cause getsockname returned af=%d\n", saddr->sa_family);
		socks5_ipv4_send_response(fd, "\0\0\0\0", 0);
		break;
	}
	}
}

DWORD WINAPI app_thread_process(LPVOID fd)
{
	SOCKET net_fd = (SOCKET)fd;
	SOCKET inet_fd = INVALID_SOCKET;
	int nmethods = socks_invitation(net_fd);
	if (nmethods < 0)app_thread_exit(-1, net_fd);
	int version = nmethods >> 8; nmethods &= 0xff;

	switch (version) {
	case VERSION5:
	{
		if (socks5_auth(net_fd, nmethods) < 0)app_thread_exit(-1, net_fd);
		socks_command command = socks5_command(net_fd);
		if (command < 0)app_thread_exit(-2, net_fd);
		const char* addr; unsigned short int port;
		socks_address_type addr_typ = socks5_read_address(net_fd, &addr, &port);
		if (addr_typ < 0)app_thread_exit(-3, net_fd);
		SOCKADDR_STORAGE saddr = gen_saddr(addr_typ, addr, port);
		if (saddr.ss_family == 0)app_thread_exit(-4, net_fd);
		socks_free((void*)addr);

		switch (command) {
		case CONNECT:
		{
			SOCKET remote_fd = socket(saddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
			if (connect(remote_fd, (sockaddr*)&saddr, sizeof(saddr))) app_thread_exit(-5, net_fd, remote_fd);
			SOCKADDR_STORAGE local_saddr;
			int local_slen = sizeof(local_saddr);
			if (getsockname(remote_fd, (sockaddr*)&local_saddr, &local_slen))app_thread_exit(-6, net_fd, remote_fd);
			socks5_send_ip_response(net_fd, (sockaddr*)&local_saddr);
			tcp_bidirectional_forward(net_fd, remote_fd);
			closesocket(remote_fd);
		}
		break;
		case BIND:
		{
			log_message("BIND unsupported now.");
			app_thread_exit(-1, net_fd);
		}
		break;
		case UDP_ASSOCIATE:
		{
			SOCKET localu_fd = socket(saddr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
			if (connect(localu_fd, (sockaddr*)&saddr, sizeof(saddr))) app_thread_exit(-5, net_fd, localu_fd);
			SOCKADDR_STORAGE local_saddr;
			int local_slen = sizeof(local_saddr);
			if (getsockname(localu_fd, (sockaddr*)&local_saddr, &local_slen))app_thread_exit(-6, net_fd, localu_fd);
			socks5_send_ip_response(net_fd, (sockaddr*)&local_saddr);
			udp_relay(net_fd, localu_fd);
			closesocket(localu_fd);
		}
		break;
		}
	}
	break;
	case VERSION4:
		app_thread_exit(-100, net_fd);
		break;
	}

	app_thread_exit(0, net_fd);

	return NULL;
}

int app_loop()
{
	SOCKET sock_fd, net_fd;
	int optval = 1;
	SOCKADDR_IN local;
	SOCKADDR_IN6 remote;
	socklen_t remotelen;
	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_message("socket()");
		exit(1);
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval)) < 0) {
		log_message("setsockopt()");
		exit(1);
	}

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.S_un.S_addr = INADDR_ANY;
	local.sin_port = htons(port);

	if (bind(sock_fd, (struct sockaddr*)&local, sizeof(local)) < 0) {
		log_message("bind()");
		exit(1);
	}

	if (listen(sock_fd, 25) < 0) {
		log_message("listen()");
		exit(1);
	}

	memset(&remote, 0, sizeof(remote));

	log_message("Listening port %d...", port);

	HANDLE worker_thread;
	while (1) {
		remotelen = sizeof(remote);
		if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0) {
			log_message("accept()");
			exit(1);
		}
		int one = 1;
		setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
		if ((worker_thread = CreateThread(0, 0, app_thread_process, (LPVOID)net_fd, 0, 0)) == INVALID_HANDLE_VALUE) {
			log_message("CreateThread()");
		}
	}
}

void daemonize()
{
}

void usage(char* app)
{
	printf("USAGE: %s [-h][-n PORT][-a AUTHTYPE][-u USERNAME][-p PASSWORD][-l LOGFILE]\n", app);
	printf("AUTHTYPE: 0 for NOAUTH, 2 for USERPASS\n");
	printf("AUTHTYPE is broken now. Please don't use it!\n");
	printf("By default: port is 1080, authtype is no auth, logfile is stdout\n");
	exit(1);
}

int s5_server_main(int argc, char* argv[])
{
	int ret;
	log_file = stdout;
	auth_type = NOAUTH;
	InitializeCriticalSection(&log_lock);//pthread_mutex_init(&lock, NULL);

	init_domain_reverse_map();

	{
		WSADATA wsadata;
		WSAStartup(MAKEWORD(2, 2), &wsadata);
	}

	//signal(SIGPIPE, SIG_IGN);

	while ((ret = getopt(argc, argv, "n:u:p:l:a:hd")) != -1) {
		switch (ret) {
		case 'd': {
			daemon_mode = 1;
			daemonize();
			break;
		}
		case 'n': {
			port = atoi(optarg) & 0xffff;
			break;
		}
		case 'u': {
			//arg_username = _strdup(optarg);
			break;
		}
		case 'p': {
			//arg_password = _strdup(optarg);
			break;
		}
		case 'l': {
			FILE* f;
			if (freopen_s(&f, optarg, "wa", log_file) == 0) {
				log_file = f;
			}
			break;
		}
		case 'a': {
			auth_type = atoi(optarg);
			break;
		}
		case 'h':
		default:
			usage(argv[0]);
		}
	}
	log_message("Starting with authtype %X", auth_type);
	if (auth_type != NOAUTH) {
		//log_message("Username is %s, password is %s", arg_username, arg_password);
	}
	app_loop();
	return 0;
}

