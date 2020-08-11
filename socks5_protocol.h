#pragma once

#include <basetsd.h>

typedef UINT_PTR SOCKS_FD;
// returns bytes read/written
//typedef int (*readn_func)(SOCKS5_FD, char* buf, int len);
//typedef int (*writen_func)(SOCKS5_FD, char* buf, int len);
extern int readn(SOCKS_FD, char* buf, int len);
extern int writen(SOCKS_FD, const char* buf, int len);
extern void* socks_alloc(int size);
extern void socks_free(void* p);

enum socks {
	RESERVED = 0x00,
	VERSION4 = 0x04,
	VERSION5 = 0x05
};

enum socks_auth_methods {
	NOAUTH = 0x00,
	USERPASS = 0x02,
	NOMETHOD = 0xff
};

enum socks_auth_userpass {
	AUTH_OK = 0x00,
	AUTH_VERSION = 0x01,
	AUTH_FAIL = 0xff
};

enum socks_command {
	CONNECT = 0x01,
	BIND = 0x02,
	UDP_ASSOCIATE = 0x03,
};

enum socks_address_type {
	IPV4 = 0x01,
	DOMAIN = 0x03,
	IPV6 = 0x04,
};

enum socks_status {
	OK = 0x00,
	FAILED = 0x05
};

int socks_invitation(SOCKS_FD fd);
int socks5_auth_userpass(SOCKS_FD fd);
int socks5_auth_noauth(SOCKS_FD fd);
void socks5_auth_notsupported(SOCKS_FD fd);
int socks5_auth(SOCKS_FD fd, int methods_count);
socks_command socks5_command(SOCKS_FD fd);
socks_address_type socks5_read_address(SOCKS_FD fd, const char** addr, unsigned short int* port);
socks_address_type socks5_address_from_buf(char** buf, const char** addr, unsigned short int* port);
void socks5_ipv4_send_response(SOCKS_FD fd, const char* ip, unsigned short int port);
void socks5_ipv6_send_response(SOCKS_FD fd, const char* ip, unsigned short int port);
void socks5_domain_send_response(SOCKS_FD fd, const char* domain, unsigned char size, unsigned short int port);
int socks4_is_4a(char* ip);
int socks4_read_nstring(SOCKS_FD fd, char* buf, int size);
void socks4_send_response(SOCKS_FD fd, int status);

