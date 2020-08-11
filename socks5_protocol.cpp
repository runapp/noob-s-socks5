#include "socks5_protocol.h"
#include <stdio.h>
#include <string.h>


#define countof(x) (sizeof(x)/sizeof(x[0]))
#define dbgprint printf

const socks_auth_methods supported_auth_types[] = { NOAUTH,USERPASS };
const char* arg_username = "user";
const char* arg_password = "pass";

int socks_invitation(SOCKS_FD fd)
{
	char init[2];
	int nread = readn(fd, init, sizeof(init));
	if (nread == 2 && init[0] != VERSION5 && init[0] != VERSION4) {
		dbgprint("They send us %hhX %hhX", init[0], init[1]);
		dbgprint("Incompatible version!");
		return -1;
	}
	return (init[0] << 8) | init[1];
}

// Read one byte length N, and then N bytes.
// Returned string needs freeing
char* socks5_auth_read_string(SOCKS_FD fd) {
	unsigned char size;
	readn(fd, (char*)&size, sizeof(size));

	char* ret = (char*)socks_alloc(sizeof(char) * size + 1);
	readn(fd, ret, (int)size);
	ret[size] = 0;

	return ret;
}

int socks5_auth_userpass(SOCKS_FD fd)
{
	char answer[2] = { VERSION5, USERPASS };
	writen(fd, answer, sizeof(answer));
	char resp;
	readn(fd, &resp, sizeof(resp));
	//dbgprint("auth %hhX", resp);
	char* username = socks5_auth_read_string(fd);
	char* password = socks5_auth_read_string(fd);
	//dbgprint("l: %s p: %s", username, password);
	if (strcmp(arg_username, username) == 0
		&& strcmp(arg_password, password) == 0) {
		char answer[2] = { AUTH_VERSION, AUTH_OK };
		writen(fd, answer, sizeof(answer));
		socks_free(username);
		socks_free(password);
		return 0;
	}
	else {
		char answer[2] = { (char)AUTH_VERSION, (char)AUTH_FAIL };
		writen(fd, answer, sizeof(answer));
		socks_free(username);
		socks_free(password);
		return 1;
	}
}

int socks5_auth_noauth(SOCKS_FD fd)
{
	char answer[2] = { VERSION5, (char)NOAUTH };
	writen(fd, answer, sizeof(answer));
	return 0;
}

void socks5_auth_notsupported(SOCKS_FD fd)
{
	char answer[2] = { VERSION5, (char)NOMETHOD };
	writen(fd, answer, sizeof(answer));
}

int socks5_auth(SOCKS_FD fd, int methods_count)
{
	int supported = 0;
	int num = methods_count;
	for (int i = 0; i < num; i++) {
		char type;
		readn(fd, &type, 1);
		//dbgprint("Method AUTH %hhX\n", type);
		if (type == NOAUTH) {
			supported = 1;
		}
	}
	if (supported == 0) {
		socks5_auth_notsupported(fd);
		return -1;
	}
	int ret = 0;
	switch (NOAUTH) {
	case NOAUTH:
		ret = socks5_auth_noauth(fd);
		break;
	case USERPASS:
		ret = socks5_auth_userpass(fd);
		break;
	}
	if (ret == 0) {
		return 0;
	}
	else {
		return -1;
	}
}

socks_command socks5_command(SOCKS_FD fd)
{
	char command[3];
	readn(fd, command, sizeof(command));
	//dbgprint("Command %hhX %hhX %hhX %hhX\n", command[0], command[1], command[2]);
	return (socks_command)command[1];
}

unsigned short int socks_read_port(SOCKS_FD fd)
{
	unsigned short int p;
	readn(fd, (char*)&p, sizeof(p));
	unsigned char* pp = (unsigned char*)&p;
	//dbgprint("Port %hu\n", (pp[0] << 8) | pp[1]);
	return p;
}

socks_address_type socks5_read_address(SOCKS_FD fd, const char** addr, unsigned short int* port) {
	unsigned char t;
	readn(fd, (char*)&t, 1);
	socks_address_type addr_typ = (socks_address_type)t;
	char* addr_t;
	switch (t) {
	case IPV4:
		addr_t = (char*)socks_alloc(4);
		readn(fd, addr_t, 4);
		break;
	case IPV6:
		addr_t = (char*)socks_alloc(16);
		readn(fd, addr_t, 16);
		break;
	case DOMAIN:
		addr_t = socks5_auth_read_string(fd);
		break;
	default:
		return (socks_address_type)-1;
	}
	*addr = addr_t;
	*port = socks_read_port(fd);
	return addr_typ;
}


socks_address_type socks5_address_from_buf(char** buf, const char** addr, unsigned short int* port) {
	char* p = *buf;
	unsigned char t = *(p++);
	socks_address_type addr_typ = (socks_address_type)t;
	switch (t) {
	case IPV4:
		*addr = p;
		p += 4;
		break;
	case IPV6:
		*addr = p;
		p += 16;
		break;
	case DOMAIN:
	{
		int domainlen = *(p++);
		*addr = p;
		p += domainlen;
		break;
	}
	default:
		return (socks_address_type)-1;
	}
	*port = *(unsigned short*)p;
	if (addr_typ == DOMAIN)*p = 0;
	p += 2; *buf = p;
	return addr_typ;
}

void socks5_ipv4_send_response(SOCKS_FD fd, const char* ip, unsigned short int port)
{
	char response[4] = { VERSION5, OK, RESERVED, IPV4 };
	writen(fd, response, sizeof(response));
	writen(fd, ip, 4);
	writen(fd, (char*)&port, sizeof(port));
}

void socks5_ipv6_send_response(SOCKS_FD fd, const char* ip, unsigned short int port)
{
	char response[4] = { VERSION5, OK, RESERVED, IPV6 };
	writen(fd, response, sizeof(response));
	writen(fd, ip, 16);
	writen(fd, (char*)&port, sizeof(port));
}


void socks5_domain_send_response(SOCKS_FD fd, const char* domain, unsigned char size, unsigned short int port)
{
	char response[4] = { VERSION5, OK, RESERVED, DOMAIN };
	writen(fd, response, sizeof(response));
	writen(fd, (char*)&size, sizeof(size));
	writen(fd, domain, size * sizeof(char));
	writen(fd, (char*)&port, sizeof(port));
}

int socks4_is_4a(char* ip)
{
	return (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0);
}

int socks4_read_nstring(SOCKS_FD fd, char* buf, int size)
{
	char sym = 0;
	int nread = 0;
	int i = 0;

	while (i < size) {
		nread = readn(fd, (char*)sym, sizeof(sym));

		if (nread <= 0) {
			break;
		}
		else {
			buf[i] = sym;
			i++;
		}

		if (sym == 0) {
			break;
		}
	}

	return i;
}

void socks4_send_response(SOCKS_FD fd, int status)
{
	char resp[8] = { 0x00, (char)status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	writen(fd, resp, sizeof(resp));
}
