/*
 * sock util
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-12-22
 */
#include "ep_util.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <string.h>
#include <assert.h>

/*
 * socket init in win32
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_win32_init(int init)
{
#ifdef _WIN32
	if (init)
	{
		WSADATA wsaData;
		int result;
	
		result = WSAStartup(MAKEWORD(2,2), &wsaData);
		return (result == NO_ERROR);
	}
	else
	{
		int result;
		result = WSACleanup();

		return (result == NO_ERROR);
	}
#else
	return 1;
#endif
}

/*
 * set socket block
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_setblock(int fd, int lock)
{
#ifdef _WIN32
	unsigned long flags = block ? 0 : 1;
	return ioctlsocket(fd, FIONBIO, &flags) != -1;
#else
	int flags;
	
	flags = fcntl(fd, F_GETFL, 0);
	flags = lock ? flags & ~O_NONBLOCK : flags | O_NONBLOCK;
	
	return fcntl(fd, F_SETFL, flags ) != -1;
#endif
}

/*
 * close socket
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_close(int fd)
{
#ifdef _WIN32
	return closesocket(fd) == NO_ERROR;
#else
	return close(fd) == 0;
#endif
}

/*
 * set socket keepalive, code from libuv
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_keepalive(int fd, int on, int delay)
{
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof(on)))
		return 0;
	
#ifdef TCP_KEEPIDLE
	if (on && setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &delay, sizeof(delay)))
		return 0;
#endif
	
	/* Solaris/SmartOS, if you don't support keep-alive,
	 * then don't advertise it in your system headers...
	 */
	/* FIXME(bnoordhuis) That's possibly because sizeof(delay) should be 1. */
#if defined(TCP_KEEPALIVE) && !defined(__sun)
	if (on && setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, (const char *)&delay, sizeof(delay)))
		return 0;
#endif
	
	return 1;
}

/*
 * get socket address by fd
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_ip(int fd, char ip[17], int * port)
{
	struct sockaddr_in sin;
	socklen_t len;
	int r;

	assert(fd > 0 && ip != NULL && port != NULL);

	*ip = 0;
	*port = 0;
	len = sizeof(sin);

	r = !getpeername(fd, (struct sockaddr *)&sin, &len);
	if (r)
	{
		strncpy(ip, inet_ntoa(sin.sin_addr), 16);
		ip[16] = '\0';
		*port = ntohs(sin.sin_port);
	}

	return r;
}
