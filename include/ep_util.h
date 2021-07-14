/*
 * sock util
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-12-22
 */
#ifndef EP_UTIL_H
#define EP_UTIL_H

/*
 * socket init in win32
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_win32_init(int init);

/*
 * set socket block
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_setblock(int fd, int lock);

/*
 * close socket
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_close(int fd);

/*
 * set socket keepalive
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_keepalive(int fd, int on, int delay);

/*
 * get socket address by fd
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_sock_ip(int fd, char ip[17], int * port);

#endif
