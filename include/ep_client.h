/*
 * client interface
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-8-13
 */
#ifndef EP_CLIENT_H
#define EP_CLIENT_H

typedef struct ep_client_conf
{
	char ip[16 + 1];			/* server ip */
	int port;					/* server port */       
	int keepalive;				/* tcp keepalive */
	int io_def_capacity;		/* default capacity per-io */
	int io_max_capacity;		/* max capacity per-io */
	int wait_timeout;			/* second for wait server response */
	int mini_compress_if;		/* minimal size if compress or <=0 is 4KB */
} ep_client_conf_t;

typedef enum ep_client_disc
{
	ep_disc_sock_close,			/* socket close */
	ep_disc_bad_request,		/* bad request */
	ep_disc_capacity_overflow,	/* bad request */
	ep_disc_user_abort			/* user abort */
} ep_client_disc;

typedef struct ep_client ep_client_t;

/*
 * client disconnect callback
 */
typedef void (* pfn_ep_disc_cb)(void * opaque, ep_client_disc type);

/*
 * start client core
 *
 * @return
 *    1 start ok
 *    0 socket error
 *   -1 server set client EP_CRYPT failed
 *   -2 server not response
 *   -3 init module failed
 */
int ep_client_start(ep_client_conf_t * conf, ep_client_t ** client);

/*
 * notify when fd disconnect
 */
void ep_client_event(ep_client_t * client, pfn_ep_disc_cb disc_cb, void * opaque);

/*
 * register a dispatch callback
 *
 * @return
 *     1 ok
 *     0 if EP_MAJOR(category) <= EP_MAJOR_USER
 */
int ep_client_register(ep_client_t * client, ep_categroy_t category, pfn_ep_cb ep_cb, void * opaque);

/*
 * stop client core
 */
void ep_client_stop(ep_client_t ** client);

#endif
