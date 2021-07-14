/*
 * service interface
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-31
 */
#ifndef EP_SERVICE_H
#define EP_SERVICE_H

#include <time.h>

typedef struct ep_service_conf
{
	int listenport;             /* listen port */
	int backlog;                /* connect backlog */
	int keepalive;              /* tcp time alive */
	int nprocessors;            /* count of worker thread pool or <=0 is 1 */
	int io_def_capacity;        /* default capacity per-io */
	int io_max_capacity;        /* max capacity per-io */
	int mini_compress_if;       /* minimal size if compress or <=0 is 4KB */
} ep_service_conf_t;

typedef enum ep_event_type
{
	event_fd_accept = 0,        /* fd accept */
	event_fd_close,             /* fd close */
	event_io_overflow,          /* io is overflow than io_max_capacity */
	event_io_exception          /* io received a bad request checksum */
} ep_event_type;

/*
 * event callback
 */
typedef void (* ep_event_cb)(void * opaque, ep_event_type type, int fd);

/*
 * start engine
 *
 * @return
 *     0 start ok
 *    -1 bind error
 *    -2 listen error
 *    -3 init error
 */
int ep_service_start(ep_service_conf_t * conf);

/*
 * init register fd event
 */
void ep_service_event(ep_event_cb event_cb, void * opaque);

/*
 * register a dispatch callback
 *
 * @return
 *     1 ok
 *     0 if EP_MAJOR(category) <= EP_MAJOR_USER
 */
int ep_service_register(ep_categroy_t category, pfn_ep_cb ep_cb, void * opaque);

/*
 * push a message to client
 *
 * @fd client fd
 *
 * @notify_type
 *     0 notify all (ignore fd)
 *     1 notify just fd
 *     2 notify except fd
 *
 * @return
 *   >=1 if notify ok
 *     0 failed
 */
int ep_service_push(int fd, int notify_type, ep_req_param_t * param);

/*
 * stop engine
 */
void ep_service_stop();

#endif
