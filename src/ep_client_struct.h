/*
 * client struct
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-8-13
 */
#ifndef EP_CLIENT_STRUCT_H
#define EP_CLIENT_STRUCT_H

#include <pthread.h>

#include "ep_io.h"
#include "ep_dispatch.h"

struct ep_client
{
	ep_client_conf_t conf;

	int fd;						/* ep_req use it */
	ep_io_mgr_t * io_mgr;		/* ep_req use it */
	ep_disp_mgr_t * disp_mgr;	/* ep_req use it */

	pfn_ep_disc_cb disc_cb;
	void * disc_opaque;

	pthread_t recv_thrd;
	int recv_loop;
};

#endif