/*
 * request used for client2server only
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-8-14
 */
#include "eventpack.h"
#include "ep_client_struct.h"
#include "ep_buffer.h"

#include "list.h"
#include "queue.h"

#include <sys/time.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

struct ep_req
{
	ep_client_t * client;

	ep_categroy_t category;
	ep_req_type req;
	ep_pack_t * pack;

	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

ep_pack_t * ep_default_dispatcher(void * opaque, int fd, ep_pack_t * pack, int * b_pack_reclaim)
{
	ep_req_t * handle;

	handle = (ep_req_t *)opaque;
	assert(fd != 0);

	pthread_mutex_lock(&handle->mutex);
	*b_pack_reclaim = 0;
	handle->pack = pack;
	pthread_cond_signal(&handle->cond);
	pthread_mutex_unlock(&handle->mutex);

	return NULL;
}

/*
 * create a request
 *
 * @ref report the number on the same category, this means ref will 
 *  >1 if you forget to destroy last request some where
 *
 * @result
 *     0 no error
 *    -1 socket error
 *    -2 memory allocated failed
 *
 * @return
 *     new request handle
 *     return NULL if failed
 */
ep_req_t * ep_req_new(ep_client_t * client, ep_req_param_t * param, int * result, int * ref)
{
	ep_req_t * handle;
    int pack_size;
    
	if (client == NULL)
	{
		if (result != NULL)
		{
			*result = -1;
		}

        assert(0);
		return NULL;
	}

    ep_pack_finish(param->pack);
    pack_size = ep_pack_size(param->pack);
    
	if (pack_size > client->conf.io_max_capacity)
	{
		if (result != NULL)
		{
			*result = -2;
		}

		if (client->disc_cb != NULL)
		{
			client->disc_cb(client->disc_opaque, ep_disc_capacity_overflow);
		}
        
        assert(0);
		return NULL;
	}

	{
		ep_buffer_t * shellbuf;
		ep_shell_t shell;
		int notify_ret;
		
		handle = (ep_req_t *)ep_calloc(1, sizeof(ep_req_t));
		if (handle == NULL)
		{
			if (result != NULL)
			{
				*result = -2;
			}
            
            assert(0);
			return NULL;
		}

		memset(&shell, 0, sizeof(shell));
		shell.magic = EP_MAGIC_NUMBER;
		shell.proto.category = param->category;
		shell.proto.c_crypt = param->c_crypt;
		shell.proto.c_compress = param->c_compress;
		shell.proto.s_crypt = param->s_crypt;
		shell.proto.s_compress = param->s_compress;
		shell.proto.type = param->type;

		pthread_mutex_init(&handle->mutex, NULL);
		pthread_cond_init(&handle->cond, NULL);
		handle->pack = NULL;
		handle->category = param->category;
		handle->client = client;

		if (ep_disp_add_cb(client->disp_mgr, handle->category, ep_default_dispatcher, handle) == 0)
		{
			pthread_mutex_destroy(&handle->mutex);
			pthread_cond_destroy(&handle->cond);
			ep_free(handle);

			if (result != NULL)
			{
				*result = -2;
			}
            
            assert(0);
			return NULL;
		}

		if (ref != NULL)
		{
			*ref = ep_disp_count(client->disp_mgr, param->category);
		}

		{
			ep_buffer_t * buffer;

			if (param->pack != NULL)
			{
				buffer = ep_buffer_new2(param->pack);	
			}
			else
			{
				buffer = NULL;
			}
			
			if (param->pack != NULL && buffer == NULL)
			{
				pthread_mutex_destroy(&handle->mutex);
				pthread_cond_destroy(&handle->cond);
				ep_free(handle);

				if (result != NULL)
				{
					*result = -2;
				}
                
                assert(0);
				return NULL;
			}

			shellbuf = ep_io_combine_shell(client->io_mgr, client->fd, &shell, buffer);
			ep_buffer_free(&buffer);
			if (shellbuf == NULL)
			{
				pthread_mutex_destroy(&handle->mutex);
				pthread_cond_destroy(&handle->cond);
				ep_free(handle);
				
				if (result != NULL)
				{
					*result = -2;
				}
                
                assert(0);
				return NULL;
			}
		}

		/* post event message which contoured by itself */
		notify_ret = ep_io_nodify_fd(client->io_mgr, client->fd, 1, shellbuf);
		if (notify_ret == 0)
		{
			pthread_mutex_destroy(&handle->mutex);
			pthread_cond_destroy(&handle->cond);
			ep_free(handle);

			if (result != NULL)
			{
				*result = -1;
			}
            
            assert(0);
			return NULL;
		}
	}
	
	if (result != NULL)
	{
		*result = 0;
	}

	return handle;
}

/*
 * wait for response returned, operation will be returned 
 *  when time reached or response returned
 *
 * @timeout wait timeout in seconds or <0 infinite
 *
 * @return
 *     2 request is a post message
 *     1 response ok
 *     0 time reached
 */
int ep_req_wait(ep_req_t * handle, ep_pack_t ** pack, int timeout)
{
	assert(handle != NULL);
	if (handle->req == req_type_post)
	{
		return 2;
	}

	pthread_mutex_lock(&handle->mutex);
	/* we do not need to wait if we have got req already */
	if (handle->pack == NULL)
	{
		if (timeout >= 0)
		{
			struct timespec ts;
			ts.tv_sec = time(NULL) + timeout;
			pthread_cond_timedwait(&handle->cond, &handle->mutex, &ts);
		}
		else
		{
			pthread_cond_wait(&handle->cond, &handle->mutex);
		}
	}
	pthread_mutex_unlock(&handle->mutex);

	if (handle->pack != NULL)
	{
		*pack = handle->pack;
		return 1;
	}

	return 0;
}

/*
 * destroy current request and cancel
 */
void ep_req_destroy(ep_req_t ** handle)
{
	if (handle == NULL || *handle == NULL)
	{
		assert(0);
		return;
	}

	pthread_mutex_lock(&(*handle)->mutex);
	pthread_cond_signal(&(*handle)->cond);
	pthread_mutex_unlock(&(*handle)->mutex);

	{
		int r;
		r = ep_disp_del_cb((*handle)->client->disp_mgr, (*handle)->category, ep_default_dispatcher, (*handle));
		assert(r == 1);
	}

	if ((*handle)->pack != NULL)
	{
		ep_pack_destroy(&(*handle)->pack);
	}

	pthread_mutex_destroy(&(*handle)->mutex);
	pthread_cond_destroy(&(*handle)->cond);
	ep_freep(*handle);
}
