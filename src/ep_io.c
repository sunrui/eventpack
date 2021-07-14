/*
 * io header
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-31
 */
#include "eventpack.h"
#include "ep_buffer.h"
#include "ep_io.h"
#include "ep_dispatch.h"

#include "list.h"
#include "htonll.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

typedef struct ep_io
{
	ep_queue_t * send;
	ep_rb_t * recv;

	ep_shell_t shell;
	ep_bool_t b_shell_cached;

	ep_aes_key_t aes;

	int fd;
	void * fd_extra;

	struct list_head list;
} ep_io_t;

typedef struct ep_io_send
{
	ep_io_mgr_t * io_mgr;

	ep_io_send_cb send;
	pthread_t thread;
	ep_queue_t * queue;
	int abort;
} ep_io_send_t;

typedef struct ep_io_task
{
	ep_io_mgr_t * io_mgr;
	int fd;

	ep_shell_t shell;
	ep_buffer_t * in;
} ep_io_task_t;

struct ep_io_mgr
{
	ep_io_refor refor;

	ep_disp_mgr_t * disp_mgr;
	ep_io_send_t send;
	ep_tp_t * thread_pool;

	int def_capacity;
	int max_capacity;
	int mini_compress_if;

	pthread_mutex_t lock;
	struct list_head io_list;
};

/*
 * find a ep_io by fd
 */
ep_io_t * ep_io_find(ep_io_mgr_t * io_mgr, int fd)
{
	struct list_head * pos;
	ep_io_t * child;
	ep_io_t * tmp;

	child = NULL;
	tmp = NULL;

	list_for_each(pos, &io_mgr->io_list)
	{
		tmp = list_entry(pos, ep_io_t, list);
		if (tmp->fd == fd)
		{
			child = tmp;
			break;
		}
	}

	return child;
}

/*
 * get a body from queue
 *
 * @body	body if get ok, you must manual free it.
 * @timeout	send timeout in milliseconds or < 0 if infinite
 *
 * @return
 *     1 get it ok
 *     0 no more buffers now (timeout reached)
 *    -1 by your abort
 */
int ep_io_get(ep_io_mgr_t * io_mgr, int fd, ep_buffer_t ** out, int timeout)
{
	ep_io_t * child;
	int ret = 0;

	assert(out != NULL);
	*out = NULL;

	pthread_mutex_lock(&io_mgr->lock);
	child = ep_io_find(io_mgr, fd);
	if (child != NULL)
	{
		ret = ep_queue_get(child->send, (void **)out, timeout);
	}
	pthread_mutex_unlock(&io_mgr->lock);

	return ret;
}

void * ep_io_routine(void * param)
{
	ep_io_send_t * send = (ep_io_send_t *)param;
	ep_io_mgr_t * io_mgr = send->io_mgr;

	while (!send->abort)
	{
		ep_buffer_t * buffer;
		ep_io_t * io;
		int got_ret;

		got_ret = ep_queue_get(send->queue, (void **)&io, -1);
		if (got_ret == 1)
		{
            char * buffer_ptr;
            int buffer_size;
			int send_bytes;

			/* process all requests in queue */
			while ((got_ret = ep_io_get(io_mgr, io->fd, &buffer, 0)) == 1)
			{
                buffer_size = ep_buffer_size(buffer);
                ep_buffer_free_shell(&buffer, &buffer_ptr);
				assert(buffer_size > 0);

                send_bytes = send->send(io->fd, buffer_ptr, buffer_size, io->fd_extra);
                if (send_bytes <= 0)
				{
                    assert(0);
					break;
				}
			}
		}
		else
		{
			break;
		}
	}

	return NULL;
}

/*
 * io module init
 *
 * @client set to 0 if this io is signed as client or 1 as server
 */
ep_io_mgr_t * ep_io_init(ep_io_refor refor, ep_disp_mgr_t * disp_mgr, ep_io_send_cb send_cb, int nprocessors, int def_capacity, int max_capacity, int mini_compress_if)
{
	ep_io_mgr_t * io_mgr;

	assert(def_capacity > 0 && max_capacity > def_capacity && nprocessors > 0 && send_cb != NULL);
	io_mgr = (ep_io_mgr_t *)ep_calloc(1, sizeof(ep_io_mgr_t));
	if (io_mgr == NULL)
	{
        assert(0);
		return NULL;
	}

	io_mgr->send.queue = ep_queue_new();
	if (io_mgr->send.queue == NULL)
	{
        assert(0);
		ep_free(io_mgr);
		return NULL;
	}

	io_mgr->thread_pool = ep_tp_create(nprocessors);
	if (io_mgr->thread_pool == NULL)
	{
        assert(0);
		ep_queue_destroy(&io_mgr->send.queue);
		ep_free(io_mgr);
		return NULL;
	}

	if (mini_compress_if <= 0)
	{
		mini_compress_if = 4096;
	}

	io_mgr->refor = refor;
	io_mgr->disp_mgr = disp_mgr;
	io_mgr->def_capacity = def_capacity;
	io_mgr->max_capacity = EP_MAX(max_capacity, def_capacity);
	io_mgr->mini_compress_if = mini_compress_if;
	io_mgr->send.send = send_cb;
	io_mgr->send.io_mgr = io_mgr;
	io_mgr->send.abort = 0;
	INIT_LIST_HEAD(&io_mgr->io_list);
	pthread_mutex_init(&io_mgr->lock, NULL);
	pthread_create(&io_mgr->send.thread, NULL, ep_io_routine, &io_mgr->send);

	return io_mgr;
}

void * ep_io_processor(void * opaque)
{
	ep_io_task_t * task;
	ep_io_mgr_t * io_mgr;
	ep_pack_t * ret_packet;
	ep_shell_t * shell;
	ep_buffer_t * in;
	int fd;

	task = (ep_io_task_t *)opaque;
	assert(task != NULL);
	io_mgr = task->io_mgr;
	fd = task->fd;
	shell = &task->shell;
	in = task->in;

	if (shell->shell_size != 0)
	{
		in = ep_io_recombine_original(io_mgr, fd, shell, in);
		if (in == NULL)
		{
            assert(0);
			ep_free(task);
			return NULL;
		}
	}

	{
		ep_pack_t * pack;

		/* some request maybe no have a body */
		if (in != NULL)
		{
			pack = ep_pack_create(ep_buffer_ptr(in), ep_buffer_size(in));
			ep_buffer_free(&in);
			if (pack == NULL)
			{
                assert(0);
				ep_free(task);
				return NULL;
			}
		}
		else
		{
			pack = NULL;
		}

		ret_packet = ep_disp_processor(io_mgr->disp_mgr, shell->proto.category, fd, pack);
		if (ret_packet)
		{
			ep_pack_finish(ret_packet);
		}
	}

	/* if their is just a post request, no need reply here */
	if (shell->proto.type == req_type_post)
	{
		ep_free(task);
		return NULL;
	}

	{
		ep_buffer_t * body;
		shell->proto.type = req_type_post;

		body = NULL;
		if (ret_packet != NULL)
		{
			ep_buffer_t * in;

			in = ep_buffer_new2(ret_packet);
			ep_pack_destroy(&ret_packet);
			if (in == NULL)
			{
                assert(0);
				ep_free(task);
				return NULL;
			}

			if (in != NULL)
			{
				body = ep_io_combine_shell(io_mgr, fd, shell, in);
				ep_buffer_free(&in);
				if (body == NULL)
				{
                    assert(0);
					ep_free(task);
					return NULL;
				}
			}
		}

		if (body != NULL)
		{
			ep_io_t * child;

			pthread_mutex_lock(&io_mgr->lock);
			child = ep_io_find(io_mgr, fd);
			if (child != NULL)
			{
				ep_queue_push(child->send, body);
				ep_queue_push(io_mgr->send.queue, child);
			}
			else
			{
				ep_buffer_free(&body);
			}
			pthread_mutex_unlock(&io_mgr->lock);
		}
	}

	ep_free(task);
	return NULL;
}

/*
 * io request dispatcher
 */
void ep_io_request_dispatcher(ep_io_mgr_t * io_mgr, int fd, ep_shell_t * shell, ep_buffer_t * in)
{
	ep_io_task_t * task;
	task = (ep_io_task_t *)ep_calloc(1, sizeof(ep_io_task_t));
	if (task == NULL)
	{
        assert(0);
		return;
	}

	task->io_mgr = io_mgr;
	task->fd = fd;
	task->shell = *shell;
	task->in = in;

	ep_tp_worker_register(io_mgr->thread_pool, ep_io_processor, NULL, task);
}

/*
 * combine a shell and body to a buffer
 *
 * @client
 *    if this combine is for client set it to 0, 'in' will be processed refer to 'crypt' and 'compress',
 *     other wise set it to 1, 'in' will refer to 's_crypt and 's_compress'
 */
ep_buffer_t * ep_io_combine_shell(ep_io_mgr_t * io_mgr, int fd, ep_shell_t * shell, ep_buffer_t * in)
{
	ep_buffer_t * out;
	char * out_buf;
	int out_size;
	const char * shell_buffer;
	int shell_size;

	if (in != NULL)
	{
		ep_compress_type compress;
		ep_crypt_type crypt;

		shell->pack_size = ep_buffer_size(in);

		compress = (io_mgr->refor == ep_io_refor_client) ? shell->proto.c_compress : shell->proto.s_compress;
		crypt = (io_mgr->refor == ep_io_refor_client) ? shell->proto.c_crypt : shell->proto.s_crypt;

		if (compress == compress_type_compress)
		{
			in = ep_buffer_compress(in);
			if (in == NULL)
			{
                assert(0);
				return NULL;
			}
		}
		else if (compress == compress_type_auto)
		{
			/* only compress if body large than mini_compress_if */
			if (ep_buffer_size(in) > io_mgr->mini_compress_if)
			{
				if (io_mgr->refor == ep_io_refor_client)
				{
					shell->proto.c_compress = compress_type_compress;
				}
				else
				{
					shell->proto.s_compress = compress_type_compress;
				}

				in = ep_buffer_compress(in);
				if (in == NULL)
				{
                    assert(0);
					return NULL;
				}
			}
			else
			{
				if (io_mgr->refor == ep_io_refor_client)
				{
					shell->proto.c_compress = compress_type_none;
				}
				else
				{
					shell->proto.s_compress = compress_type_none;
				}
			}
		}

		shell->decrypt_size = ep_buffer_size(in);
		if (crypt == crypt_type_encrypt)
		{
			ep_aes_key_t aes;
			int ret;

			ret = ep_io_get_aes(io_mgr, fd, &aes);
			if (ret == 0)
			{
                assert(0);
				return NULL;
			}

			in = ep_buffer_encrypt(in, &aes);
			if (in == NULL)
			{
                assert(0);
				return NULL;
			}
		}

		shell_buffer = ep_buffer_ptr(in);
		shell_size = ep_buffer_size(in);
	}
	else
	{
		shell->pack_size = 0;
		shell_buffer = NULL;
		shell_size = 0;
	}

	out_size = sizeof(ep_shell_t) + shell_size;
	out_buf = (char *)ep_malloc(sizeof(ep_shell_t) + shell_size + 1);
	if (out_buf == NULL)
	{
		return NULL;
	}

	shell->shell_size = shell_size;

	/* host endian to network endian */
	{
		shell->magic = htons(shell->magic);

		{
			uint32_t n_proto;
			n_proto = htonl(*(uint32_t *)&shell->proto);
			memcpy(&shell->proto, &n_proto, sizeof(uint32_t));
		}

		shell->shell_size = htonl(shell->shell_size);
		shell->decrypt_size = htonl(shell->decrypt_size);
		shell->pack_size = htonl(shell->pack_size);
	}

	memcpy(out_buf, shell, sizeof(ep_shell_t));
	memcpy(out_buf + sizeof(ep_shell_t), shell_buffer, shell_size);
	out = ep_buffer_new(out_buf, out_size);
	ep_free(out_buf);

	return out;
}

/*
 * recombine and get original body buffer
 */
ep_buffer_t * ep_io_recombine_original(ep_io_mgr_t * io_mgr, int fd, ep_shell_t * shell, ep_buffer_t * in)
{
	ep_compress_type compress;
	ep_crypt_type crypt;

	compress = (io_mgr->refor == ep_io_refor_client) ? shell->proto.s_compress : shell->proto.c_compress;
	crypt = (io_mgr->refor == ep_io_refor_client) ? shell->proto.s_crypt : shell->proto.c_crypt;

	if (crypt == crypt_type_encrypt)
	{
		ep_aes_key_t aes;
		int ret;

		ret = ep_io_get_aes(io_mgr, fd, &aes);
		if (ret == 0)
		{
            assert(0);
			return NULL;
		}

		in = ep_buffer_decrypt(in, &aes, shell->decrypt_size);
		if (in == NULL)
		{
            assert(0);
			return NULL;
		}
	}

	if (compress == compress_type_compress)
	{
		in = ep_buffer_decompress(in, shell->pack_size);
		if (in == NULL)
		{
            assert(0);
			return NULL;
		}
	}

	return in;
}

/*
 * io insert a new fd
 *
 * @return
 *     1 add ok
 *     0 exist no need add
 */
int ep_io_add(ep_io_mgr_t * io_mgr, int fd, void * extra)
{
	ep_io_t * child;
	int ret = 0;

	pthread_mutex_lock(&io_mgr->lock);
	child = ep_io_find(io_mgr, fd);
	if (child == NULL)
	{
		child = (ep_io_t *)ep_calloc(1, sizeof(ep_io_t));
		if (child == NULL)
		{
            assert(0);
			pthread_mutex_unlock(&io_mgr->lock);
			return 0;
		}

		child->recv = ep_rb_new(io_mgr->def_capacity, io_mgr->max_capacity);
		if (child->recv == NULL)
		{
            assert(0);
			pthread_mutex_unlock(&io_mgr->lock);
			ep_free(child);
			return 0;
		}

		child->send = ep_queue_new();
		if (child->send == NULL)
		{
            assert(0);
			pthread_mutex_unlock(&io_mgr->lock);
			ep_rb_free(&child->recv);
			ep_free(child);
			return 0;
		}

		child->fd = fd;
		child->fd_extra = extra;
		child->b_shell_cached = 0;
		list_add_tail(&child->list, &io_mgr->io_list);
		ret = 1;
	}
	pthread_mutex_unlock(&io_mgr->lock);

	return ret;
}

/*
 * serialize received buffer to ep_buffer_t
 *
 * @return
 *     1 enqueue and send processor pool ok
 *     0 received ok but buffer is not enough
 *    -1 got a bad request
 *    -2 max capacity overflow
 *    -3 socket not valid
 */
int ep_io_enqueue(ep_io_mgr_t * io_mgr, int fd, const char * inbuf, int insize)
{
	ep_io_t * child;

	assert(inbuf != NULL && insize != 0);
	pthread_mutex_lock(&io_mgr->lock);
	child = ep_io_find(io_mgr, fd);

	if (child == NULL)
	{
        assert(0);
		pthread_mutex_unlock(&io_mgr->lock);
		return -3;
	}

	{
		int writed;
		writed = ep_rb_write(child->recv, inbuf, insize);
		if (writed < insize)
		{
            assert(0);
			pthread_mutex_unlock(&io_mgr->lock);
			return -2;
		}
	}

	for (;;)
	{
		ep_buffer_t * in;

		if (!child->b_shell_cached && ep_rb_can_read(child->recv) < (int)sizeof(child->shell))
		{
			pthread_mutex_unlock(&io_mgr->lock);
			/* not enough for a package header */
			return 0;
		}

		if (!child->b_shell_cached)
		{
			ep_shell_t * shell;

			ep_rb_read(child->recv, (char **)&shell, sizeof(child->shell));
			child->shell = *shell;

			/* network endian to host endian */
			{
				child->shell.magic = ntohs(child->shell.magic);

				{
					uint32_t n_proto;
					n_proto = ntohl(*(uint32_t *)&child->shell.proto);
					memcpy(&child->shell.proto, &n_proto, sizeof(uint32_t));
				}

				child->shell.shell_size = ntohl(child->shell.shell_size);
				child->shell.decrypt_size = ntohl(child->shell.decrypt_size);
				child->shell.pack_size = ntohl(child->shell.pack_size);
			}
		}

		if (child->shell.magic != EP_MAGIC_NUMBER)
		{
            assert(0);
			pthread_mutex_unlock(&io_mgr->lock);
			return -1;
		}

		if (child->shell.shell_size > io_mgr->max_capacity)
		{
            assert(0);
			pthread_mutex_unlock(&io_mgr->lock);
			return -2;
		}

		if (ep_rb_can_read(child->recv) < child->shell.shell_size)
		{
			/* not enough for a package body */
			child->b_shell_cached = 1;
			break;
		}

		in = NULL;
		if (child->shell.shell_size != 0)
		{
			char * body;
			ep_rb_read(child->recv, &body, child->shell.shell_size);
			in = ep_buffer_new(body, child->shell.shell_size);
		}

		/* dispatcher a request */
		ep_io_request_dispatcher(io_mgr, fd, &child->shell, in);
		child->b_shell_cached = 0;
	}

	pthread_mutex_unlock(&io_mgr->lock);

	return 1;
}

/*
 * send client an message
 *
 * @curfd current fd
 *
 * @notify_type
 *     0 notify all
 *     1 notify just curfd
 *     2 notify except curfd
 *
 * @return
 *   >=1 if notify ok
 *     0 failed
 */
int ep_io_nodify_fd(ep_io_mgr_t * io_mgr, int curfd, int notify_type, ep_buffer_t * in)
{
	struct list_head * pos;
	ep_io_t * tmp;
	int cnt;

	cnt = 0;
	pthread_mutex_lock(&io_mgr->lock);
	list_for_each(pos, &io_mgr->io_list)
	{
		tmp = list_entry(pos, ep_io_t, list);

		/* do not post any event message which contoured by itself */
		/*  we must notify user he is login from another place */
		if (notify_type == 1)
		{
			if (tmp->fd != curfd)
			{
				continue;
			}
		}
		else if (notify_type == 2)
		{
			if (tmp->fd == curfd)
			{
				continue;
			}
		}
		else
		{
			assert(notify_type == 0);
		}

		ep_queue_push(tmp->send, in);
		ep_queue_push(io_mgr->send.queue, tmp);
		cnt++;
	}
	pthread_mutex_unlock(&io_mgr->lock);

	return cnt;
}

/*
 * update io crypt key/vec
 *
 * @return
 *     1 if notify ok
 *     0 failed
 */
int ep_io_update_aes(ep_io_mgr_t * io_mgr, int fd, ep_aes_key_t * aes)
{
	ep_io_t * tmp;
	int ret;

	ret = 0;
	pthread_mutex_lock(&io_mgr->lock);
	tmp = ep_io_find(io_mgr, fd);
	if (tmp != NULL)
	{
		memcpy(tmp->aes.key, aes->key, sizeof(tmp->aes.key));
		memcpy(tmp->aes.vec, aes->vec, sizeof(tmp->aes.vec));
		ret = 1;
	}
	pthread_mutex_unlock(&io_mgr->lock);

	return ret;
}


/*
 * get aes key/vec
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_io_get_aes(ep_io_mgr_t * io_mgr, int fd, ep_aes_key_t * aes)
{
	ep_io_t * tmp;
	int ret;

	ret = 0;
	pthread_mutex_lock(&io_mgr->lock);
	tmp = ep_io_find(io_mgr, fd);
	if (tmp != NULL)
	{
		memcpy(aes->key, tmp->aes.key, sizeof(tmp->aes.key));
		memcpy(aes->vec, tmp->aes.vec, sizeof(tmp->aes.vec));
		ret = 1;
	}

	assert(ret == 1);
	pthread_mutex_unlock(&io_mgr->lock);
	return ret;
}

/*
 * stop a io
 */
void ep_io_stop(ep_io_mgr_t * io_mgr, int fd)
{
	ep_io_t * tmp;

	pthread_mutex_lock(&io_mgr->lock);
	tmp = ep_io_find(io_mgr, fd);
	if (tmp != NULL)
	{
		ep_queue_stop(tmp->send);
	}
	pthread_mutex_unlock(&io_mgr->lock);
}

/*
 * discard a fd ensure that no longer used
 *
 * return
 *    1 success
 *    0 failed
 */
int ep_io_del(ep_io_mgr_t * io_mgr, int fd)
{
	struct list_head * pos, * q;
	ep_io_t * tmp;
	int ret;

	ret = 0;
	pthread_mutex_lock(&io_mgr->lock);
	list_for_each_safe(pos, q, &io_mgr->io_list)
	{
		tmp = list_entry(pos, ep_io_t, list);
		if (tmp->fd == fd)
		{
			list_del(pos);
			{
				ep_buffer_t * buffer;

				ep_queue_stop(tmp->send);
				while (ep_queue_get(tmp->send, (void **)&buffer, 0) == 1)
				{
					ep_buffer_free(&buffer);
				}
				ep_queue_destroy(&tmp->send);
			}

			ep_rb_free(&tmp->recv);
			ep_freep(tmp);

			ret = 1;
			break;
		}
	}

	assert(ret == 1);
	pthread_mutex_unlock(&io_mgr->lock);

	return ret;
}

/*
 * io module destroy
 */
void ep_io_destroy(ep_io_mgr_t ** io_mgr)
{
	if (io_mgr == NULL || *io_mgr == NULL)
	{
		assert(0);
		return;
	}

	(*io_mgr)->send.abort = 1;
	ep_queue_stop((*io_mgr)->send.queue);
	pthread_join((*io_mgr)->send.thread, NULL);

	{
		struct list_head * pos, * q;
		ep_buffer_t * buffer;
		ep_io_t * tmp;

		pthread_mutex_lock(&(*io_mgr)->lock);
		list_for_each_safe(pos, q, &(*io_mgr)->io_list)
		{
			tmp = list_entry(pos, ep_io_t, list);

			list_del(pos);
			ep_queue_stop(tmp->send);

			while (ep_queue_get(tmp->send, (void **)&buffer, 0) == 1)
			{
				ep_buffer_free(&buffer);
			}

			ep_queue_destroy(&tmp->send);
			ep_rb_free(&tmp->recv);
			ep_freep(tmp);
		}
		pthread_mutex_unlock(&(*io_mgr)->lock);
	}

	{
		ep_io_t * io;
		int got_ret;

		while (ep_queue_get((*io_mgr)->send.queue, (void **)&io, 0) == 1)
		{
			ep_buffer_t * buffer;

			while ((got_ret = ep_io_get(*io_mgr, io->fd, &buffer, 0)) == 1)
			{
				ep_buffer_free(&buffer);
			}
		}

		ep_queue_destroy(&(*io_mgr)->send.queue);
	}

	ep_tp_destroy(&(*io_mgr)->thread_pool, tp_kill_wait);
	pthread_mutex_destroy(&(*io_mgr)->lock);
	ep_freep(*io_mgr);
}
