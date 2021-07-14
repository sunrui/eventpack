/*
 * service socket module
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-11-2
 */
#include "ep_socket.h"
#include "eventpack.h"

#include "uv.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#ifdef EP_HAVE_SERVER

typedef struct write_req
{
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;


static uv_async_t s_loop_send;
static char * s_loop_send_buffer;
static int s_loop_send_buffer_size;
static uv_stream_t * s_loop_send_stream;
static pthread_mutex_t s_loop_send_mutex;

static uv_async_t s_loop_exit;
static pthread_t s_loop_thread;
static uv_loop_t * s_loop;
static uv_tcp_t s_fd;

static service_core_cb s_core_cb;
static void * s_core_opaque;

void accept_cb(uv_stream_t * server, int status);
void alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t * buf);
void read_cb(uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf);
int fd_write(uv_stream_t * stream, char * buffer, int size);
void write_cb(uv_write_t * req, int status);
void fd_shutdown(uv_stream_t * stream);
void shutdown_cb(uv_shutdown_t * req, int status);
void close_cb(uv_handle_t * handle);

int uv_sock_fd(void * stream)
{
	uv_tcp_t * tcp = (uv_tcp_t *)stream;
	int fd;

#ifdef _WIN32
	fd = tcp->socket;
#else
	fd = tcp->io_watcher.fd;
#endif

	assert(fd != 0);
	return fd;
}

void accept_cb(uv_stream_t * server, int status)
{
	uv_stream_t * stream;
	int r;

	if (status != 0 || server != (uv_stream_t *)&s_fd)
	{
        assert(0);
		return;
	}

	stream = (uv_stream_t *)ep_calloc(1, sizeof(uv_tcp_t));
	if (stream == NULL)
	{
        assert(0);
		return;
	}

	r = uv_tcp_init(s_loop, (uv_tcp_t *)stream);
	assert(r == 0);
	stream->data = server;
	r = uv_accept(server, (uv_stream_t *)stream);
	assert(r == 0);

	s_core_cb.on_accept(s_core_opaque, uv_sock_fd(stream), stream);

	r = uv_read_start((uv_stream_t *)stream, alloc_cb, read_cb);
	assert(r == 0);
}

void alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	suggested_size = 4096;
	buf->base = (char *)ep_malloc(suggested_size);
	buf->len = (buf->base != NULL) ? suggested_size : 0;
	assert(buf->base != NULL && buf->len != 0);
}

void write_cb(uv_write_t * req, int status)
{
	write_req_t * wr;

	wr = (write_req_t *)req;
    ep_free(wr->buf.base);
	ep_free(wr);
}

int fd_write(uv_stream_t * stream, char * buffer, int size)
{
	write_req_t * wr;
    
    assert(buffer != NULL && size > 0);
	wr = (write_req_t *)ep_calloc(1, sizeof(write_req_t));
	if (wr == NULL)
	{
        assert(0);
		return 0;
	}

	wr->buf.base = buffer;
	wr->buf.len = size;
	uv_write(&wr->req, stream, &wr->buf, 1, write_cb);

	//- fixed me for real size
	return size;
}

void fd_shutdown(uv_stream_t * stream)
{
	uv_shutdown_t * req;

	s_core_cb.on_close(s_core_opaque, uv_sock_fd(stream));
	req = (uv_shutdown_t *)ep_malloc(sizeof(uv_shutdown_t));
	if (req != NULL)
	{
		uv_shutdown(req, stream, shutdown_cb);
	}
}

void read_cb(uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{
	int ret = 0;

	if (nread < 0)
	{
        assert(0);
		if (buf->base != NULL)
		{
			ep_free(buf->base);
		}

		fd_shutdown(stream);
		return;
	}

	if (nread == 0)
	{
		if (buf->base != NULL)
		{
			ep_free(buf->base);
		}

		return;
	}

	ret = s_core_cb.on_read(s_core_opaque, uv_sock_fd(stream), buf->base, nread);
	ep_free(buf->base);
	if (ret != 1)
	{
		fd_shutdown(stream);
	}
}

void shutdown_cb(uv_shutdown_t * req, int status)
{
	uv_close((uv_handle_t *)req->handle, close_cb);
	ep_free(req);
}

void close_cb(uv_handle_t * handle)
{
	ep_free(handle);
}

void exit_async_cb(uv_async_t * handle, int status)
{
	uv_stop(s_loop);
	uv_close((uv_handle_t *)&s_loop_exit, NULL);
}

void send_async_cb(uv_async_t * handle, int status)
{
    char * buffer = s_loop_send_buffer;
    int size = s_loop_send_buffer_size;
    uv_stream_t * extra =  s_loop_send_stream;

    fd_write((uv_stream_t *)extra, buffer, size);
    pthread_mutex_unlock(&s_loop_send_mutex);
}

void * ep_loop_proc(void * param)
{
	uv_run(s_loop, UV_RUN_DEFAULT);
	s_loop = NULL;

	return NULL;
}

/*
 * start engine
 *
 * @return
 *     0 start ok
 *    -1 bind error
 *    -2 listen error
 */
int service_core_start(int port, int backlog, int keepalive, service_core_cb core_cb, void * opaque)
{
	struct sockaddr_in addr;
	int r;

	assert(port > 0 && backlog > 0);
	assert(s_loop == NULL);

	s_core_cb = core_cb;
	s_core_opaque = opaque;
    
    uv_ip4_addr("127.0.0.1", port, &addr);
    s_loop = uv_default_loop();
	r = uv_tcp_init(s_loop, &s_fd);
	assert(r == 0);

	r = uv_tcp_bind(&s_fd, (struct sockaddr *)&addr);
	if (r < 0)
	{
		return -1;
	}

	r = uv_listen((uv_stream_t *)&s_fd, backlog, accept_cb);
	if (r < 0)
	{
		return -2;
	}

	/* set buffer event read timeval and write timeval in seconds*/
	if (keepalive > 0)
	{
		uv_tcp_keepalive(&s_fd, 1, keepalive);
	}
    
    pthread_mutex_init(&s_loop_send_mutex, NULL);
	uv_async_init(s_loop, &s_loop_exit, exit_async_cb);
    uv_async_init(s_loop, &s_loop_send, send_async_cb);
	pthread_create(&s_loop_thread, NULL, ep_loop_proc, NULL);

	return 0;
}

int service_core_send(int fd, char * buffer, int size, void * extra)
{
    //- due to uv_write is not thread safe
    //return fd_write((uv_stream_t *)extra, buffer, size);
    
    pthread_mutex_lock(&s_loop_send_mutex);
    s_loop_send_buffer = buffer;
    s_loop_send_buffer_size = size;
    s_loop_send_stream = (uv_stream_t *)extra;
	uv_async_send(&s_loop_send);
    
    //- fix me for real size
    return size;
}

void service_core_shutdown(int fd, void * extra)
{
	fd_shutdown((uv_stream_t *)extra);
}

void service_core_stop()
{
	assert(s_loop != NULL);
	uv_async_send(&s_loop_exit);
	uv_close((uv_handle_t *)&s_fd, NULL);
	pthread_join(s_loop_thread, NULL);
    pthread_mutex_unlock(&s_loop_send_mutex);
    pthread_mutex_destroy(&s_loop_send_mutex);
	s_loop = NULL;
}

#endif