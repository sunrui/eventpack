/*
 * io header
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-31
 */
#ifndef EP_IO_H
#define EP_IO_H

#include "ep_buffer.h"
#include "ep_shell.h"
#include "ep_dispatch.h"

#include <time.h>

typedef enum ep_io_refor
{
	ep_io_refor_server = 0,
	ep_io_refor_client
} ep_io_refor;

typedef struct ep_io_mgr ep_io_mgr_t;

/*
 * register io send callback
 */
typedef int (* ep_io_send_cb)(int fd, char * buffer, int size, void * extra);

/*
 * io module init
 *
 * @client set to 0 if this io is signed as client or 1 as server
 */
ep_io_mgr_t * ep_io_init(ep_io_refor refor, ep_disp_mgr_t * disp_mgr, ep_io_send_cb send_cb, int nprocessors, int def_capacity, int max_capacity, int mini_compress_if);

/*
 * combine a shell and body to a buffer
 *
 * @client
 *    if this combine is for client set it to 0, 'in' will be processed refer to 'crypt' and 'compress',
 *     other wise set it to 1, 'in' will refer to 's_crypt and 's_compress'
 */
ep_buffer_t * ep_io_combine_shell(ep_io_mgr_t * io_mgr, int fd, ep_shell_t * shell, ep_buffer_t * in);

/*
 * recombine and get original body buffer
 */
ep_buffer_t * ep_io_recombine_original(ep_io_mgr_t * io_mgr, int fd, ep_shell_t * shell, ep_buffer_t * in);

/*
 * io insert a new fd
 *
 * @return
 *     1 add ok
 *     0 exist no need add
 */
int ep_io_add(ep_io_mgr_t * io_mgr, int fd, void * extra);

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
int ep_io_enqueue(ep_io_mgr_t * io_mgr, int fd, const char * inbuf, int insize);

/*
 * send client an message
 *
 * @curfd	current fd
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
int ep_io_nodify_fd(ep_io_mgr_t * io_mgr, int curfd, int notify_type, ep_buffer_t * in);

/*
 * update io crypt key/vec
 *
 * @return
 *     1 if notify ok
 *     0 failed
 */
int ep_io_update_aes(ep_io_mgr_t * io_mgr, int fd, ep_aes_key_t * aes);

/*
 * get aes key/vec
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_io_get_aes(ep_io_mgr_t * io_mgr, int fd, ep_aes_key_t * aes);

/*
 * stop a io
 */
void ep_io_stop(ep_io_mgr_t * io_mgr, int fd);

/*
 * discard a fd ensure that no longer used
 *
 * return
 *    1 success
 *    0 failed
 */
int ep_io_del(ep_io_mgr_t * io_mgr, int fd);

/*
 * io module destroy
 */
void ep_io_destroy(ep_io_mgr_t ** io_mgr);

#endif
