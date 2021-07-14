/*
 * send queue, use for maintenance send/recv pools
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-31
 */
#ifndef EP_QUEUE_H
#define EP_QUEUE_H

typedef struct ep_queue ep_queue_t;

/*
 * create a new queue
 */
ep_queue_t * ep_queue_new();

/*
 * push a new body to queue, must be alloc here
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_queue_push(ep_queue_t * queue, void * item);

/*
 * get a body from queue
 *
 * @body out body if get ok, you must manual free it by ep_free.
 * @timeout	send timeout in seconds or < 0 if infinite
 *
 * @return
 *     1 get it ok
 *     0 no more buffers now (timeout reached)
 *    -1 by your abort
 */
int ep_queue_get(ep_queue_t * queue, void ** body, int timeout);

/*
 * queue ensure stop and return
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_queue_stop(ep_queue_t * queue);

/*
 * destroy queue and tear down
 */
void ep_queue_destroy(ep_queue_t ** queue);

#endif