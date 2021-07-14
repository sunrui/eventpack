/*
 * send queue, use for maintenance send/recv pools
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-31 12:29
 */
#include "eventpack.h"

#include <sys/queue.h>
#include <sys/time.h>
#include <pthread.h>
#include <assert.h>

typedef struct ep_queue_body_t
{
	void * body; /* need send/recv buffers */
	TAILQ_ENTRY(ep_queue_body_t) entries;
} ep_queue_body_t;

struct ep_queue
{
	TAILQ_HEAD(, ep_queue_body_t) queue; /* unique event queue instance */
	pthread_cond_t cond; /* use for queue thread-safe */
	pthread_mutex_t mutex; /* use for queue thread-safe */
	int stop_sign; /* whether received a signal to stop */
};

/*
 * create a new queue
 */
ep_queue_t * ep_queue_new()
{
	ep_queue_t * queue;

	queue = (ep_queue_t *)ep_calloc(1, sizeof(ep_queue_t));
	if (queue == NULL)
	{
        assert(0);
		return NULL;
	}

	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->cond, NULL);
	queue->stop_sign = 0;
	TAILQ_INIT(&queue->queue);

	return queue;
}

/*
 * push a new body to queue, must be alloc here
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_queue_push(ep_queue_t * queue, void * body)
{
	ep_queue_body_t * item;

	if (queue == NULL)
	{
		assert(0);
		return 0;
	}
	
	item = (ep_queue_body_t *)ep_calloc(1, sizeof(ep_queue_body_t));
	if (item == NULL)
	{
        assert(0);
		return 0;
	}

	item->body = body;

	pthread_mutex_lock(&queue->mutex);
	TAILQ_INSERT_TAIL(&queue->queue, item, entries);
	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->mutex);

	return 1;
}

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
int ep_queue_get(ep_queue_t * queue, void ** body, int timeout)
{
	ep_queue_body_t * item;
	int ret = 0;

	if (queue == NULL || body == NULL)
	{
		assert(0);
		return 0;
	}

	pthread_mutex_lock(&queue->mutex);

	*body = NULL;
	item = TAILQ_FIRST(&queue->queue);
	while (item == NULL && !queue->stop_sign)
	{
		int wait_r = 0;

		if (timeout > 0)
		{
			struct timespec ts;
			ts.tv_sec = time(NULL) + timeout;
			wait_r = pthread_cond_timedwait(&queue->cond, &queue->mutex, &ts);
		}
		else if (timeout == 0)
		{
			*body = NULL;
			ret = 0;
			goto ret_clean;
		}
		else
		{
			wait_r = pthread_cond_wait(&queue->cond, &queue->mutex);
		}

		/* if waked by user stop sign */
		if (queue->stop_sign)
		{
			*body = NULL;
			ret = -1;
			goto ret_clean;
		}

		item = TAILQ_FIRST(&queue->queue);
		if (item == NULL)
		{
			/* timeout reached */
			if (wait_r != 0)
			{
				*body = NULL;
				ret = 0;
				goto ret_clean;
			}
			else
			/* by user abort */
			{
				*body = NULL;
				ret = -1;
				goto ret_clean;
			}
		}
		else
		{
			/* wait ok and receive a body */
			break;
		}
	}

	if (item != NULL)
	{
		*body = item->body;
		TAILQ_REMOVE(&queue->queue, item, entries);
		ep_free(item);
		ret = 1;
	}

ret_clean:
	pthread_mutex_unlock(&queue->mutex);

	return ret;
}

/*
 * queue ensure stop and return
 *
 * @return
 *     1 ok
 *     0 failed
 */
int ep_queue_stop(ep_queue_t * queue)
{
	if (queue == NULL)
	{
		assert(0);
		return 0;
	}

	pthread_mutex_lock(&queue->mutex);
	queue->stop_sign = 1;
	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->mutex);

	return 1;
}

/*
 * destroy queue and tear down
 */
void ep_queue_destroy(ep_queue_t ** queue)
{
	if (queue != NULL && *queue != NULL)
	{
		ep_queue_stop(*queue);
		assert(TAILQ_FIRST(&(*queue)->queue) == NULL);

		pthread_mutex_destroy(&(*queue)->mutex);
		pthread_cond_destroy(&(*queue)->cond);
		ep_freep(*queue);
	}
}
