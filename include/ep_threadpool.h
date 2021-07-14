/*
 * thread pool
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-4-12
 */
#ifndef EP_THREADPOOL_H
#define EP_THREADPOOL_H

typedef struct ep_tp_worker ep_tp_worker_t;
typedef struct ep_tp ep_tp_t;

typedef void (* ep_tp_complete_cb)(ep_tp_worker_t * worker, void * result, void * opaque);
typedef void * (* ep_tp_process_cb)(void * opaque);

typedef enum
{
	tp_state_idle = 0,
	tp_state_busy,
	tp_state_complete,
	tp_state_invalid
} ep_tp_state;

typedef enum
{
	tp_kill_immediate = 0,
	tp_kill_wait
} ep_tp_kill;

/*
 * create a thread pool
 *
 * @nthreads number of working threads
 *
 * @return
 *		new thread pool
 */
ep_tp_t * ep_tp_create(int nthreads);

/*
 * register a worker
 *
 * @pool pool instance
 * @process_cb process callback
 * @complete_cb complete callback
 * @opaque user data
 *
 * @return
 *     a worker instance
 */
ep_tp_worker_t * ep_tp_worker_register(ep_tp_t * pool, ep_tp_process_cb process_cb, ep_tp_complete_cb complete_cb, void * opaque);

/*
 * touch a work
 */
ep_tp_state ep_tp_worker_touch(ep_tp_worker_t * worker);

/*
 * wait for worker finished
 */
void * ep_tp_worker_wait(ep_tp_worker_t * worker);

/*
 * free a worker if in idle status
 */
void ep_tp_worker_free(ep_tp_worker_t * worker);

/*
 * destroy thread pool
 */
void ep_tp_destroy(ep_tp_t ** pool, ep_tp_kill type);

#endif