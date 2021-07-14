/*
 * thread pool
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-4-12
 */
#include "ep_threadpool.h"
#include "ep_alloctor.h"

#include <semaphore.h>
#include <pthread.h>

#include <sys/queue.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

struct ep_tp_worker
{
	ep_tp_t * pool;

	ep_tp_process_cb process_cb;
	ep_tp_complete_cb complete_cb;

	void * opaque;
	void * result;

	ep_tp_state state;
	sem_t sem;

	TAILQ_ENTRY(ep_tp_worker) entries;
};

struct ep_tp
{
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	
	TAILQ_HEAD(, ep_tp_worker) worker_queue;
	pthread_t * thread;
	int nthreads;
	int abort;
};

/*
 * working thread queue
 */
void * ep_tp_routine(void * param)
{
	struct ep_tp * pool = (struct ep_tp *)param;

	for (; !pool->abort;)
	{
		ep_tp_worker_t * worker;

		pthread_mutex_lock(&pool->mutex);
		while ((worker = TAILQ_FIRST(&pool->worker_queue)) == NULL)
		{
			if (pool->abort)
			{
				pthread_mutex_unlock(&pool->mutex);
				pthread_exit(NULL);
				return NULL;
			}

			pthread_cond_wait(&pool->cond, &pool->mutex);
		}

		TAILQ_REMOVE(&pool->worker_queue, worker, entries);
		pthread_mutex_unlock(&pool->mutex);
		assert(worker != NULL);

		worker->state = tp_state_busy;
		worker->result = (*worker->process_cb)(worker->opaque);
		worker->state = tp_state_complete;
		sem_post(&worker->sem);

		if (worker->complete_cb != NULL)
		{
			(*worker->complete_cb)(worker, worker->result, worker->opaque);
		}

		ep_tp_worker_free(worker);
	}

	return NULL;
}

/*
 * create a thread pool
 *
 * @nthreads number of working threads
 *
 * @return
 *		new thread pool
 */
ep_tp_t * ep_tp_create(int nthreads)
{
	ep_tp_t * pool;

	pool = (ep_tp_t *)ep_calloc(1, sizeof(ep_tp_t));
	if (pool == NULL || nthreads <= 0)
	{
        assert(0);
		return NULL;
	}

	pthread_mutex_init(&pool->mutex, NULL);
	pthread_cond_init(&pool->cond, NULL);
	pool->thread = (pthread_t *)ep_calloc(1, nthreads * sizeof(pthread_t));
	if (pool->thread == NULL)
	{
		ep_freep(pool);
		return NULL;
	}

	pool->nthreads = nthreads;
	TAILQ_INIT(&pool->worker_queue);
	pool->abort = 0;

	{
		int index;
		for (index = 0; index < nthreads; index++)
		{
			pthread_create(&pool->thread[index], NULL, ep_tp_routine, pool);
		}
	}

	return pool;
}

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
ep_tp_worker_t * ep_tp_worker_register(ep_tp_t * pool, ep_tp_process_cb process_cb, ep_tp_complete_cb complete_cb, void * opaque)
{
	ep_tp_worker_t * worker;

	if (pool == NULL || pool->abort || process_cb == NULL)
	{
		assert(0);
		return NULL;
	}

	worker = (ep_tp_worker_t *)ep_calloc(1, sizeof(ep_tp_worker_t));
	if (worker == NULL)
	{
        assert(0);
		return NULL;
	}

	worker->pool = pool;
	worker->process_cb = process_cb;
	worker->complete_cb = complete_cb;
	worker->opaque = opaque;
	worker->result = NULL;
	worker->state = tp_state_idle;
	sem_init(&worker->sem, 0, 0);

	pthread_mutex_lock(&pool->mutex);
	TAILQ_INSERT_TAIL(&pool->worker_queue, worker, entries);
	pthread_cond_broadcast(&pool->cond);
	pthread_mutex_unlock(&pool->mutex);

	return worker;
}

/*
 * touch a work
 */
ep_tp_state ep_tp_worker_touch(ep_tp_worker_t * worker)
{
	if (worker == NULL)
	{
		assert(0);
		return tp_state_invalid;
	}

	return worker->state;
}

/*
 * wait for worker finished
 */
void * ep_tp_worker_wait(ep_tp_worker_t * worker)
{
	if (worker == NULL)
	{
		assert(0);
		return NULL;
	}

	sem_wait(&worker->sem);
	return worker->result;
}

/*
 * free a worker if in idle status
 */
void ep_tp_worker_free(ep_tp_worker_t * worker)
{
	pthread_mutex_lock(&worker->pool->mutex);
	{
		ep_tp_worker_t * a_worker;

		TAILQ_FOREACH(a_worker, &worker->pool->worker_queue, entries)
		{
			if (a_worker == worker)
			{
				assert(worker->state == tp_state_idle);
				TAILQ_REMOVE(&worker->pool->worker_queue, a_worker, entries);
				break;
			}
		}
	}
	pthread_mutex_unlock(&worker->pool->mutex);

	sem_post(&worker->sem);
	sem_destroy(&worker->sem);
	ep_free(worker);
}

/*
 * destroy thread pool
 */
void ep_tp_destroy(ep_tp_t ** pool, ep_tp_kill type)
{
	if (pool == NULL || *pool == NULL || (*pool)->abort)
	{
        assert(0);
		return;
	}

	if (type == tp_kill_wait)
	{
		while (TAILQ_FIRST(&(*pool)->worker_queue) != NULL)
		{
			usleep(50 * 1000);
		}
	}

	pthread_mutex_lock(&(*pool)->mutex);
	(*pool)->abort = 1;
	pthread_cond_broadcast(&(*pool)->cond);
	pthread_mutex_unlock(&(*pool)->mutex);

	{
		int index;

		for (index = 0; index < (*pool)->nthreads; index++)
		{
			pthread_join((*pool)->thread[index], NULL);
		}
	}

	{
		ep_tp_worker_t * worker;

		while ((worker = TAILQ_FIRST(&(*pool)->worker_queue)) != NULL)
		{
			TAILQ_REMOVE(&(*pool)->worker_queue, worker, entries);
			sem_post(&worker->sem);
			sem_destroy(&worker->sem);
			ep_free(worker);
		}
	}

	pthread_mutex_destroy(&(*pool)->mutex);
	pthread_cond_destroy(&(*pool)->cond);
	ep_free((*pool)->thread);
	ep_freep(*pool);
}

#ifdef TEST_EP_THREADPOOL_H
#include <windows.h>
#include <stdio.h>
#include <vld.h>

#include "ep_threadpool.h"

void * process_cb(void * opaque)
{
	int taskid;
	taskid = (int)opaque;
	printf("taskid = %d.\n", taskid);
	Sleep(2000);

	return NULL;
}

void complete_cb(ep_tp_worker_t * worker, void * result, void * opaque)
{
}

int main()
{
	ep_tp_t * pool;

	pool = ep_tp_create(5);

	{
		ep_tp_process_cb pcb;
		ep_tp_complete_cb ccb;
		void * opaque;
		int tasks;

		pcb = process_cb;
		ccb = complete_cb;

		for (tasks = 0; tasks < 19; tasks++)
		{
			ep_tp_worker_t * worker;
			ep_tp_state state;
			void * result;

			opaque = (void *)tasks;
			worker = ep_tp_worker_register(pool, pcb, ccb, opaque);
			state = ep_tp_worker_touch(worker);

			result = NULL;
			//result = ep_tp_worker_wait(worker);
		}

		ep_tp_destroy(&pool, tp_kill_wait);
		printf("destroy ok.\n");
	}
}
#endif
