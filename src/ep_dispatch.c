/*
 * request process dispatcher
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-31
 */
#include "eventpack.h"
#include "ep_dispatch.h"

#include "list.h"

#include <pthread.h>
#include <assert.h>
#include <string.h>

typedef struct ep_dispatch
{
	ep_categroy_t category;

	pfn_ep_cb cb;
	void * opaque;

	struct list_head list;
} ep_disp_t;

struct ep_disp_mgr
{
	pthread_mutex_t lock;
	struct list_head disp_list; /* all request dispatch list */
};

/*
 * dispatch module init
 */
ep_disp_mgr_t * ep_disp_init()
{
	ep_disp_mgr_t * disp_mgr;

	disp_mgr = (ep_disp_mgr_t *)ep_calloc(1, sizeof(ep_disp_mgr_t));
	if (disp_mgr == NULL)
	{
        assert(0);
		return NULL;
	}

	INIT_LIST_HEAD(&disp_mgr->disp_list);
	pthread_mutex_init(&disp_mgr->lock, NULL);

	return disp_mgr;
}


/*
 * add a dispatch callback
 *
 * @return
 *     1 success
 *     0 failed
 */
int ep_disp_add_cb(ep_disp_mgr_t * disp_mgr, ep_categroy_t category, pfn_ep_cb ep_cb, void * opaque)
{
	ep_disp_t * disp;
	
	assert(disp_mgr != NULL);
	disp = (ep_disp_t *)ep_calloc(1, sizeof(ep_disp_t));
	if (disp == NULL)
	{
        assert(0);
		return 0;
	}

	disp->category = category;
	disp->cb = ep_cb;
	disp->opaque = opaque;

	pthread_mutex_lock(&disp_mgr->lock);
	list_add(&(*disp).list, &disp_mgr->disp_list);
	pthread_mutex_unlock(&disp_mgr->lock);

	return 1;
}

/*
 * delete a dispatch callback
 *
 * @return
 *     1 success
 *     0 failed
 */
int ep_disp_del_cb(ep_disp_mgr_t * disp_mgr, ep_categroy_t category, pfn_ep_cb ep_cb, void * opaque)
{
	struct list_head * pos, *q;
	ep_disp_t * tmp;
	int ret;

	ret = 0;
	pthread_mutex_lock(&disp_mgr->lock);
	list_for_each_safe(pos, q, &disp_mgr->disp_list)
	{
		tmp = list_entry(pos, ep_disp_t, list);
		if (tmp->category == category && tmp->cb == ep_cb && tmp->opaque == opaque)
		{
			list_del(pos);
			ep_free(tmp);
			ret = 1;
			break;
		}
	}
	pthread_mutex_unlock(&disp_mgr->lock);
	assert(ret == 1);

	return ret;
}

/*
 * count on same category
 */
int ep_disp_count(ep_disp_mgr_t * disp_mgr, ep_categroy_t category)
{
	struct list_head * pos;
	ep_disp_t * tmp;
	int count;

	count = 0;
	pthread_mutex_lock(&disp_mgr->lock);
	list_for_each(pos, &disp_mgr->disp_list)
	{
		tmp = list_entry(pos, ep_disp_t, list);
		if (tmp->category == category)
		{
			count++;
		}
	}
	pthread_mutex_unlock(&disp_mgr->lock);

	assert(count >= 1);
	return count;
}


/*
 * processor request by category id
 */
ep_pack_t * ep_disp_processor(ep_disp_mgr_t * disp_mgr, ep_categroy_t category, int fd, ep_pack_t * pack)
{
	int b_pack_reclaim = 1;
	ep_pack_t * response;
	struct list_head * pos;
	ep_disp_t * tmp;

	response = NULL;
	pthread_mutex_lock(&disp_mgr->lock);
	list_for_each(pos, &disp_mgr->disp_list)
	{
		tmp = list_entry(pos, ep_disp_t, list);
		if (tmp->category == category)
		{
			response = tmp->cb(tmp->opaque, fd, pack, &b_pack_reclaim);
			break;
		}
	}
	pthread_mutex_unlock(&disp_mgr->lock);

	if (b_pack_reclaim)
	{
		ep_pack_destroy(&pack);
	}

	return response;
}

/*
 * dispatch module destroy
 */
void ep_disp_destroy(ep_disp_mgr_t ** disp_mgr)
{
	if (disp_mgr != NULL && *disp_mgr != NULL)
	{
		struct list_head * pos, * q;
		ep_disp_t * tmp;

		pthread_mutex_lock(&(*disp_mgr)->lock);
		list_for_each_safe(pos, q, &(*disp_mgr)->disp_list)
		{
			tmp = list_entry(pos, ep_disp_t, list);
			list_del(pos);
			ep_free(tmp);
		}

		pthread_mutex_unlock(&(*disp_mgr)->lock);
		pthread_mutex_destroy(&(*disp_mgr)->lock);
		ep_freep(*disp_mgr);
	}
}