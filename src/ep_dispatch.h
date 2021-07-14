/*
 * request process dispatcher
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-31
 */
#ifndef EP_DISPATH_H
#define EP_DISPATH_H

typedef struct ep_disp_mgr ep_disp_mgr_t;

/*
 * dispatch module init
 */
ep_disp_mgr_t * ep_disp_init();

/*
 * add a dispatch callback
 *
 * @return
 *     1 success
 *     0 failed
 */
int ep_disp_add_cb(ep_disp_mgr_t * disp_mgr, ep_categroy_t category, pfn_ep_cb ep_cb, void * opaque);

/*
 * delete a dispatch callback
 *
 * @return
 *     1 success
 *     0 failed
 */
int ep_disp_del_cb(ep_disp_mgr_t * disp_mgr, ep_categroy_t category, pfn_ep_cb ep_cb, void * opaque);

/*
 * count on same category
 */
int ep_disp_count(ep_disp_mgr_t * disp_mgr, ep_categroy_t category);

/*
 * processor request by category id
 */
ep_pack_t * ep_disp_processor(ep_disp_mgr_t * disp_mgr, ep_categroy_t category, int fd, ep_pack_t * pack);

/*
 * dispatch module destroy
 */
void ep_disp_destroy(ep_disp_mgr_t ** disp_mgr);

#endif