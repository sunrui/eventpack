/*
 * ring buffer
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-4-13
 */
#ifndef EP_RINGBUFFER_H
#define EP_RINGBUFFER_H

typedef struct ep_rb ep_rb_t;

/*
 * create a new ring buffer
 *
 * @capacity default capacity
 * @limit limit capacity
 *
 * @return
 *     new ring buffer
 */
ep_rb_t * ep_rb_new(int capacity, int limit);

/*
 * get ring buffer capacity
 */
int ep_rb_capacity(ep_rb_t * rb);

/*
 * get capacities which can be read
 */
int ep_rb_can_read(ep_rb_t * rb);

/*
 * get capacities which can be write
 */
int ep_rb_can_write(ep_rb_t * rb);

/*
 * read buffers from ring buffer
 *
 * @return
 *     real size buffer read-ed
 */
int ep_rb_read(ep_rb_t * rb, char ** data, int count);

/*
 * write buffers to ring buffer
 *
 * @return
 *     real size buffer write-ed
 */
int ep_rb_write(ep_rb_t * rb, const char * data, int count);

/*
 * free a ring buffer
 */
void ep_rb_free(ep_rb_t ** rb);

#endif