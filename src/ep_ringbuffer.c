/*
 * ring buffer
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-4-13
 */
#include "ep_ringbuffer.h"
#include "ep_alloctor.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

struct ep_rb
{
	char * buffer;
	int head;
	int tail;
	int wrap;

	int capacity;
	int limit;

	struct ep_rb_retval
	{
		char * buffer;
		int size;
	} retval;
};

/*
 * create a new ring buffer
 *
 * @capacity default capacity
 * @limit limit capacity
 *
 * @return
 *     new ring buffer
 */
ep_rb_t * ep_rb_new(int capacity, int limit)
{
	ep_rb_t * rb;

	assert(capacity > 0 && limit > 0);
	rb = (ep_rb_t * )ep_calloc(1, sizeof(ep_rb_t));
	if (rb == NULL)
	{
        assert(0);
		return NULL;
	}

	rb->capacity = capacity;
	rb->buffer = (char *)ep_malloc(rb->capacity);
	if (rb->buffer == NULL)
	{
        assert(0);
		ep_free(rb);
		return NULL;
	}

	memset(rb->buffer, 0, rb->capacity);
	rb->head = 0;
	rb->tail = 0;
	rb->limit = limit;
	rb->wrap = 0;
	rb->retval.buffer = NULL;
	rb->retval.size = 0;

	return rb;
}

/*
 * get ring buffer capacity
 */
int ep_rb_capacity(ep_rb_t * rb)
{
	assert(rb != NULL);

	return rb->capacity;
}

/*
 * get capacities which can be read
 */
int ep_rb_can_read(ep_rb_t * rb)
{
	if (rb->tail == rb->head)
	{
		return rb->wrap ? rb->capacity : 0;
	}
	else if (rb->tail > rb->head)
	{
		return rb->tail - rb->head;
	}
	else
	{
		return rb->capacity + rb->tail - rb->head;
	}
}

/*
 * get capacities which can be write
 */
int ep_rb_can_write(ep_rb_t * rb)
{
	int can_write = rb->capacity - ep_rb_can_read(rb);
	assert(can_write >= 0);

	if (can_write == 0 && rb->limit > rb->capacity)
	{
		can_write = rb->limit - ep_rb_can_read(rb);
	}

	return can_write;
}

/*
 * read buffers from ring buffer
 *
 * @return
 *     real size buffer read-ed
 */
int ep_rb_read(ep_rb_t * rb, char ** data, int count)
{
	assert(rb != NULL && data != NULL);
	count = min(count, ep_rb_can_read(rb));

	if (count == 0)
	{
		*data = NULL;
		return 0;
	}

	/* case in no need wrapper lines */
	{
		int tail_chunk = rb->capacity - rb->head;

		if (tail_chunk > count)
		{
			*data = rb->buffer + rb->head;
			rb->head = (rb->head + count) % rb->capacity;
			return count;
		}
	}

	/* case in need wrapper lines */
	{
		int tail_chunk = min(count, rb->capacity - rb->head);
		int head_chunk = count - tail_chunk;

		if (rb->retval.size < tail_chunk + head_chunk)
		{
			if (rb->retval.buffer != NULL)
			{
				ep_free(rb->retval.buffer);
			}

			rb->retval.size = tail_chunk + head_chunk;
			rb->retval.buffer = (char *)ep_malloc(rb->retval.size);
		}

		*data = rb->retval.buffer;
		memcpy(rb->retval.buffer, rb->buffer + rb->head, tail_chunk);
		rb->head = (rb->head + tail_chunk) % rb->capacity;

		if (tail_chunk < count)
		{
			memcpy(rb->retval.buffer + tail_chunk, rb->buffer + rb->head, head_chunk);
			rb->head = (rb->head + head_chunk) % rb->capacity;
		}
	}

	if (rb->wrap)
	{
		rb->wrap = 0;
	}

	return count;
}

/*
 * automate expend capacity if necessary
 */
void ep_rb_expand_limit(ep_rb_t * rb, int count)
{
	int can_write = rb->capacity - ep_rb_can_read(rb);
	if (can_write >= count)
	{
		return;
	}

	{
		char * capacity;
		char * buffer;
		int expand;
		int readed;

		expand = min(count, rb->limit);
		capacity = (char *)ep_malloc(rb->capacity + expand);
		readed = ep_rb_read(rb, &buffer, ep_rb_can_read(rb));
		memcpy(capacity, buffer, readed);
		ep_free(rb->buffer);
		rb->buffer = capacity;
		rb->head = 0;
		rb->capacity = rb->capacity + expand;
		rb->tail = readed % rb->capacity;
	}
}

/*
 * write buffers to ring buffer
 *
 * @return
 *     real size buffer write-ed
 */
int ep_rb_write(ep_rb_t * rb, const char * data, int count)
{
	assert(rb != NULL);
	assert(data != NULL);

	ep_rb_expand_limit(rb, count);
	count = min(count, ep_rb_can_write(rb));

	if (count == 0)
	{
		return count;
	}

	{
		int tail_chunk = min(count, rb->capacity - rb->tail);
		memcpy(rb->buffer + rb->tail, data, tail_chunk);
		rb->tail = (rb->tail + tail_chunk) % rb->capacity;

		if (tail_chunk < count)
		{
			int head_chunk = count - tail_chunk;
			memcpy(rb->buffer + rb->tail, data + tail_chunk, head_chunk);
			rb->tail = (rb->tail + head_chunk) % rb->capacity;
		}
	}

	if (rb->head == rb->tail)
	{
		rb->wrap = 1;
	}

	return count;
}

/*
 * free a ring buffer
 */
void ep_rb_free(ep_rb_t ** rb)
{
	if (rb != NULL && * rb != NULL)
	{
		if ((*rb)->retval.buffer != NULL)
		{
			ep_free((*rb)->retval.buffer);
		}

		ep_free((*rb)->buffer);
		ep_freep(*rb);
	}
}
