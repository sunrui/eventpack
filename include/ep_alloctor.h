/*
 * memory allocator
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-1-28
 */
#ifndef EP_ALLOCTOR_H
#define EP_ALLOCTOR_H

#include <stddef.h>

#define ep_align_size(x, ALIGNED_SIZE) ((x + (ALIGNED_SIZE - 1)) & ~(ALIGNED_SIZE - 1))

typedef struct ep_alloctor
{
	void * (* malloc)(size_t size);
	void * (* calloc)(size_t count, size_t size);
	void * (* realloc)(void * ptr, size_t size);
	void (* free)(void * ptr);
} ep_alloctor_t;

/*
 * register custom buffer allocator
 *
 * return 1 if success otherwise 0
 */
int ep_alloctor_custom(ep_alloctor_t * allocator);

/*
 * memory malloc, calloc, free
 */
void * ep_malloc(int size);
void * ep_calloc(int count, int size);
void ep_free(void * ptr);

/*
 * extend freep
 */
#define ep_freep(ptr) { \
	if (ptr != NULL) { \
		ep_free(ptr); \
		ptr = NULL; \
	} \
}

#endif