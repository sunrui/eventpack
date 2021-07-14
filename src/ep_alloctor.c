/*
 * memory provider
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-1-28
 */
#include "eventpack.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "jemalloc.h"

#if defined(__GNUC__) && (__GNUC__ > 2)
#define EP_LIKELY(x)    (__builtin_expect(!!(x), 1))
#define EP_UNLIKELY(x)  (__builtin_expect(!!(x), 0))
#else
#define EP_LIKELY(x)    (x)
#define EP_UNLIKELY(x)  (x)
#endif

static ep_alloctor_t s_alloctor = {
	je_malloc, je_calloc, je_realloc, je_free
};

/*
 * register custom buffer allocator
 *
 * return 1 if success otherwise 0
 */
int ep_alloctor_custom(ep_alloctor_t * allocator)
{
	if (allocator == NULL || allocator->malloc == NULL ||
		allocator->calloc == NULL || allocator->realloc == NULL ||
		allocator->free == NULL)
	{
		assert(0);
		return 0;
	}
	
	s_alloctor = *allocator;
		
	return 1;
}

void * ep_malloc(int size)
{
    if (EP_UNLIKELY(size <= 0))
	{
		assert(0);
		return NULL;
    }

	return s_alloctor.malloc(size);
}

void * ep_calloc(int count, int size)
{
	if (EP_UNLIKELY(count <= 0 || size <= 0))
	{
		assert(0);
		return NULL;
    }
	
	return s_alloctor.calloc(count, size);
}

void ep_free(void * ptr)
{
    if (EP_UNLIKELY(ptr == NULL))
	{
		assert(0);
		return;
    }

	s_alloctor.free(ptr);
}