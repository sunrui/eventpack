/*
 * compress
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-8-13
 */
#include "eventpack.h"

#include "bzlib.h"

#include <assert.h>

/*
 * buffer compress
 *
 * @return
 *     NULL if compress failed
 */
char * ep_compress(const char * src, unsigned int src_len, unsigned int * alloc_len, unsigned int * dest_len)
{
	char * dest;
	unsigned int alloced;
	int ret;

	assert(src != NULL && src_len > 0 && dest_len != NULL);
	alloced = ep_align_size((unsigned int)(src_len * 1.01) + 600, 16);
	dest = (char *)ep_malloc(alloced);
	if (dest == NULL)
	{
        assert(0);
		return NULL;
	}

	*alloc_len = alloced;
	*dest_len = alloced;

	ret = BZ2_bzBuffToBuffCompress(dest, dest_len, (char *)src, src_len, 5, 0, 0);
	assert(ret == BZ_OK);

	return dest;
}

/*
 * buffer compress
 *
 * @return
 *     NULL if decompress failed
 */
char * ep_decompress(const char * src, unsigned int src_len, unsigned int dest_len)
{
	unsigned int dec_len;
	char * dest;
	int ret;

	assert(src != NULL && src_len > 0 && dest_len > 0);
	dest = (char *)ep_malloc(ep_align_size(dest_len, 16));
	if (dest == NULL)
	{
        assert(0);
		return NULL;
	}

	dec_len = dest_len;
	ret = BZ2_bzBuffToBuffDecompress(dest, (unsigned int *)&dec_len, (char *)src, src_len, 0, 0);
	if (ret != BZ_OK || dest_len != dec_len)
	{
		assert(0);
		ep_freep(dest);
	}

	return dest;
}
