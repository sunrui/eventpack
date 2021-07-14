/*
 * buffer helper, user for serial buffer streams
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-26
 */
#include "eventpack.h"
#include "ep_buffer.h"
#include "ep_io.h"

#include <assert.h>
#include <string.h>

struct ep_buffer
{
	char * chunk; /* make sure chuck is the first */
	int capacity;
	int used;
};

/*
 * create a new buffer
 */
ep_buffer_t * ep_buffer_new(const char * in, int size)
{
	ep_buffer_t * buffer;

	assert(in != NULL && size > 0);
	buffer = (ep_buffer_t *)ep_calloc(1, sizeof(ep_buffer_t));
	if (buffer == NULL)
	{
        assert(0);
		return NULL;
	}

	/* we align size for 16 because aes crypt block size is 16 */
	buffer->capacity = ep_align_size(size, 16);
	buffer->chunk = (char *)ep_malloc(buffer->capacity);
	if (buffer->chunk == NULL)
	{
		ep_freep(buffer);
	}
	else
	{
		memcpy(buffer->chunk, in, size);
		buffer->used = size;
	}

	return buffer;
}

ep_buffer_t * ep_buffer_new2(ep_pack_t * pack)
{
	assert(pack != NULL);
	ep_pack_finish(pack);
	return ep_buffer_new(ep_pack_data(pack), ep_pack_size(pack));
}

/*
 * clone a buffer
 */
ep_buffer_t * ep_buffer_clone(ep_buffer_t * buffer)
{
	return ep_buffer_new(ep_buffer_ptr(buffer), ep_buffer_size(buffer));
}

/*
 * buffer get buffers
 */
const char * ep_buffer_ptr(ep_buffer_t * buffer)
{
	return (const char *)buffer->chunk;
}

/*
 * buffer get buffer size
 */
int ep_buffer_size(ep_buffer_t * buffer)
{
	assert(buffer->used > 0);
	return buffer->used;
}

/*
 * free buffers
 */
void ep_buffer_free(ep_buffer_t ** buffer)
{
	if (buffer != NULL && *buffer != NULL)
	{
		ep_free((*buffer)->chunk);
		ep_freep(*buffer);
	}
}

/*
 * free buffer shell but real buffers, you must manual
 *  free ep_buffer_ptr by ep_free
 *
 * @chunk_buffer    got real buffer buffer
 */
void ep_buffer_free_shell(ep_buffer_t ** buffer, char ** chunk_buffer)
{
	if (buffer != NULL && *buffer != NULL)
	{
        assert(chunk_buffer != NULL);
		*chunk_buffer = (*buffer)->chunk;
		ep_freep(*buffer);
	}
}

/*
 * encrypt an buffer
 *
 * @note input buffer will be overwrite
 */
ep_buffer_t * ep_buffer_encrypt(ep_buffer_t * buffer, ep_aes_key_t * aes)
{
	unsigned char * crypt;
	int mem_size;

	crypt = ep_crypt_aes((const unsigned char *)buffer->chunk,
		buffer->used,
		&mem_size, 
		aes->key,
		aes->vec,
		1);
	ep_freep(buffer->chunk);

	if (crypt != NULL)
	{
		buffer->chunk = (char *)crypt;
		buffer->used = mem_size;
		buffer->capacity = mem_size;
	}
	else
	{
        assert(0);
		ep_buffer_free(&buffer);
	}

	return buffer;
}

/*
 * decrypt an buffer
 *
 * @note input buffer will be overwrite
 */
ep_buffer_t * ep_buffer_decrypt(ep_buffer_t * buffer, ep_aes_key_t * aes, int orignal_size)
{
	unsigned char * crypt;
	int mem_size;

	crypt = ep_crypt_aes((const unsigned char *)buffer->chunk,
		buffer->used,
		&mem_size, 
		aes->key,
		aes->vec,
		0);
	ep_freep(buffer->chunk);

	if (crypt != NULL)
	{
		buffer->chunk = (char *)crypt;
		buffer->used = orignal_size;
		buffer->capacity = mem_size;
	}
	else
	{
        assert(0);
		ep_buffer_free(&buffer);
	}

	return buffer;
}

/*
 * compress buffer
 *
 * @note input buffer will be overwrite
 *
 * @return
 *     NULL if compress failed
 */
ep_buffer_t * ep_buffer_compress(ep_buffer_t * buffer)
{
	char * dest;
	unsigned int size;

	dest = ep_compress((char *)buffer->chunk, buffer->used, (unsigned int *)&buffer->capacity, &size);
	ep_freep(buffer->chunk);

	if (dest != NULL)
	{
		buffer->chunk = dest;
		buffer->used = size;
	}
	else
	{
        assert(0);
		ep_buffer_free(&buffer);
	}

	return buffer;
}

/*
 * decompress buffer
 *
 * @note input buffer will be overwrite
 *
 * @return
 *     NULL if decompress failed
 */
ep_buffer_t * ep_buffer_decompress(ep_buffer_t * buffer, int orignal_size)
{
	char * dest;

	dest = ep_decompress(buffer->chunk, buffer->used, orignal_size);
	ep_freep(buffer->chunk);

	if (dest != NULL)
	{
		buffer->chunk = dest;
		buffer->used = orignal_size;
		buffer->capacity = buffer->used;
	}
	else
	{
        assert(0);
		ep_buffer_free(&buffer);
	}

	return buffer;
}
