
/*
 * buffer helper, user for serial buffer streams
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-26
 */
#ifndef EP_BUFFER_H
#define EP_BUFFER_H

#include "eventpack.h"

typedef struct ep_aes_key
{
	unsigned char key[16];
	unsigned char vec[16];
} ep_aes_key_t;

typedef struct ep_buffer ep_buffer_t;

/*
 * create a new buffer
 */
ep_buffer_t * ep_buffer_new(const char * buffer, int size);
ep_buffer_t * ep_buffer_new2(ep_pack_t * pack);

/*
 * clone a buffer
 */
ep_buffer_t * ep_buffer_clone(ep_buffer_t * buffer);

/*
 * buffer get buffers
 */
const char * ep_buffer_ptr(ep_buffer_t * buffer);

/*
 * buffer get buffer size
 */
int ep_buffer_size(ep_buffer_t * buffer);

/*
 * free buffers
 */
void ep_buffer_free(ep_buffer_t ** buffer);

/*
 * free buffer shell but real buffers, you must manual 
 *  free ep_buffer_ptr by ep_free
 *
 * @chunk_buffer    got real buffer buffer
 */
void ep_buffer_free_shell(ep_buffer_t ** buffer, char ** chunk_buffer);

/*
 * encrypt an buffer
 *
 * @note input buffer will be overwrite
 */
ep_buffer_t * ep_buffer_encrypt(ep_buffer_t * buffer, ep_aes_key_t * aes);

/*
 * decrypt an buffer
 *
 * @note input buffer will be overwrite
 */
ep_buffer_t * ep_buffer_decrypt(ep_buffer_t * buffer, ep_aes_key_t * aes, int orignal_size);

/*
 * compress buffer
 *
 * @note input buffer will be overwrite
 *
 * @return
 *     NULL if compress failed
 */
ep_buffer_t * ep_buffer_compress(ep_buffer_t * buffer);

/*
 * decompress buffer
 *
 * @note input buffer will be overwrite
 *
 * @return
 *     NULL if decompress failed
 */
ep_buffer_t * ep_buffer_decompress(ep_buffer_t * buffer, int orignal_size);

#endif