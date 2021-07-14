/*
 * compress
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-8-13
 */
#ifndef EP_COMPRESS_H
#define EP_COMPRESS_H

/*
 * buffer compress
 *
 * @return
 *     NULL if compress failed
 */
char * ep_compress(const char * src, unsigned int src_len, unsigned int * alloc_len, unsigned int * dest_len);

/*
 * buffer compress
 *
 * @return
 *     NULL if decompress failed
 */
char * ep_decompress(const char * src, unsigned int src_len, unsigned int dest_len);

#endif