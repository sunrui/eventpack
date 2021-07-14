/*
 * buffer crypt
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-4-15
 */
#ifndef EP_CRYPT_H
#define EP_CRYPT_H

/*
 * use crypt for thread-safe
 */
void ep_crypt_safe_init();
void ep_crypt_safe_uninit();

/*
 * cert calculate md5
 */
void ep_crypt_md5(unsigned char md5[16], const char * buffer, int size);

/*
 * aes crypt
 *
 * @return
 *     buffer alloc by ep_malloc
 */
unsigned char * ep_crypt_aes(const unsigned char * in,
	int in_size,
	int * out_len,
	const unsigned char key[16], 
	unsigned char vec[16],
	int enc);

/*
 * rsa crypt
 *
 * @key_buffer
 *     for encrypt: public key
 *     for decrypt: private key
 *
 * @return
 *     1 ok or 0 failed
 */
int ep_crypt_rsa(const char * key_buffer,
	int key_size,
	const char * in_buffer,
	int in_size,
	char ** out_buffer,
	int * out_size,
	int enc);

#endif