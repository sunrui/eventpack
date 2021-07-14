/*
 * buffer crypt
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-4-15 
 */
#include "eventpack.h"

#include "openssl/crypto.h"
#include "openssl/aes.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/md5.h"

#include <pthread.h>
#include <string.h>
#include <assert.h>

/*
 * cert calculate md5
 */
void ep_crypt_md5(unsigned char md[16], const char * buffer, int size)
{
	MD5_CTX  ctx;
    
	assert(buffer != NULL && size > 0);
	MD5_Init(&ctx);
	MD5_Update(&ctx, buffer, size);
	MD5_Final(md, &ctx);
}

/* we have this global to let the callback get easy access to it */ 
static pthread_mutex_t *lockarray;
static int inited;

void lock_callback(int mode, int type, char *file, int line)
{
	(void)file;
	(void)line;
	if (mode & CRYPTO_LOCK)
	{
		pthread_mutex_lock(&(lockarray[type]));
	}
	else
	{
		pthread_mutex_unlock(&(lockarray[type]));
	}
}

unsigned long thread_id(void)
{
#ifdef WIN32
	return GetCurrentThreadId();
#else
	return (unsigned long)pthread_self();
#endif
}

void ep_crypt_safe_init()
{
	if (!inited)
	{
		int i;

		lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
		for (i = 0; i < CRYPTO_num_locks(); i++)
		{
			pthread_mutex_init(&(lockarray[i]), NULL);
		}

		CRYPTO_set_id_callback((unsigned long (*)(void))thread_id);
		CRYPTO_set_locking_callback((void (*)(int, int, const char *, int))lock_callback);

		inited = 1;
	}
}

void ep_crypt_safe_uninit()
{
	if (inited)
	{
		int i;

		CRYPTO_set_locking_callback(NULL);
		for (i = 0; i < CRYPTO_num_locks(); i++)
		{
			pthread_mutex_destroy(&(lockarray[i]));
		}
		OPENSSL_free(lockarray);

		inited = 0;
	}
}

/*
 * crypt
 *
 * @return
 *     buffer alloc by ep_malloc
 */
unsigned char * ep_crypt_aes(const unsigned char * in,
	int in_size,
	int * out_len,
	const unsigned char key[16], 
	unsigned char vec[16],
	int enc)
{
	AES_KEY aes;
	unsigned char * out;
	int len;

	len = 0;
	if ((in_size + 1) % AES_BLOCK_SIZE == 0)
	{
		len = in_size + 1;
	}
	else
	{
		len = ((in_size + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	}

	if (enc == AES_ENCRYPT)
	{
		AES_set_encrypt_key(key, 128, &aes);
	}
	else
	{
		AES_set_decrypt_key(key, 128, &aes);
	}

	out = (unsigned char *)ep_malloc(len);
	if (out == NULL)
	{
        assert(0);
		*out_len = 0;
		return NULL;
	}

	AES_cbc_encrypt(in, out, len, &aes, vec, enc ? AES_ENCRYPT : AES_DECRYPT);
	*out_len = len;

	return out;
}

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
	int enc)
{
	RSA * key;
	int r;

	if (key_buffer == NULL || key_size <= 0 ||
		in_buffer == NULL || in_size <= 0 ||
		out_buffer == NULL || out_size == NULL)
	{
		assert(0);
		return 0;
	}

	{
		BIO * bio;

		bio = BIO_new_mem_buf((void *)key_buffer, key_size);
		if (bio == NULL)
		{
			assert(0);
			return 0;
		}

		if (enc == 1)
		{
			key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
		}
		else
		{
			EVP_PKEY * k;

			k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
			if (k != NULL)
            {
                key = RSAPrivateKey_dup(k->pkey.rsa);
                EVP_PKEY_free(k);
            }
            else
            {
                key = NULL;
            }
		}

		BIO_free(bio);
        if (key == NULL)
        {
            assert(0);
            return 0;
        }
	}

	*out_size = RSA_size(key);
	*out_buffer = (char *)ep_malloc(*out_size);
	if (*out_buffer == NULL)
	{
		assert(0);
		*out_size = 0;
		return 0;
	}

	if (enc == 1)
	{
		r = RSA_public_encrypt(in_size, (const unsigned char *)in_buffer, (unsigned char *)*out_buffer,
			key, RSA_PKCS1_PADDING);
	}
	else
	{
		r = RSA_private_decrypt(in_size, (const unsigned char *)in_buffer, (unsigned char *)*out_buffer,
			key, RSA_PKCS1_PADDING);
	}
    
    if (r == -1)
	{
		assert(0);
		*out_size = 0;
		ep_freep(*out_buffer);
		return 0;
	}
    
	*out_size = r;
	RSA_free(key);

	return 1;
}
