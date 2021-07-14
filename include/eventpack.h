/*
 * eventpack is a event based network interaction engine
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-30
 */
#ifndef EVENTPACK_H
#define EVENTPACK_H

/* category for major/minor id */
#define EP_MAKEWORD(major, minor) (((major) << 8) | (minor))
#define EP_MAJOR(major) (((major) >> 8) & 0xff)
#define EP_MINOR(minor) ((minor) & 0xff)
#define EP_MAX(a, b) ((a) > (b) ? (a) : (b))
#define EP_MAJOR_USER (1 << 4)

typedef short ep_categroy_t;

/* request type */
typedef int ep_req_type;
#define req_type_get			0
#define req_type_post			1

/* crypt type */
typedef int ep_crypt_type;
#define	crypt_type_none			0
#define crypt_type_encrypt		1

/* compress type */
typedef int ep_compress_type;
#define	compress_type_none		0
#define compress_type_compress	1
#define compress_type_auto		2

/* packet instance */
typedef struct ep_pack ep_pack_t;
typedef int ep_bool_t;

typedef struct ep_pack_iterator
{
	const char * cur;
	ep_bool_t first;
} ep_pack_iterator_t;

typedef enum ep_pack_type
{
	PACKET_BINDATA,
	PACKET_STRING,
	PACKET_BOOL,
	PACKET_INT,
	PACKET_LONG,
	PACKET_ARRAY,
	PACKET_UNKNOWN = -1
} ep_pack_type;

typedef struct ep_req_param
{
	ep_req_type type;				/* request type */
	ep_categroy_t category;			/* message category */
	ep_crypt_type c_crypt;			/* client crypt type */
	ep_compress_type c_compress;	/* client compress type */
	ep_crypt_type s_crypt;			/* expect server crypt type */
	ep_compress_type s_compress;	/* expect server compress type */
	ep_pack_t * pack;				/* none encrypted pack */
} ep_req_param_t;

/*
 * the callback function that gets invoked on requesting path
 *
 * @opaque			defined user data
 * @fd				socket fd
 * @pack			event body package
 * @b_pack_reclaim	set it to 1 if you want to free packet manual
 *
 * @return
 *     a new packet for response
 */
typedef ep_pack_t * (* pfn_ep_cb)(void * opaque, int fd, ep_pack_t * pack, int * b_pack_reclaim);

#include "ep_alloctor.h"
#include "ep_client.h"
#include "ep_compress.h"
#include "ep_crypt.h"
#include "ep_packet.h"
#include "ep_queue.h"
#include "ep_request.h"
#include "ep_ringbuffer.h"
#include "ep_threadpool.h"
#include "ep_util.h"

#endif
