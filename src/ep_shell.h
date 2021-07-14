/*
 * shell for packet
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2012-7-31
 */
#ifndef EP_SHELL_H
#define EP_SHELL_H

#include "eventpack.h"
#include <stdint.h>

/* protocol magic number */
#define EP_MAGIC_NUMBER 0x9087 /* honeysense 9087 */

#pragma pack(1)

typedef struct ep_shell_proto
{
	ep_categroy_t		category:16;		/* message category */
	ep_req_type			type:3;				/* request type */
	ep_crypt_type		c_crypt:3;			/* client crypt type */
	ep_compress_type	c_compress:3;		/* client compress type */
	ep_crypt_type		s_crypt:3;			/* server crypt type */
	ep_compress_type	s_compress:3;		/* server compress type */
	int					serverd:1;			/* serverd */
} ep_shell_proto_t;

typedef struct ep_shell
{
	uint16_t			magic;				/* magic code, always EP_MAGIC_NUMBER */
	ep_shell_proto_t	proto;				/* message protocol */
	int32_t				shell_size;			/* size in shell */
	int32_t				decrypt_size;		/* real decrypt size if encrypted */
	int32_t				pack_size;			/* real packet size with any reduced */
} ep_shell_t;

#pragma pack()

#endif
