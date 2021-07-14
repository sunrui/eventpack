#include "eventpack.h"
#include "ep_service.h"
#include "proto.h"

#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

ep_alloctor_t io_pool;
int client_fd;
int count;

ep_pack_t * res_version_check(void * opaque, int fd, ep_pack_t * pack, int * b_req_reclaim)
{
	const char * platform = NULL;
	int ver = -1;
	ep_bool_t root = 1;

	ep_pack_print(pack);
	count++;

	{
		ep_pack_iterator_t iter;

		iter = ep_pack_iterator_get(pack);
		while (ep_pack_iterator_next(&iter))
		{
			ep_pack_type type;
			const char * key;

			type = ep_pack_iterator_type(iter);
			key = ep_pack_iterator_key(iter);

			if (strcmp(key, "ver") == 0)
			{
				ver = ep_pack_iterator_int(iter);
				assert(type == PACKET_INT);
				continue;
			}

			if (strcmp(key, "platform") == 0)
			{
				platform = ep_pack_iterator_string(iter);
				assert(type == PACKET_STRING);
				continue;
			}

			if (strcmp(key, "root") == 0)
			{
				root = ep_pack_iterator_bool(iter);
				assert(type == PACKET_BOOL);
				continue;
			}
		}

	}

	pack = ep_pack_new();
	if (pack == NULL)
	{
		return 0;
	}

	/* illegal request, record to sys log? */
	if (ver <= 0 || platform == NULL)
	{
		ep_pack_append_int(pack, "result", result_syntax_error);
		return pack;
	}

	fprintf(stdout, "server_req_version_check:\n");
	fprintf(stdout, "ver = %d, platform = %s, root = %d.\n\n", ver, platform, root);

	if (ver == 0x100)
	{
		ep_pack_append_int(pack, "result", result_ok);
		ep_pack_append_string(pack, "logs", "no need update current");
		return pack;
	}
	else
	{
		ep_pack_append_int(pack, "result", result_ok);
		ep_pack_append_string(pack, "logs", "need update now from office site");
		return pack;
	}
}

ep_pack_t * res_account_login(void * opaque, int fd, ep_pack_t * pack, int * b_req_reclaim)
{
	char uid[16 + 1] = { 0 };
	char pwd[16 + 1] = { 0 };

	ep_pack_print(pack);
	{
		ep_pack_iterator_t iter;

		iter = ep_pack_iterator_get(pack);
		while (ep_pack_iterator_next(&iter))
		{
			ep_pack_type type;
			const char * key;

			type = ep_pack_iterator_type(iter);
			key = ep_pack_iterator_key(iter);
			
			if (strcmp(key, "uid") == 0)
			{
				strncpy(uid, ep_pack_iterator_string(iter), sizeof(uid));
				assert(type == PACKET_STRING);
			}
			else if (strcmp(key, "pwd") == 0)
			{
				strncpy(pwd, ep_pack_iterator_string(iter), sizeof(pwd));
				assert(type == PACKET_STRING);
			}
		}
	}

	pack = ep_pack_new();
	if (pack == NULL)
	{
		return NULL;
	}

	if (uid[0] == 0 || pwd[0] == 0)
	{
		ep_pack_append_int(pack, "result", result_syntax_error);
		return pack;
	}

	ep_pack_append_int(pack, "result", result_ok);
	return pack;
}


void * io_alloc(int size)
{
	return malloc(size);
}

void io_free(void * ptr)
{
	free(ptr);
}

void my_ep_event_cb(void * opaque, ep_event_type type, int fd)
{
	{
		char ip[17];
		int port;
		int r;

		r = ep_sock_ip(fd, ip, &port);
		assert(r);

		switch (type)
		{
		case event_fd_accept: fprintf(stdout, "ACCEPT"); break;
		case event_fd_close: fprintf(stdout, "CLOSE"); break;
		case event_io_exception: fprintf(stdout, "EXCEPTION"); break;
		case event_io_overflow: fprintf(stdout, "OVERFLOW"); break;
		}
		fprintf(stdout, " fd = %d, ip = %s, port = %d.\n", fd, ip, port);
	}

	client_fd = fd;
}

int server_main()
{
	ep_service_conf_t conf;
	int ret;

	conf.listenport = 1356;
	conf.keepalive = 300;
	conf.nprocessors = 100;
	conf.backlog = 511;
	conf.io_def_capacity = 4 * 1024;
	conf.io_max_capacity = 4 * 1024 * 1024;
	conf.mini_compress_if = 4096;

	/*
	{
		io_pool.alloc = io_alloc;
		io_pool.free = io_free;
		ep_allocator(&io_pool);
	}
	*/
	//ep_alloctor_pool();

	ret = ep_service_start(&conf);
	switch (ret)
	{
	case  0: fprintf(stdout, "service start ok.\n"); break;
	case -1: fprintf(stdout, "service bind error.\n"); break;
	case -2: fprintf(stdout, "service listen error.\n"); break;
 	default: fprintf(stdout, "service fetal error.\n"); break;
	}
	if (ret != 0) return 0;

	ep_service_event(my_ep_event_cb, NULL);
	ep_service_register(EP_MAKEWORD(ep_id_platform, ep_id_version_check), res_version_check, NULL);
	ep_service_register(EP_MAKEWORD(ep_id_account, ep_id_account_login), res_account_login, NULL);

	fprintf(stdout, "service all handler register ok.\n");
	usleep(5 * 1000 * 1000);

	for (; ; count++)
	{
		ep_req_param_t param;
		ep_pack_t * pack;
		
		param.category = EP_MAKEWORD(ep_id_push, ep_id_push_update);
		//! will ignore this definition
		param.c_crypt = crypt_type_none;
		param.c_compress = compress_type_none;
		param.s_crypt = crypt_type_none;
		param.s_compress = compress_type_none;

		pack = ep_pack_new();
		if (pack == NULL)
		{
			return -1;
		}

		ep_pack_append_string(pack, "hello", "world");
		ep_pack_append_start_array(pack, "student");
		ep_pack_append_string(pack, "name", "zhang3");
		ep_pack_append_int(pack, "age", count);
		ep_pack_append_start_array(pack, "phone");
		ep_pack_append_string(pack, "type", "mobile");
		ep_pack_append_int(pack, "number", 1000);
		ep_pack_append_finish_array(pack);
		ep_pack_append_start_array(pack, "school");
		ep_pack_append_string(pack, "type", "local");
		ep_pack_append_int(pack, "number", 1001);
		ep_pack_append_finish_array(pack);
		ep_pack_append_string(pack, "comment", "he is at home");
		ep_pack_append_finish_array(pack);
		ep_pack_finish(pack);
		param.pack = pack;

		printf("======================================\n");
		printf("server_push per 1s %d...\n", count);
		ep_service_push(client_fd, 1, &param);
		ep_pack_destroy(&pack);

		usleep(100 * 1000);
	}

	printf("server begin close.\n");
	ep_service_stop();
	printf("server close ok.\n");

	return 0;
}
