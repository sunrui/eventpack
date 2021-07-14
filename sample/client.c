#include "eventpack.h"
#include "proto.h"

#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

extern int count;

#define REQUEST_TIMEOUT 60

int req_check_version(ep_client_t * client)
{
	ep_req_t * handle;
	ep_pack_t * pack;
	int ret;

	pack = ep_pack_new();
	if (pack == NULL)
	{
		return 0;
	}

	ep_pack_append_int(pack, "ver", 0x1000);
	ep_pack_append_string(pack, "platform", "windows");
	ep_pack_append_bool(pack, "root", 1);

	// dump
	ep_pack_print(pack);

	{
		ep_req_param_t param;

		param.category = EP_MAKEWORD(ep_id_platform, ep_id_version_check);
		param.type = req_type_get;
		param.c_crypt = crypt_type_none;
		param.c_compress = compress_type_auto;
		param.s_crypt = crypt_type_none;
		param.s_compress = compress_type_auto;
		param.pack = pack;

		handle = ep_req_new(client, &param, NULL, NULL);
		ep_pack_destroy(&pack);
		if (handle == NULL)
		{
			return 0;
		}
	}

	ret = ep_req_wait(handle, &pack, REQUEST_TIMEOUT);
	if (pack == NULL)
	{
		fprintf(stdout, "server not response. \n");
		ep_req_destroy(&handle);
		return 0;
	}

	// dump server result
	ep_pack_print(pack);

	ep_req_destroy(&handle);
	return 1;
}

int req_account_login(ep_client_t * client, const char * uid, const char * pwd)
{
	ep_req_t * handle;
	ep_pack_t * pack;
	int ret;

	char token[33] = { 0 };
	int result = result_ok;

	if (uid == NULL || pwd == NULL)
	{
		return result_syntax_error;
	}

	pack = ep_pack_new();
	if (pack == NULL)
	{
		return 0;
	}

	ep_pack_append_string(pack, "uid", uid);
	ep_pack_append_string(pack, "pwd", pwd);

	// try to attack on the server
#if 0
	{
		int size = 50 * 1024 * 1024;
		char * p = (char *)ep_calloc(1, size);
		ep_pack_append_binary(pack, "binay", p, size);
		ep_free(p);
	}
#endif

	{
		ep_req_param_t param;

		param.category = EP_MAKEWORD(ep_id_account, ep_id_account_login);
		param.type = req_type_get;
		param.c_crypt = crypt_type_none;
		param.c_compress = compress_type_none;
		param.s_crypt = crypt_type_none;
		param.s_compress = compress_type_none;
		param.pack = pack;

		handle = ep_req_new(client, &param, NULL, NULL);
		ep_pack_destroy(&pack);
		if (handle == NULL)
		{
			return result_no_response;
		}
	}

	ret = ep_req_wait(handle, &pack, REQUEST_TIMEOUT);
	if (pack == NULL)
	{ 
		ep_pack_destroy(&pack);
		return result_no_response;
	}

	{
		ep_pack_iterator_t iter;

		iter = ep_pack_iterator_get(pack);
		while (ep_pack_iterator_next(&iter))
		{
			ep_pack_type type;
			const char * key;

			type = ep_pack_iterator_type(iter);
			key = ep_pack_iterator_key(iter);

			if (strcmp(key, "result") == 0)
			{
				result = ep_pack_iterator_int(iter);
				assert(type == PACKET_INT);
			}
			else if (strcmp(key, "token") == 0)
			{
				assert(strlen(ep_pack_iterator_string(iter)) == sizeof(token));
				strncpy(token, ep_pack_iterator_string(iter), sizeof(token));
				assert(type == PACKET_STRING);
			}
		}
	}

	ep_pack_print(pack);

	ep_req_destroy(&handle);
	return result;
}

ep_pack_t * req_push(void * opaque, int fd, ep_pack_t * pack, int * b_req_reclaim)
{
	// dump server result
	fprintf(stdout, "client_received_push:\n");
	ep_pack_print(pack);
	fprintf(stdout, "\n");

	return NULL;
}

int client_main()
{
	ep_client_t * client;
	ep_client_conf_t conf;
	int ret;

	strcpy(conf.ip, "127.0.0.1");
	conf.port = 1356;
	conf.keepalive = 300;
	conf.io_def_capacity = 4 * 1024;
	conf.io_max_capacity = 4 * 1024 * 1024;
	conf.mini_compress_if = 4096;
	conf.wait_timeout = 30;

	ret = ep_client_start(&conf, &client);
    switch (ret)
	{
        case  0: fprintf(stdout, "client start ok.\n"); break;
        case -1: fprintf(stdout, "set client EP_CRYPT failed.\n"); break;
        case -2: fprintf(stdout, "server not response.\n"); break;
        default: fprintf(stdout, "init module failed.\n"); break;
	}
    
	if (client == NULL)
    {
        assert(0);
        return 0;
    }
    
	/* push param */
	ep_client_register(client, EP_MAKEWORD(ep_id_push, ep_id_push_update), req_push, NULL);

	{
		int loop = 1;
		for (; ; loop++)
		{
			fprintf(stdout, "\n================ LOOP %d ================\n", loop);
			ret = req_account_login(client, "uid", "pwd");
			assert(ret == result_ok);

			ret = req_check_version(client);
			assert(ret == 1);

			usleep(100 * 1000);
		}
	}

	printf("client begin close.\n");
	ep_client_stop(&client);
	printf("client close ok.\n");

	return 0;
}
