/*
 * packet
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-8-11
 */
#include "eventpack.h"
#include "ep_buffer.h"
#include "bson.h"

#include <assert.h>

struct ep_pack
{
	bson b;
};

/*
 * new a new empty packet.
 */
ep_pack_t * ep_pack_new()
{
	ep_pack_t * pack;
	
	pack = (ep_pack_t *)ep_calloc(1, sizeof(ep_pack_t));
	if (pack == NULL)
	{
        assert(0);
		return NULL;
	}

	bson_init(&pack->b);

	return pack;
}

/*
 * create a new packet from given data.
 *
 * @note
 *   it will be a finish status and cannot append
 *    more elements more for current feature.
 */
ep_pack_t * ep_pack_create(const char * data, int len)
{
	ep_pack_t * pack;
	
	assert(data != NULL && len != 0);
	pack = (ep_pack_t *)ep_calloc(1, sizeof(ep_pack_t));
	if (pack == NULL)
	{
        assert(0);
		return NULL;
	}

	/* data[0] cannot be 0 because bson use this as internal size */
	if (data != NULL && data[0] != 0 && len > 0)
	{
		int ret;
		ret = bson_init_finished_data_with_copy(&pack->b, (char *)data);
		if (ret == BSON_OK)
		{
			return pack;
		}
	}

	ep_free(pack);
	return NULL;
}

/*
 * get packet data
 */
const char * ep_pack_data(ep_pack_t * pack)
{
	return bson_data(&pack->b);
}

/*
 * get packet size
 */
int ep_pack_size(ep_pack_t * pack)
{
	return bson_size(&pack->b);
}

/*
 * finish packet
 */
void ep_pack_finish(ep_pack_t * pack)
{
	bson_finish(&pack->b);
}

/*
 * output all packet element
 */
void ep_pack_print(ep_pack_t * pack)
{
	if (pack != NULL)
	{
		bson_finish(&pack->b);
		bson_print(&pack->b);
	}
}

/*
 * destroy packet
 */
void ep_pack_destroy(ep_pack_t ** pack)
{
	if (pack != NULL && *pack != NULL)
	{
		bson_destroy(&(*pack)->b);
		ep_freep(*pack);
	}
}

ep_pack_iterator_t ep_pack_iterator_get(ep_pack_t * pack)
{
	ep_pack_iterator_t iter;
	bson_iterator_from_buffer((bson_iterator *)&iter, pack->b.data);
	return iter;
}

const char * ep_pack_iterator_key(ep_pack_iterator_t iter)
{
	return bson_iterator_key((bson_iterator *)&iter);
}

ep_pack_type bson_type_to_ep_pack_type(bson_type type)
{
	switch (type)
	{
	case BSON_BINDATA:
		return PACKET_BINDATA;
	case BSON_STRING:
		return PACKET_STRING;
	case BSON_BOOL:
		return PACKET_BOOL;
	case BSON_INT:
		return PACKET_INT;
	case BSON_LONG:
		return PACKET_LONG;
	case BSON_ARRAY:
		return PACKET_ARRAY;
	default:
		return PACKET_UNKNOWN;
	}
}

ep_pack_type ep_pack_iterator_type(ep_pack_iterator_t iter)
{
	return bson_type_to_ep_pack_type(bson_iterator_type((bson_iterator *)&iter));
}

ep_bool_t ep_pack_iterator_next(ep_pack_iterator_t * iter)
{
	ep_pack_type type;

	type = bson_type_to_ep_pack_type(bson_iterator_next((bson_iterator *)iter));

	return type != PACKET_UNKNOWN;
}

const char * ep_pack_iterator_bin_data(ep_pack_iterator_t iter)
{
	return bson_iterator_bin_data((bson_iterator *)&iter);
}

int ep_pack_interator_bin_len(ep_pack_iterator_t iter)
{
	return bson_iterator_bin_len((bson_iterator *)&iter);
}

const char * ep_pack_iterator_string(ep_pack_iterator_t iter)
{
	return bson_iterator_string((bson_iterator *)&iter);
}

ep_bool_t ep_pack_iterator_bool(ep_pack_iterator_t iter)
{
	return bson_iterator_bool((bson_iterator *)&iter);
}

int ep_pack_iterator_int(ep_pack_iterator_t iter)
{
	return bson_iterator_int((bson_iterator *)&iter);
}

int64_t ep_pack_iterator_long(ep_pack_iterator_t iter)
{
	return bson_iterator_long((bson_iterator *)&iter);
}

ep_pack_iterator_t ep_pack_interator_array(ep_pack_iterator_t iter)
{
	ep_pack_iterator_t ret_iter;
	const char * buffer;
	
	buffer = bson_iterator_value((bson_iterator *)&iter);
	bson_iterator_from_buffer((bson_iterator *)&ret_iter, buffer);

	return ret_iter;
}

void ep_pack_append_binary(ep_pack_t * pack, const char * name, const char * data, int size)
{
	bson_append_binary(&pack->b, name, BSON_BIN_BINARY, data, size);
}

void ep_pack_append_string(ep_pack_t * pack, const char * name, const char * data)
{
	bson_append_string(&pack->b, name, data);
}

void ep_pack_append_bool(ep_pack_t * pack, const char * name, ep_bool_t value)
{
	bson_append_bool(&pack->b, name, value);
}

void ep_pack_append_int(ep_pack_t * pack, const char * name, int value)
{
	bson_append_int(&pack->b, name, value);
}

void ep_pack_append_long(ep_pack_t * pack, const char * name, int64_t value)
{
	bson_append_long(&pack->b, name, value);
}

void ep_pack_append_start_array(ep_pack_t * pack, const char * name)
{
	bson_append_start_array(&pack->b, name);
}

void ep_pack_append_finish_array(ep_pack_t * pack)
{
	bson_append_finish_array(&pack->b);
}

#ifdef ep_PACKET_TEST

void ep_pack_test()
{
	ep_pack_t * pack;

	pack = ep_pack_new();

	ep_pack_append_string(pack, "hello", "world");
	ep_pack_append_start_array(pack, "student");
	ep_pack_append_string(pack, "name", "zhang3");
	ep_pack_append_int(pack, "age", 18);
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
	ep_pack_print(pack);

	{
		ep_pack_t * pack2;
		
		pack2 = ep_pack_create(ep_pack_data(pack), ep_pack_size(pack));
		ep_pack_finish(pack2);
		ep_pack_print(pack2);
		ep_pack_destroy(&pack2);
	}

	ep_pack_destroy(&pack);
}

#endif