/*
 * packet
 *
 * Copyright (C) 2012-2013 honeysense.com
 * @author rui.sun 2013-8-11
 */
#ifndef EP_PACK_H
#define EP_PACK_H

#include <stdint.h>

/*
 * new a new empty packet.
 */
ep_pack_t * ep_pack_new();

/*
 * create a new packet from given data.
 *
 * @note
 *   it will be a finish status and cannot append
 *    more elements more for current feature.
 */
ep_pack_t * ep_pack_create(const char * data, int len);

/*
 * get packet data
 */
const char * ep_pack_data(ep_pack_t * pack);

/*
 * get packet size
 */
int ep_pack_size(ep_pack_t * pack);

/*
 * finish packet
 */
void ep_pack_finish(ep_pack_t * pack);

/*
 * output all packet element
 */
void ep_pack_print(ep_pack_t * pack);

/*
 * destroy packet
 */
void ep_pack_destroy(ep_pack_t ** pack);

/* ----------------------------
   ITERATOR FUNCTION
   ---------------------------- */
ep_pack_iterator_t ep_pack_iterator_get(ep_pack_t * pack);
const char * ep_pack_iterator_key(ep_pack_iterator_t iter);
ep_pack_type ep_pack_iterator_type(ep_pack_iterator_t iter);
ep_bool_t ep_pack_iterator_next(ep_pack_iterator_t * iter);

/* ----------------------------
   READING FUNCTION
   ---------------------------- */
const char * ep_pack_iterator_bin_data(ep_pack_iterator_t iter);
int ep_pack_interator_bin_len(ep_pack_iterator_t iter);
const char * ep_pack_iterator_string(ep_pack_iterator_t iter);
ep_bool_t ep_pack_iterator_bool(ep_pack_iterator_t iter);
int ep_pack_iterator_int(ep_pack_iterator_t iter);
int64_t ep_pack_iterator_long(ep_pack_iterator_t iter);
ep_pack_iterator_t ep_pack_interator_array(ep_pack_iterator_t iter);

/* ----------------------------
   WRITE FUNCTION
   ---------------------------- */
void ep_pack_append_binary(ep_pack_t * pack, const char * name, const char * data, int size);
void ep_pack_append_string(ep_pack_t * pack, const char * name, const char * data);
void ep_pack_append_bool(ep_pack_t * pack, const char * name, ep_bool_t value);
void ep_pack_append_int(ep_pack_t * pack, const char * name, int value);
void ep_pack_append_long(ep_pack_t * pack, const char * name, int64_t value);
void ep_pack_append_start_array(ep_pack_t * pack, const char * name);
void ep_pack_append_finish_array(ep_pack_t * pack);

#endif