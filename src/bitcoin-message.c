/*
 * bitcoin-message.c
 * 
 * Copyright 2021 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the "Software"), to deal in 
 * the Software without restriction, including without limitation the rights to 
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
 * of the Software, and to permit persons to whom the Software is furnished to 
 * do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>

#include "satoshi-types.h"
#include "utils.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "unsupport byte-order"
#endif

typedef void * (* parse_payload_fn)(void * object, const void * payload, size_t length);
typedef void  (* cleanup_message_fn)(void * msg);

static const char * s_sz_message_types[bitcoin_message_types_count] = 
{
	[bitcoin_message_type_unknown] = "unknown",
	[bitcoin_message_type_version] = "version",
	[bitcoin_message_type_verack] = "verack",
	[bitcoin_message_type_addr] = "addr",
	[bitcoin_message_type_inv] = "inv",
	[bitcoin_message_type_getdata] = "getdata",
	[bitcoin_message_type_notefound] = "notefound",
	[bitcoin_message_type_getblocks] = "getblocks",
	[bitcoin_message_type_getheaders] = "getheaders",
	[bitcoin_message_type_tx] = "tx",
	[bitcoin_message_type_block] = "block",
	[bitcoin_message_type_headers] = "headers",
	[bitcoin_message_type_getaddr] = "getaddr",
	[bitcoin_message_type_mempool] = "mempool",
	[bitcoin_message_type_checkorder] = "checkorder",
	[bitcoin_message_type_submitorder] = "submitorder",
	[bitcoin_message_type_reply] = "reply",
	[bitcoin_message_type_ping] = "ping", 
	[bitcoin_message_type_pong] = "pong",
	[bitcoin_message_type_reject] = "reject",
	[bitcoin_message_type_filterload] = "filterload",
	[bitcoin_message_type_filteradd] = "filteradd",
	[bitcoin_message_type_filterclear] = "filterclear",
	[bitcoin_message_type_merkle_block] = "merkle_block",
	[bitcoin_message_type_alert] = "alert",
	[bitcoin_message_type_sendheaders] = "sendheaders",
	[bitcoin_message_type_feefilter] = "feefilter",
	[bitcoin_message_type_sendcmpct] = "sendcmpct",
	[bitcoin_message_type_cmpctblock] = "cmpctblock",
	[bitcoin_message_type_getblocktxn] = "getblocktxn",
	[bitcoin_message_type_blocktxn] = "blocktxn",
	//
};
const char * bitcoin_message_type_to_string(enum bitcoin_message_type msg_type)
{
	if(msg_type < 0 || msg_type > bitcoin_message_types_count) return NULL;
	return s_sz_message_types[msg_type];
}
enum bitcoin_message_type bitcoin_message_type_from_string(const char * command)
{
	for(int i = 1; i < bitcoin_message_types_count; ++i) {
		if(strncmp(command, s_sz_message_types[i], 12) == 0) return i;
	}
	return bitcoin_message_type_unknown;
}

cleanup_message_fn s_cleanup_message_func[bitcoin_message_types_count] = {
	[bitcoin_message_type_unknown] = (cleanup_message_fn)NULL,
	[bitcoin_message_type_version] = (cleanup_message_fn)bitcoin_message_version_cleanup,
	[bitcoin_message_type_verack] = NULL,
	[bitcoin_message_type_addr] = (cleanup_message_fn)bitcoin_message_addr_cleanup,
	[bitcoin_message_type_inv] = (cleanup_message_fn)bitcoin_message_inv_cleanup,
	[bitcoin_message_type_getdata] = NULL,
	[bitcoin_message_type_notefound] = NULL,
	[bitcoin_message_type_getblocks] = NULL,
	[bitcoin_message_type_getheaders] = (cleanup_message_fn)bitcoin_message_getheaders_cleanup,
	[bitcoin_message_type_tx] = NULL,
	[bitcoin_message_type_block] = NULL,
	[bitcoin_message_type_headers] = NULL,
	[bitcoin_message_type_getaddr] = NULL,
	[bitcoin_message_type_mempool] = NULL,
	[bitcoin_message_type_checkorder] = NULL,
	[bitcoin_message_type_submitorder] = NULL,
	[bitcoin_message_type_reply] = NULL,
	[bitcoin_message_type_ping] = NULL,
	[bitcoin_message_type_pong] = NULL,
	[bitcoin_message_type_reject] = NULL,
	[bitcoin_message_type_filterload] = NULL,
	[bitcoin_message_type_filteradd] = NULL,
	[bitcoin_message_type_filterclear] = NULL,
	[bitcoin_message_type_merkle_block] = NULL,
	[bitcoin_message_type_alert] = NULL,
	[bitcoin_message_type_sendheaders] = NULL,
	[bitcoin_message_type_feefilter] = NULL,
	[bitcoin_message_type_sendcmpct] = NULL,
	[bitcoin_message_type_cmpctblock] = NULL,
	[bitcoin_message_type_getblocktxn] = NULL,
	[bitcoin_message_type_blocktxn] = NULL,
};
static inline cleanup_message_fn get_cleanup_function(enum bitcoin_message_type type)
{
	if(type >= 0 && type < bitcoin_message_types_count) return s_cleanup_message_func[type];
	return NULL;
}

static parse_payload_fn s_payload_parsers[bitcoin_message_types_count] = 
{
	[bitcoin_message_type_unknown] = NULL,
	[bitcoin_message_type_version] = (parse_payload_fn)bitcoin_message_version_parse,
	[bitcoin_message_type_verack] = NULL,
	[bitcoin_message_type_addr] = (parse_payload_fn)bitcoin_message_addr_parse,
	[bitcoin_message_type_inv] = (parse_payload_fn)bitcoin_message_inv_parse,
	[bitcoin_message_type_getdata] = NULL,
	[bitcoin_message_type_notefound] = NULL,
	[bitcoin_message_type_getblocks] = NULL,
	[bitcoin_message_type_getheaders] = (parse_payload_fn)bitcoin_message_getheaders_parse,
	[bitcoin_message_type_tx] = NULL,
	[bitcoin_message_type_block] = NULL,
	[bitcoin_message_type_headers] = NULL,
	[bitcoin_message_type_getaddr] = NULL,
	[bitcoin_message_type_mempool] = NULL,
	[bitcoin_message_type_checkorder] = NULL,
	[bitcoin_message_type_submitorder] = NULL,
	[bitcoin_message_type_reply] = NULL,
	[bitcoin_message_type_ping] = NULL,
	[bitcoin_message_type_pong] = NULL,
	[bitcoin_message_type_reject] = NULL,
	[bitcoin_message_type_filterload] = NULL,
	[bitcoin_message_type_filteradd] = NULL,
	[bitcoin_message_type_filterclear] = NULL,
	[bitcoin_message_type_merkle_block] = NULL,
	[bitcoin_message_type_alert] = NULL,
	[bitcoin_message_type_sendheaders] = NULL,
	[bitcoin_message_type_feefilter] = NULL,
	[bitcoin_message_type_sendcmpct] = NULL,
	[bitcoin_message_type_cmpctblock] = NULL,
	[bitcoin_message_type_getblocktxn] = NULL,
	[bitcoin_message_type_blocktxn] = NULL,
};
static inline parse_payload_fn get_payload_parser(enum bitcoin_message_type type)
{
	if(type >= 0 && type < bitcoin_message_types_count) return s_payload_parsers[type];
	return NULL;
}

void bitcoin_message_clear(bitcoin_message_t * msg)
{
	if(NULL == msg) return;
	if(msg->priv) {
		cleanup_message_fn cleanup = get_cleanup_function(msg->msg_type);
		if(cleanup) cleanup(msg->priv);
		free(msg->priv);
		msg->priv = NULL;
	}
	
	if(msg->msg_data) {
		free(msg->msg_data);
		msg->msg_data = NULL;
	}
	
	msg->msg_type = bitcoin_message_type_unknown;
	return;
}

int bitcoin_message_parse(bitcoin_message_t * msg, const struct bitcoin_message_header * hdr, const void * payload, size_t length)
{
	assert(msg && hdr);
	bitcoin_message_clear(msg);	// clear old data
	
	if(0 == length) length = hdr->length;
	assert(length >= hdr->length);
	if(NULL == payload) payload = hdr->payload;
	
	enum bitcoin_message_type type = bitcoin_message_type_from_string(hdr->command);
	if(type == bitcoin_message_type_unknown) return -1;
	
	// verify checksum
	unsigned char hash[32] = { 0 };
	hash256(payload, hdr->length, hash);
	if(memcmp(hash, &hdr->checksum, 4) != 0) return -1;	// invalid checksum
	
	// copy data
	size_t size = sizeof(*hdr) + hdr->length;
	struct bitcoin_message_header * msg_data = malloc(size);
	assert(msg_data);
	if(payload == hdr->payload) memcpy(msg_data, hdr, size);
	else {
		memcpy(msg_data, hdr, sizeof(*hdr));
		if(hdr->length > 0) memcpy(msg_data->payload, payload, hdr->length);
	}
	msg->msg_data = msg_data;
	msg->msg_type = type;
	
	if(msg_data->length > 0) {
		parse_payload_fn parser = get_payload_parser(type);
		if(parser) {
			msg->priv = parser(NULL, msg_data->payload, msg_data->length);
			if(NULL == msg->priv) return -1;
		}
	}
	return 0;
}

void bitcoin_message_cleanup(bitcoin_message_t * msg)
{
	if(NULL == msg) return;
	if(NULL == msg->clear) msg->clear = bitcoin_message_clear;
	
	msg->clear(msg);
	return;
}

ssize_t bitcoin_message_serialize(const struct bitcoin_message * msg, unsigned char ** p_data)
{
	return 0;
}

void bitcoin_message_getheaders_cleanup(struct bitcoin_message_getheaders * msg)
{
	if(NULL == msg) return;
	if(msg->hashes) free(msg->hashes);
	memset(msg, 0, sizeof(*msg));
	return;
}
struct bitcoin_message_getheaders * bitcoin_message_getheaders_parse(struct bitcoin_message_getheaders * _msg, const unsigned char * payload, size_t length)
{
	assert(payload && length > 0);
	struct bitcoin_message_getheaders * msg = _msg;
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	assert(msg);
	
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	size_t size = 0;
	
	if((p + sizeof(int32_t)) >= p_end) goto label_error;
	msg->version = *(int32_t *)p; 	p += sizeof(int32_t);
	
	size = varint_size((varint_t *)p);
	if((p + size) >= p_end) goto label_error;
	msg->hash_count = varint_get((varint_t *)p); p += size;
	if(msg->hash_count <= 0 || msg->hash_count > INT32_MAX) goto label_error;
	
	size = sizeof(*msg->hashes) * msg->hash_count;
	if((p + size) >= p_end) goto label_error;
	uint256_t * hashes = malloc(size);
	assert(hashes);
	memcpy(hashes, p, size); p += size;
	msg->hashes = hashes;
	
	if((p + sizeof(msg->hash_stop)) > p_end) goto label_error;
	memcpy(&msg->hash_stop, p, sizeof(msg->hash_stop)); 
	return msg;
	
label_error:
	bitcoin_message_getheaders_cleanup(msg);
	if(NULL == _msg) free(msg);
	return NULL;
	
}

void bitcoin_message_inv_cleanup(struct bitcoin_message_inv * msg)
{
	if(msg->invs) free(msg->invs);
	memset(msg, 0, sizeof(*msg));
	return;
}
struct bitcoin_message_inv * bitcoin_message_inv_parse(struct bitcoin_message_inv * _msg, const unsigned char * payload, size_t length)
{
	assert(payload && length > 0);
	struct bitcoin_message_inv * msg = _msg;
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	assert(msg);
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	size_t size = varint_size((varint_t *)p);
	if((p + size) >= p_end) goto label_error;
	msg->count = varint_get((varint_t *)p); p += size;
	
	size = sizeof(struct bitcoin_inventory) * msg->count;
	if((p + size) > p_end) goto label_error;
	struct bitcoin_inventory * invs = malloc(size);
	assert(invs);
	memcpy(invs, p, size);
	msg->invs = invs;
	return msg;
	
label_error:
	bitcoin_message_inv_cleanup(msg);
	if(NULL == _msg) free(msg);
	return NULL;
	
}
