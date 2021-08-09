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

#include <endian.h>
#include "satoshi-types.h"
#include "utils.h"

typedef void (* cleanup_message_fn)(void * msg);
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
	[bitcoin_message_type_addr] = NULL,
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

static void bitcoin_message_clear(bitcoin_message_t * msg)
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

static int parse_payload(enum bitcoin_message_type type, const unsigned char * payload, size_t length, void ** p_object)
{
	void * object = NULL;
	switch(type) {
	case bitcoin_message_type_version:
		object = bitcoin_message_version_parse(NULL, payload, length);
		if(NULL == object) return -1;
		break;
	case bitcoin_message_type_verack:
	case bitcoin_message_type_ping:
		return 0;
	case bitcoin_message_type_alert: // Note: Support for alert messages has been removed from bitcoin core in March 2016. 
		return 0;
	case bitcoin_message_type_sendheaders: // https://github.com/bitcoin/bips/blob/master/bip-0130.mediawiki
		return 0;
	case bitcoin_message_type_getheaders:
		object = bitcoin_message_getheaders_parse(NULL, payload, length);
		if(NULL == object) return -1;
		break;
	default:
		return 0;	// skip unknown messages
	}
	
	*p_object = object;
	return 0;
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
	
	int rc = parse_payload(type, 
		msg_data->payload, msg_data->length, 
		&msg->priv);
	return rc;
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


#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "unsupport byte-order"
#endif
ssize_t bitcoin_message_version_serialize(const struct bitcoin_message_version *msg, unsigned char ** p_data)
{
	ssize_t size = 0;
	size = sizeof(int32_t) + sizeof(uint64_t) + sizeof(int64_t) + sizeof(msg->addr_recv);
	if(msg->version >= 106) {
		size += sizeof(msg->addr_from) + sizeof(msg->nonce);
		assert(msg->user_agent);
		size += varstr_size(msg->user_agent);
		size += sizeof(msg->start_height);
	}
	if(msg->version >= 70001) ++size;	// sizeof(msg->relay)
	
	if(NULL == p_data) return size;
	unsigned char * payload = *p_data;
	if(NULL == payload) {
		payload = malloc(size);
		assert(payload);
		*p_data = payload;
	}
	
	unsigned char * p = payload;
	unsigned char * p_end = p + size;
	
#define append_data(dst, src, size)  do { memcpy(dst, src, size); dst += size; } while(0)
	append_data(p, &msg->version, sizeof(msg->version));
	append_data(p, &msg->services, sizeof(msg->services));
	append_data(p, &msg->timestamp, sizeof(msg->timestamp));
	append_data(p, &msg->addr_recv, sizeof(msg->addr_recv));
	
	if(msg->version >= 106) {
		append_data(p, &msg->addr_from, sizeof(msg->addr_from));
		append_data(p, &msg->nonce, sizeof(msg->nonce));
		
		ssize_t cb_user_agent = varstr_size(msg->user_agent);
		append_data(p, msg->user_agent, cb_user_agent);
		append_data(p, &msg->start_height, sizeof(msg->start_height));
		
		if(msg->version >= 70001) {
			append_data(p, &msg->relay, sizeof(msg->relay));
		}
	}
#undef append_data

	assert(p == p_end);
	return size;
}

void bitcoin_message_version_cleanup(struct bitcoin_message_version * msg)
{
	if(msg->user_agent) varstr_free(msg->user_agent);
	memset(msg, 0, sizeof(*msg));
	return;
}
struct bitcoin_message_version * bitcoin_message_version_parse(struct bitcoin_message_version * _msg, const unsigned char * payload, size_t length)
{
	assert(payload && length > 0);
	struct bitcoin_message_version * msg = _msg;
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	assert(msg);
	
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	if((p + sizeof(int32_t) + sizeof(uint64_t) + sizeof(int64_t) + sizeof(msg->addr_recv)) > p_end) goto label_error;

	msg->version = *(int32_t *)p; 	p += sizeof(int32_t);
	msg->services = *(uint64_t *)p; p += sizeof(uint64_t);
	msg->timestamp = *(int64_t *)p;	p += sizeof(int64_t);
	memcpy(&msg->addr_recv, p, sizeof(msg->addr_recv)); p += sizeof(msg->addr_recv);
	if(msg->version < 106) return msg;
	
	if((p + sizeof(msg->addr_from) + sizeof(uint64_t)) >= p_end) goto label_error;
	memcpy(&msg->addr_from, p, sizeof(msg->addr_from)); p += sizeof(msg->addr_from);
	msg->nonce = *(uint64_t *)p; p += sizeof(uint64_t);
	
	size_t size = varstr_size((varstr_t *)p);
	if(size < 1 || (p + size + sizeof(int32_t) > p_end)) goto label_error;
	msg->user_agent = malloc(size);
	assert(msg->user_agent);
	memcpy(msg->user_agent, p, size); p += size;
	msg->start_height = *(int32_t *)p; p += sizeof(int32_t);
	
	if(msg->version >= 70001) {
		if(p >= p_end) goto label_error;
		msg->relay = *p++;
	}
	assert(p <= p_end);
	return msg;
	
label_error:
	bitcoin_message_version_cleanup(msg);
	if(NULL == _msg) free(msg);
	return NULL;
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
