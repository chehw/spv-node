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

#include "bitcoin-message.h"
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
	[bitcoin_message_type_notfound] = "notefound",
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
	[bitcoin_message_type_merkleblock] = "merkle_block",
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
	[bitcoin_message_type_unknown] =     (cleanup_message_fn)NULL,
	[bitcoin_message_type_version] =     (cleanup_message_fn)bitcoin_message_version_cleanup,
	[bitcoin_message_type_verack] =      NULL,
	[bitcoin_message_type_addr] =        (cleanup_message_fn)bitcoin_message_addr_cleanup,
	[bitcoin_message_type_inv] =         (cleanup_message_fn)bitcoin_message_inv_cleanup,
	[bitcoin_message_type_getdata] =     (cleanup_message_fn)bitcoin_message_getdata_cleanup,
	[bitcoin_message_type_notfound] =    (cleanup_message_fn)bitcoin_message_notfound_cleanup,
	[bitcoin_message_type_getblocks] =   (cleanup_message_fn)bitcoin_message_getblocks_cleanup,
	[bitcoin_message_type_getheaders] =  (cleanup_message_fn)bitcoin_message_getheaders_cleanup,
	[bitcoin_message_type_tx] =          (cleanup_message_fn)bitcoin_message_tx_cleanup,
	[bitcoin_message_type_block] =       (cleanup_message_fn)bitcoin_message_block_cleanup,
	[bitcoin_message_type_headers] =     NULL,
	[bitcoin_message_type_getaddr] =     NULL,
	[bitcoin_message_type_mempool] =     NULL,
	[bitcoin_message_type_checkorder] =  NULL,
	[bitcoin_message_type_submitorder] = NULL,
	[bitcoin_message_type_reply] =       NULL,
	[bitcoin_message_type_ping] =        NULL,
	[bitcoin_message_type_pong] =        NULL,
	[bitcoin_message_type_reject] =      NULL,
	[bitcoin_message_type_filterload] =  NULL,
	[bitcoin_message_type_filteradd] =   NULL,
	[bitcoin_message_type_filterclear] = NULL,
	[bitcoin_message_type_merkleblock] = NULL,
	[bitcoin_message_type_alert] =       NULL,
	[bitcoin_message_type_sendheaders] = NULL,
	[bitcoin_message_type_feefilter] =   NULL,
	[bitcoin_message_type_sendcmpct] =   NULL,
	[bitcoin_message_type_cmpctblock] =  NULL,
	[bitcoin_message_type_getblocktxn] = NULL,
	[bitcoin_message_type_blocktxn] =    NULL,
};
static inline cleanup_message_fn get_cleanup_function(enum bitcoin_message_type type)
{
	if(type >= 0 && type < bitcoin_message_types_count) return s_cleanup_message_func[type];
	return NULL;
}

static parse_payload_fn s_payload_parsers[bitcoin_message_types_count] = 
{
	[bitcoin_message_type_unknown] =     NULL,
	[bitcoin_message_type_version] =     (parse_payload_fn)bitcoin_message_version_parse,
	[bitcoin_message_type_verack] =      NULL,
	[bitcoin_message_type_addr] =        (parse_payload_fn)bitcoin_message_addr_parse,
	[bitcoin_message_type_inv] =         (parse_payload_fn)bitcoin_message_inv_parse,
	[bitcoin_message_type_getdata] =     (parse_payload_fn)bitcoin_message_getdata_parse,
	[bitcoin_message_type_notfound] =    (parse_payload_fn)bitcoin_message_notfound_parse,
	[bitcoin_message_type_getblocks] =   (parse_payload_fn)bitcoin_message_getblocks_parse,
	[bitcoin_message_type_getheaders] =  (parse_payload_fn)bitcoin_message_getheaders_parse,
	[bitcoin_message_type_tx] =          (parse_payload_fn)bitcoin_message_tx_parse,
	[bitcoin_message_type_block] =       (parse_payload_fn)bitcoin_message_block_parse,
	[bitcoin_message_type_headers] =     NULL,
	[bitcoin_message_type_getaddr] =     NULL,
	[bitcoin_message_type_mempool] =     NULL,
	[bitcoin_message_type_checkorder] =  NULL,
	[bitcoin_message_type_submitorder] = NULL,
	[bitcoin_message_type_reply] =       NULL,
	[bitcoin_message_type_ping] =        NULL,
	[bitcoin_message_type_pong] =        NULL,
	[bitcoin_message_type_reject] =      NULL,
	[bitcoin_message_type_filterload] =  NULL,
	[bitcoin_message_type_filteradd] =   NULL,
	[bitcoin_message_type_filterclear] = NULL,
	[bitcoin_message_type_merkleblock] = NULL,
	[bitcoin_message_type_alert] =       NULL,
	[bitcoin_message_type_sendheaders] = NULL,
	[bitcoin_message_type_feefilter] =   NULL,
	[bitcoin_message_type_sendcmpct] =   NULL,
	[bitcoin_message_type_cmpctblock] =  NULL,
	[bitcoin_message_type_getblocktxn] = NULL,
	[bitcoin_message_type_blocktxn] =    NULL,
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


