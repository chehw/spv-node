/*
 * test_bitcoin-messages.c
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

#include "spv-node.h"
#include "satoshi-types.h"
#include "utils.h"

#include <signal.h>

static int custom_init(spv_node_context_t * spv);
void on_signal(int sig);
int main(int argc, char **argv)
{
	signal(SIGINT, on_signal);
	signal(SIGUSR1, on_signal);
	
	int rc = 0;
	spv_node_context_t * spv = spv_node_context_init(NULL, NULL);
	rc = spv_node_parse_args(spv, argc, argv);
	assert(0 == rc);
	
	rc = custom_init(spv);
	assert(0 == rc);
	
	rc = spv_node_run(spv, 0);
	spv_node_context_cleanup(spv);
	free(spv);
	return rc;
}

static int on_message_verack(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_inv(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_getdata(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_notfound(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_getblocks(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_getheaders(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_tx(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_block(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_headers(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int custom_init(spv_node_context_t * spv)
{
	spv_node_message_callback_fn * callbacks = spv->msg_callbacks;
	assert(callbacks);

	callbacks[bitcoin_message_type_verack]     = on_message_verack;
	callbacks[bitcoin_message_type_inv]        = on_message_inv;
	callbacks[bitcoin_message_type_getdata]    = on_message_getdata;
	callbacks[bitcoin_message_type_notfound]   = on_message_notfound;
	callbacks[bitcoin_message_type_getblocks]  = on_message_getblocks;
	callbacks[bitcoin_message_type_getheaders] = on_message_getheaders;
	callbacks[bitcoin_message_type_tx]         = on_message_tx;
	callbacks[bitcoin_message_type_block]      = on_message_block;
	callbacks[bitcoin_message_type_headers]    = on_message_headers;

	return 0; 
}

static int on_message_verack(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	// send test data when 'verack' msg received
	bitcoin_message_header_dump(in_msg->msg_data);
	
	struct bitcoin_message * getheaders_msg = bitcoin_message_new(NULL, 
		in_msg->msg_data->magic, 
		bitcoin_message_type_getheaders, 
		spv);
	struct bitcoin_message_getheaders * getheaders = bitcoin_message_get_object(getheaders_msg);
	assert(getheaders);
	
	uint32_t version = spv->peer_version;
	if(0 == version || version > spv->protocol_version) version = spv->protocol_version;
	
	size_t hash_count = 1;
	uint256_t hashes[hash_count];
	memset(hashes, 0, sizeof(hashes[0]) * hash_count);
	void * p_hash = hashes;
	ssize_t cb = hex2bin("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000", -1, &p_hash);
	assert(cb == 32);

	getheaders->version = version;
	getheaders->hash_count = hash_count;
	getheaders->hashes = hashes;
	if(spv->send_message) spv->send_message(spv, getheaders_msg);
	
	getheaders->hashes = NULL;
	getheaders->hash_count = 0;

	bitcoin_message_free(getheaders_msg);
	return 0;
}

static int on_message_inv(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	struct bitcoin_message_inv * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_inv_dump(msg);
	
	/** 
	 * getdata is used in response to inv, to retrieve the content of a specific object, 
	 * and is usually sent after receiving an inv packet, after filtering known elements. 
	*/
	struct bitcoin_message * getdata_msg = bitcoin_message_new(NULL, 
		in_msg->msg_data->magic, 
		bitcoin_message_type_getdata, 
		spv);

	assert(getdata_msg);
	struct bitcoin_message_getdata * getdata = bitcoin_message_get_object(getdata_msg);
	
	///< @todo : filter-out known elements
	getdata->count = msg->count;
	getdata->invs = (struct bitcoin_inventory *)msg->invs;

	bitcoin_message_getdata_dump(getdata);
	assert(spv->send_message);
	
	if(spv->send_message) spv->send_message(spv, getdata_msg);
	
	// clear data
	getdata->count = 0;
	getdata->invs = NULL;
	
	bitcoin_message_free(getdata_msg);
	return 0;
}

static int on_message_getdata(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	struct bitcoin_message_getdata * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_getdata_dump(msg);
	return 0;
}

static int on_message_notfound(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	struct bitcoin_message_getdata * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_getdata_dump(msg);
	return 0;
}

static int on_message_getblocks(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	struct bitcoin_message_getblocks * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_getblocks_dump(msg);
	
	return 0;
}

static int on_message_getheaders(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	struct bitcoin_message_getheaders * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_getheaders_dump(msg);
	return 0;
}

static int on_message_tx(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	bitcoin_message_tx_t * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_tx_dump(msg);
	
//	exit(0);
	return 0;
}

static int on_message_block(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	bitcoin_message_block_t * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_block_dump(msg);
	
//	exit(0);
	return 0;
}

static int on_message_headers(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	struct bitcoin_message_block_headers * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_block_headers_dump(msg);
	
//	exit(0);
	return 0;
}


