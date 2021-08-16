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
#include <search.h>

#include "gcloud/google-oauth2.h"
#include "gcloud/gcloud-storage.h"

#define DEBUG_BREAK_HEIGHT 193183	// bug locator

static int custom_init(spv_node_context_t * spv);
void on_signal(int sig);

static const char * s_block_headers_file = "data/block_headers.dat";
static FILE * s_block_headers_fp;
static ssize_t load_block_headers(blockchain_t * chain, const char * block_headers_file);
static void save_block_headers(const struct bitcoin_message_block_headers * msg_hdrs);

static void dump_active_chain(const active_chain_t * chain, int index)
{
	char logfile[200] = "";
	snprintf(logfile, sizeof(logfile), "log/chain_%.3d.dat", index);
	
	FILE * fp = fopen(logfile, "w+");

#define MAX_STACK_DEPTH	(100 * 10000)
	const struct block_info ** stack = calloc(MAX_STACK_DEPTH, sizeof(*stack));
	assert(stack);
	ssize_t top = 0;
	
	const struct block_info * node = chain->head;
	const struct block_info * sibling = node->next_sibling;

	// DFS_traverse
	while(sibling) stack[top++] = sibling;
	stack[top++] = node;
	while(top > 0)
	{
		node = stack[--top];
		dump2(fp, &node->hash, 32);
		fprintf(fp, "\n");
		
		node = node->first_child;
		if(NULL == node) continue;
		sibling = node->next_sibling;
		while(sibling) stack[top++] = sibling;
		stack[top++] = node;
	}
	
	free(stack);
	fclose(fp);
	return;
}

static void dump_chains_info(blockchain_t * chain)
{
	system("mkdir -p log");
	fprintf(stderr, "height: %ld\n", (long)chain->height);
	fprintf(stderr, "num_active_chains: %d\n", (int)chain->candidates_list->count);

	for(int i = 0; i < chain->candidates_list->count; ++i)
	{
		fprintf(stderr, "  -- active chain %d\n", i);
		active_chain_t * active = chain->candidates_list->chains[i];
		dump_active_chain(active, i);
	}

	FILE * fp = fopen("log/heirs.dat", "wb+");
	assert(fp);

	ssize_t count = fwrite(chain->heirs, sizeof(*chain->heirs), chain->height + 1, fp);
	assert(count == (chain->height + 1));
	fclose(fp);

	return;
}

int main(int argc, char **argv)
{
	signal(SIGINT, on_signal);
	signal(SIGUSR1, on_signal);
	
	int rc = 0;
	const char * credentials_file = ".private/credentials.json";
	
	static const char * g_scope = "https://www.googleapis.com/auth/devstorage.read_write";
	const char * bucket_name = "storage-tokyo-01";
	google_oauth2_context_t * gauth = google_oauth2_context_new(NULL);
	rc = gauth->load_credentials_file(gauth, credentials_file);
	gauth->set_scope(gauth, g_scope);
	
	gcloud_storage_context_t * gstorage = gcloud_storage_context_init(NULL, gauth, bucket_name, NULL);
	assert(gstorage);
	
	spv_node_context_t * spv = spv_node_context_init(NULL, gstorage);
	rc = spv_node_parse_args(spv, argc, argv);
	assert(0 == rc);
	
	ssize_t height = load_block_headers(spv->chain, s_block_headers_file);
	
	if(height == DEBUG_BREAK_HEIGHT) {
		dump_chains_info(spv->chain);
		exit(0);
	}
	if(height == 0) {
		fprintf(stderr, "[info]: block_headers_file not found. generating ...\n");
	}
	rc = custom_init(spv);
	assert(0 == rc);
	
	rc = spv_node_run(spv, 0);
	
	height = blockchain_get_latest(spv->chain, NULL, NULL);
	fprintf(stderr, "[INFO]: spv_node_run()=%d, lastest block: %ld\n",
		rc, height);
	
	spv_node_context_cleanup(spv);
	free(spv);
	
	if(s_block_headers_fp) fclose(s_block_headers_fp);
	s_block_headers_fp = NULL;
	return rc;
}

static void save_block_headers(const struct bitcoin_message_block_headers * msg)
{
	FILE * fp = s_block_headers_fp;
	if(NULL == fp) {
		fp = fopen(s_block_headers_file, "wb+");
		assert(fp);
		
		s_block_headers_fp = fp;
	}
	
	size_t count = 0;
	for(int i = 0; i < msg->count; ++i) {
		size_t n = fwrite(&msg->hdrs[i], sizeof(struct satoshi_block_header), 1, fp);
		assert(n == 1);
		count += n;
	}
	fflush(fp);
	return;
}

static ssize_t load_block_headers(blockchain_t * chain, const char * block_headers_file)
{
	FILE * fp = fopen(block_headers_file, "rb");
	if(NULL == fp) return 0;
	
#define BATCH_SIZE (2000)
	size_t total = 0;
	size_t num_hdrs = 0;
	struct satoshi_block_header * hdrs = calloc(BATCH_SIZE, sizeof(*hdrs));
	assert(hdrs);
	
	while((num_hdrs = fread(hdrs, sizeof(*hdrs), BATCH_SIZE, fp)) > 0)
	{
		for(int i = 0; i < num_hdrs; ++i) {
			chain->add(chain, NULL, &hdrs[i]);
		}
		
		total += num_hdrs;
	}
	free(hdrs);
	fclose(fp);
	
#undef BATCH_SIZE
	printf("latest height: %ld\n", chain->height);
	dump_line("hash: ", &chain->heirs[chain->height].hash, 32);
	dump_line("hdr : ", chain->heirs[chain->height].hdr, 80);
	
	return chain->height;
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

static int bitcoin_message_getheaders_set(struct bitcoin_message_getheaders * getheaders,
	uint32_t version,
	ssize_t hash_count,
	const uint256_t * known_hashes,
	const uint256_t * hash_stop)
{
	if(hash_count <= 0 || hash_count > 2000) return -1;

	assert(known_hashes);
	
	uint256_t * hashes = realloc(getheaders->hashes, sizeof(uint256_t) * hash_count);
	assert(hashes);
	getheaders->hashes = hashes;
	
	getheaders->version = version;
	getheaders->hash_count = hash_count;
	memcpy(hashes, known_hashes, sizeof(uint256_t) * hash_count);
	if(hash_stop) memcpy(&getheaders->hash_stop, hash_stop, sizeof(*hash_stop));
	
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
	
	
	uint256_t * hashes = NULL;
	blockchain_t * chain = spv->chain;
	assert(chain && chain->add);
	
	ssize_t count = blockchain_get_known_hashes(chain, 0, &hashes);
	assert(count > 0 && hashes);
	
	int rc = bitcoin_message_getheaders_set(getheaders, version, count, hashes, NULL);
	if(0 == rc) {
		if(spv->send_message) spv->send_message(spv, getheaders_msg);
	}
	free(hashes);
	bitcoin_message_free(getheaders_msg);
	return rc;
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

#include <limits.h>
#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif
#define dump_json_response(title, jresponse) do { assert(jresponse); \
		fprintf(stderr, "%s: %s\n", title, json_object_to_json_string_ext(jresponse, JSON_C_TO_STRING_PRETTY)); \
		json_object_put(jresponse); \
		jresponse = NULL; \
	} while(0)

static int upload_to_gstorage(gcloud_storage_context_t * gstorage, const struct bitcoin_message_block_headers * msg)
{
	// test2. upload files
#define ROOT_PATH "block_hdrs/"
	char object_name[200] = ROOT_PATH;
	char * p_name = object_name + sizeof(ROOT_PATH) - 1;
#undef ROOT_PATH

	for(int i = 0; i < msg->count; ++i) {
		unsigned char hash[32] = "";
		const struct satoshi_block_header * hdr = &msg->hdrs[i].hdr;
		hash256(hdr, sizeof(*hdr), hash);
		
		// reverse bytes;
		uint256_reverse((uint256_t *)hash);	// big-endian hash to little-endian search-index
		ssize_t cb = bin2hex(hash, 32, &p_name);
		assert(cb == 64);
		strcpy(&p_name[64], ".hdr");
	
		json_object * jresponse = gstorage->objects->insert(gstorage, object_name, "media", hdr, sizeof(*hdr), NULL);
		dump_json_response(object_name, jresponse);
	}
	
	return 0;
}

static int on_message_headers(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	struct bitcoin_message_block_headers * msg = bitcoin_message_get_object(in_msg);
	bitcoin_message_block_headers_dump(msg);
	if(msg->count <= 0) return -1;
	
	gcloud_storage_context_t * gstorage = spv->user_data;
	assert(gstorage);
	
	blockchain_t * chain = spv->chain;
	assert(chain && chain->add);
	int rc = 0;
	
	for(int i = 0; i < msg->count; ++i) {
		rc = chain->add(chain, NULL, &msg->hdrs[i].hdr);
		if(rc) break;
	}
	
	save_block_headers(msg);
	
	///< @todo use a background thread to upload data
	UNUSED(upload_to_gstorage);
	//~ upload_to_gstorage(gstorage, msg);
	
	ssize_t height = chain->height;
	fprintf(stderr, "\e[32m" "current height: %ld" "\e[39m" "\n", (long)height);
	

	assert(height != DEBUG_BREAK_HEIGHT);
	
	// pull more headers
	struct bitcoin_message * getheaders_msg = bitcoin_message_new(NULL, 
		in_msg->msg_data->magic, 
		bitcoin_message_type_getheaders, 
		spv);
	struct bitcoin_message_getheaders * getheaders = bitcoin_message_get_object(getheaders_msg);
	assert(getheaders);
	
	uint32_t version = spv->peer_version;
	if(0 == version || version > spv->protocol_version) version = spv->protocol_version;
	
	uint256_t * hashes = NULL;
	
	
	ssize_t count = blockchain_get_known_hashes(chain, 100, &hashes);
	assert(count > 0 && hashes);
	
	rc = bitcoin_message_getheaders_set(getheaders, version, count, hashes, NULL);
	if(0 == rc) {
		if(spv->send_message) spv->send_message(spv, getheaders_msg);
	}
	free(hashes);
	bitcoin_message_free(getheaders_msg);
	return rc;
}


