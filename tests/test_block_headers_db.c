/*
 * test_block_headers_db.c
 * 
 * Copyright 2021 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pthread.h>
#include <db.h>
#include "block_hdrs-db.h"
#include "chains.h"
#include "utils.h"

#include <errno.h>
#include <signal.h>

static int on_add_block(struct blockchain * chain, 
	const uint256_t * block_hash, const int height, 
	const struct satoshi_block_header * hdr,
	void * user_data);
static int on_remove_block(struct blockchain * chain, 
		const uint256_t * block_hash, 
		const int height, void * user_data);
		
volatile int g_quit;
void on_signal(int sig)
{
	if(sig == SIGINT) g_quit = 1;
}
int main(int argc, char **argv)
{
	static const char db_home[] = "data";
	signal(SIGINT, on_signal);
	
	DB_ENV * db_env = NULL;
	int rc = db_env_create(&db_env, 0);
	assert(0 == rc);
	
	u_int32_t flags = DB_INIT_MPOOL 
		//~ | DB_INIT_CDB
		| DB_INIT_LOCK
		| DB_INIT_LOG
		//~ | DB_INIT_REP
		| DB_INIT_TXN
		| DB_REGISTER
		| DB_RECOVER
		| DB_THREAD
		| DB_CREATE
		| 0;
	rc = db_env->open(db_env, db_home, flags, 0666);
	if(rc) {
		db_env->err(db_env, rc, "db_env->open()");
	}
	
	assert(0 == rc);
	block_headers_db_t * hdrs_db = block_headers_db_init(NULL, db_env, NULL);
	assert(hdrs_db);
	
	blockchain_t * chain = blockchain_init(NULL, NULL, NULL, hdrs_db);
	assert(chain);
	
	chain->on_add_block = on_add_block;
	chain->on_remove_block = on_remove_block;
	
	const char * hdrs_dump_file = "temp-data/block_headers.dat";
	FILE * fp = fopen(hdrs_dump_file, "rb");
	assert(fp);
	
	struct satoshi_block_header hdr;
	int num_hdrs = 0;
	while(!g_quit) {
		int n = fread(&hdr, sizeof(hdr), 1, fp);
		if(n <= 0) break;
		
		rc = chain->add(chain, NULL, &hdr);
		assert(0 == rc);
		++num_hdrs;
	}
	
	printf("num_hdrs: %d\n", num_hdrs);
	printf("height: %d\n", (int)chain->height);
	
	fclose(fp);
	
	blockchain_cleanup(chain); free(chain);
	block_headers_db_cleanup(hdrs_db);
	free(hdrs_db);
	
	db_env->close(db_env, 0);
	return 0;
}

#define COLOR_RED "\e[31m"
#define COLOR_DEFAULT "\e[39m"

static int on_remove_block(struct blockchain * chain, 
		const uint256_t * block_hash, 
		const int height, void * user_data)
{
	fprintf(stderr, COLOR_RED "== %s(height=%d): hash=", __FUNCTION__, height);
	dump2(stderr, block_hash, sizeof(*block_hash));
	fprintf(stderr, COLOR_DEFAULT "\n");
	
	block_headers_db_t * db = user_data;
	assert(user_data);
	
	ssize_t count = db->del(db, block_hash);
	assert(count == 1);
	return 0;
}

static int on_add_block(struct blockchain * chain, 
	const uint256_t * block_hash, const int height, 
	const struct satoshi_block_header * hdr,
	void * user_data)
{
	fprintf(stderr, COLOR_RED"== %s(height=%d): hash=", __FUNCTION__, height);
	dump2(stderr, block_hash, sizeof(*block_hash));
	fprintf(stderr, COLOR_DEFAULT"\n");
	
	block_headers_db_t * db = user_data;
	assert(user_data);
	
	const struct block_header_record record = {
		.height = height,
		.hdr = *hdr,
	};
	
	ssize_t count = db->put(db, block_hash, &record);
	assert(count == 1);
	return 0;
}
