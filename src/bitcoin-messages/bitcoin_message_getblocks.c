/*
 * bitcoin_message_getblocks.c
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

#include "bitcoin-message.h"
#include "utils.h"

/**
 * getblocks
	Return an inv packet containing the list of blocks starting right after the last known hash in the block locator object, up to hash_stop or 500 blocks, whichever comes first.
**/
#define BITCOIN_MESSAGE_GETBLOCKS_HASH_COUNT_MAX (500)

void bitcoin_message_getblocks_dump(const struct bitcoin_message_getblocks * msg)
{
#ifdef _DEBUG
	printf("==== %s() ====\n", __FUNCTION__);
	printf("version: %u\n", (int)msg->version);
	printf("hash_count: %ld\n", (long)msg->hash_count);
	for(int i = 0; i < msg->hash_count; ++i) {
		printf("[%.4d]: ", i);
		dump(&msg->hashes[i], sizeof(msg->hashes[i]));
		printf("\n");
	}
	dump_line("hash_stop: ", &msg->hash_stop, sizeof(msg->hash_stop));
#endif
	return;
}

void bitcoin_message_getblocks_cleanup(struct bitcoin_message_getblocks * msg)
{
	if(NULL == msg) return;
	if(msg->hashes) free(msg->hashes);
	memset(msg, 0, sizeof(*msg));
}

struct bitcoin_message_getblocks * bitcoin_message_getblocks_parse(struct bitcoin_message_getblocks * msg, const unsigned char * payload, size_t length)
{
	assert(payload && length > 0);
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	
	if((p + sizeof(uint32_t)) >= p_end) return NULL;
	uint32_t version = 0;
	memcpy(&version, p, sizeof(uint32_t)); ; p += sizeof(uint32_t);
	
	size_t vint_size = varint_size((varint_t *)p);
	if((p + vint_size) >= p_end) return NULL;
	size_t count = varint_get((varint_t *)p); p += vint_size;
	if(count <= 0 || count > BITCOIN_MESSAGE_GETBLOCKS_HASH_COUNT_MAX) return NULL;
	
	size_t hashes_array_size = sizeof(*msg->hashes) * count;
	if((p + hashes_array_size + sizeof(msg->hash_stop)) != p_end) return NULL;
	
	uint256_t * hashes = malloc(hashes_array_size);
	assert(hashes);
	memcpy(hashes, p, hashes_array_size); p += hashes_array_size;
	
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	assert(msg);

	msg->version = version;
	msg->hash_count = count;
	msg->hashes = hashes;
	memcpy(&msg->hash_stop, p, sizeof(msg->hash_stop)); 
	return msg;
}

ssize_t bitcoin_message_getblocks_serialize(const struct bitcoin_message_getblocks * msg, unsigned char ** p_data)
{
	assert(msg && msg->hash_count > 0 && msg->hash_count <= BITCOIN_MESSAGE_GETBLOCKS_HASH_COUNT_MAX);
	
	size_t vint_size = varint_calc_size(msg->hash_count);
	assert(vint_size > 0 && vint_size <= 9);
	
	size_t hashes_array_size = sizeof(*msg->hashes) * msg->hash_count;
	size_t total_size = sizeof(uint32_t) 
			+ vint_size 
			+ hashes_array_size
			+ sizeof(msg->hash_stop);
	if(NULL == p_data) return total_size;
	
	unsigned char * data = *p_data;
	if(NULL == data) {
		data = malloc(total_size);
		assert(data);
		*p_data = data;
	}
	unsigned char * p = data;
	unsigned char * p_end = data + total_size;
	
	memcpy(p, &msg->version, sizeof(uint32_t)); p += sizeof(uint32_t);
	varint_set((varint_t *)p, msg->hash_count); p += vint_size;
	memcpy(p, msg->hashes, hashes_array_size);  p += hashes_array_size;
	memcpy(p, &msg->hash_stop, sizeof(msg->hash_stop)); p += sizeof(msg->hash_stop);
	
	assert(p == p_end);
	return total_size;
}
