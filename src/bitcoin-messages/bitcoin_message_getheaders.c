/*
 * bitcoin_message_getheaders.c
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

void bitcoin_message_getheaders_dump(const struct bitcoin_message_getheaders * msg)
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
