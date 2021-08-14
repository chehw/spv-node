/*
 * bitcoin_message_inv.c
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

void bitcoin_message_inv_dump(const struct bitcoin_message_inv * msg)
{
#ifdef _DEBUG
	printf("==== %s() ====\n", __FUNCTION__);
	printf("num_invs: %d\n", (int)msg->count);
	
	for(int i = 0; i < msg->count; ++i) {
		struct bitcoin_inventory * inv = &msg->invs[i];
		printf("[%.4d]: type=0x%.8x, hash=", i, inv->type);
		dump(inv->hash, sizeof(inv->hash));
		printf("\n");
	}
#endif
	return;
}

void bitcoin_message_inv_cleanup(struct bitcoin_message_inv * msg)
{
	if(msg->invs) free(msg->invs);
	memset(msg, 0, sizeof(*msg));
	return;
}
struct bitcoin_message_inv * bitcoin_message_inv_parse(struct bitcoin_message_inv * msg, const unsigned char * payload, size_t length)
{
	assert(payload && length > 0);
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	size_t vint_size = varint_size((varint_t *)p);
	if((p + vint_size) > p_end) return NULL;
	
	size_t count = varint_get((varint_t *)p); p += vint_size;
	if(count <= 0 || count >= BITCOIN_MESSAGE_MAX_PAYLOAD_ENTRIES) return NULL;
	
	size_t invs_array_size = sizeof(struct bitcoin_inventory) * count;
	if((p + invs_array_size) != p_end) return NULL;
	
	struct bitcoin_inventory * invs = malloc(invs_array_size);
	assert(invs);
	memcpy(invs, p, invs_array_size);
	
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	assert(msg);
	
	msg->count = count;
	msg->invs = invs;
	return msg;
}

ssize_t bitcoin_message_inv_serialize(const struct bitcoin_message_inv * msg, unsigned char ** p_data)
{
	assert(msg && msg->count > 0 && msg->count <= BITCOIN_MESSAGE_MAX_PAYLOAD_ENTRIES);
	
	size_t vint_size = varint_calc_size(msg->count);
	assert(vint_size > 0 && vint_size <= 9);

	size_t total_size = vint_size + sizeof(struct bitcoin_message_inv) * msg->count;
	if(NULL == p_data) return total_size;
	
	unsigned char * data = *p_data;
	if(NULL == data) {
		data = malloc(total_size);
		assert(data);
		*p_data = data;
	}
	varint_set((varint_t *)data, msg->count);
	memcpy(data + vint_size, msg->invs, sizeof(struct bitcoin_message_inv) * msg->count);
	return total_size;
}
