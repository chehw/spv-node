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
