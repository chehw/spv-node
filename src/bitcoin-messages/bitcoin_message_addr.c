/*
 * bitcoin_message_addr.c
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
#include <arpa/inet.h>
#include "bitcoin-message.h"

struct bitcoin_message_addr * bitcoin_message_addr_parse(struct bitcoin_message_addr * msg, const unsigned char * payload, size_t length)
{
	const unsigned char * p = payload;
	const unsigned char * p_end = payload + length;
	if(p_end <= p) return NULL;
	
	ssize_t count = varint_get((varint_t *)p);
	p += varint_size((varint_t *)p);
	
	size_t size = sizeof(struct bitcoin_network_address) * count;
	if((p + size) != p_end) return NULL;
	
	struct bitcoin_network_address * addrs = malloc(size);
	assert(addrs);
	memcpy(addrs, p, size);
	
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	
	msg->count = count;
	msg->addrs = addrs;
	return msg;
}

void bitcoin_message_addr_cleanup(struct bitcoin_message_addr * msg)
{
	if(NULL == msg) return;
	if(msg->addrs) free(msg->addrs);
	memset(msg, 0, sizeof(*msg));
	return;
}

ssize_t bitcoin_message_addr_serialize(const struct bitcoin_message_addr * msg, unsigned char ** p_data)
{
	ssize_t vint_size = varint_calc_size(msg->count);
	assert(vint_size > 0 && vint_size <= 9);
	
	size_t total_size = vint_size + sizeof(struct bitcoin_network_address) * msg->count;
	if(NULL == p_data) return total_size;
	
	unsigned char * data = *p_data;
	if(NULL == data) {
		data = malloc(total_size);
		assert(data);
		*p_data = data;
	}
	
	varint_set((varint_t *)data, msg->count);
	data += vint_size;
	
	if(msg->count) {
		memcpy(data, msg->addrs, sizeof(struct bitcoin_network_address) * msg->count);
	}
	return total_size;
}
