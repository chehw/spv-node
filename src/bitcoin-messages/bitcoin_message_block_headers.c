/*
 * bitcoin_message_block_headers.c
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
#include "satoshi-types.h"
#include "auto_buffer.h"
#include "utils.h"

struct bitcoin_message_block_headers * bitcoin_message_block_headers_parse(
	struct bitcoin_message_block_headers * msg, 
	const unsigned char * payload, size_t length)
{
	assert(msg && payload && length > 0);
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	ssize_t count = varint_get((varint_t *)p); p += varint_size((varint_t *)p);
	if(count <= 0 || p >= p_end) return NULL;
	
	struct bitcoin_message_block_header * hdrs = calloc(count, sizeof(*hdrs));
	assert(hdrs);
	
	for(ssize_t i = 0; i < count; ++i) {
		if((p + sizeof(struct satoshi_block_header)) >= p_end) goto label_error;
		memcpy(&hdrs[i].hdr, p, sizeof(struct satoshi_block_header));
		p += sizeof(struct satoshi_block_header);
		
		int rc = satoshi_block_header_verify(&hdrs[i].hdr, NULL);
		if(rc) goto label_error;
		
		ssize_t vint_size = varint_size((varint_t *)p);
		if((p + vint_size) > p_end) goto label_error;
		
		hdrs[i].txn_count = varint_get((varint_t *)p);
		p += vint_size;
	}
	
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	assert(msg);
	
	msg->count = count;
	msg->hdrs = hdrs;
	return msg;
	
label_error:
	if(hdrs) free(hdrs);
	return NULL;
}
void bitcoin_message_block_headers_cleanup(struct bitcoin_message_block_headers * msg)
{
	if(NULL == msg) return;
	if(msg->hdrs) free(msg->hdrs);
	memset(msg, 0, sizeof(*msg));
	return;
}

ssize_t bitcoin_message_block_headers_serialize(const struct bitcoin_message_block_headers * msg, unsigned char ** p_data)
{
	assert(msg);
	if(msg->count <= 0) return 0;
	
	auto_buffer_t buf[1];
	auto_buffer_init(buf, 0);
	
	for(int i = 0; i < msg->count; ++i) 
	{
		struct bitcoin_message_block_header * hdr = &msg->hdrs[i];
		ssize_t vint_size = varint_calc_size(hdr->txn_count);
		assert(vint_size > 0 && vint_size <= 9);
		
		unsigned char vint_buf[9] = { 0 };
		varint_set((varint_t *)vint_buf, hdr->txn_count);
		
		auto_buffer_push(buf, hdr, sizeof(struct satoshi_block_header));
		auto_buffer_push(buf, vint_buf, vint_size);
	}
	ssize_t length = buf->length;
	
	if(NULL == *p_data) {
		auto_buffer_cleanup(buf);
		return length;
	}
	
	void * data = *p_data;
	if(NULL == data) {
		*p_data = buf->data; 	// pointer transfer
		buf->data = NULL;		// clear buf
		return length;
	}
	
	memcpy(data, buf->data, buf->length);
	auto_buffer_cleanup(buf);
	return length;
}
void bitcoin_message_block_headers_dump(const struct bitcoin_message_block_headers * msg)
{
#ifdef _DEBUG
	fprintf(stderr, "==== %s() ====\n", __FUNCTION__);
	fprintf(stderr, "num headers: %d\n", (int)msg->count);
	
	for(int i = 0; i < msg->count; ++i) {
		struct bitcoin_message_block_header * hdr = &msg->hdrs[i];
		
		fprintf(stderr, "[%.4d]: block_header_hex: \n", i);
		dump2(stderr, hdr, sizeof(struct satoshi_block_header));
		fprintf(stderr, "\n    txn_count: %ld\n", hdr->txn_count);
	}
#endif
	return;
}
