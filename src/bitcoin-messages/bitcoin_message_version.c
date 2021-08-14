/*
 * bitcoin_message_version.c
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
#include "utils.h"

static const unsigned char s_ipv4_mapped_prefix[12] = { [10] = 0xff, [11] = 0xff, };
static const char * ipaddr_to_string(const char ip[static 16], char * addr_buf, size_t buf_size)
{
	if(0 == memcmp(ip, s_ipv4_mapped_prefix, 12)) {
		return inet_ntop(AF_INET, ip + 12, addr_buf, buf_size);
	}
	return inet_ntop(AF_INET6, ip, addr_buf, buf_size);
}

void bitcoin_message_version_dump(const struct bitcoin_message_version * msg)
{
#ifdef _DEBUG
	printf("==== %s() ====\n", __FUNCTION__);
	printf("version: %d(0x%.8x)\n", msg->version, msg->version);
	printf("service: %"PRIx64"\n", msg->services);
	printf("timestamp: %" PRIi64"\n", msg->timestamp);
	char addr_buf[INET6_ADDRSTRLEN + 1] = "";
	
	const char * addr = ipaddr_to_string(msg->addr_recv.ip, addr_buf, sizeof(addr_buf));
	if(NULL == addr) perror("msg->addr_recv.ip");
	printf("addr_recv: %s:%hu\n", addr, msg->addr_recv.port);
	
	addr = ipaddr_to_string(msg->addr_recv.ip, addr_buf, sizeof(addr_buf));
	printf("addr_from: %s:%hu\n", addr, msg->addr_from.port);
	printf("nonce: %ld(%"PRIx64")\n", msg->nonce, msg->nonce);
	
	int cb = varstr_length(msg->user_agent);
	printf("user_agent(cb=%d): %*s\n", cb, cb, varstr_getdata_ptr(msg->user_agent));
	printf("start_height: %d\n", msg->start_height);
	printf("relay: %d\n", msg->relay);
#endif
	return;
}

ssize_t bitcoin_message_version_serialize(const struct bitcoin_message_version *msg, unsigned char ** p_data)
{
	ssize_t size = 0;
	size = sizeof(int32_t) + sizeof(uint64_t) + sizeof(int64_t) + sizeof(msg->addr_recv);
	if(msg->version >= 106) {
		size += sizeof(msg->addr_from) + sizeof(msg->nonce);
		assert(msg->user_agent);
		size += varstr_size(msg->user_agent);
		size += sizeof(msg->start_height);
	}
	if(msg->version >= 70001) ++size;	// sizeof(msg->relay)
	
	if(NULL == p_data) return size;
	unsigned char * payload = *p_data;
	if(NULL == payload) {
		payload = malloc(size);
		assert(payload);
		*p_data = payload;
	}
	
	unsigned char * p = payload;
	unsigned char * p_end = p + size;
	
#define append_data(dst, src, size)  do { memcpy(dst, src, size); dst += size; } while(0)
	append_data(p, &msg->version, sizeof(msg->version));
	append_data(p, &msg->services, sizeof(msg->services));
	append_data(p, &msg->timestamp, sizeof(msg->timestamp));
	append_data(p, &msg->addr_recv, sizeof(msg->addr_recv));
	
	if(msg->version >= 106) {
		append_data(p, &msg->addr_from, sizeof(msg->addr_from));
		append_data(p, &msg->nonce, sizeof(msg->nonce));
		
		ssize_t cb_user_agent = varstr_size(msg->user_agent);
		append_data(p, msg->user_agent, cb_user_agent);
		append_data(p, &msg->start_height, sizeof(msg->start_height));
		
		if(msg->version >= 70001) {
			append_data(p, &msg->relay, sizeof(msg->relay));
		}
	}
#undef append_data

	assert(p == p_end);
	return size;
}

void bitcoin_message_version_cleanup(struct bitcoin_message_version * msg)
{
	if(msg->user_agent) varstr_free(msg->user_agent);
	memset(msg, 0, sizeof(*msg));
	return;
}

struct bitcoin_message_version * bitcoin_message_version_parse(struct bitcoin_message_version * _msg, const unsigned char * payload, size_t length)
{
	assert(payload && length > 0);
	struct bitcoin_message_version * msg = _msg;
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	assert(msg);
	
	const unsigned char * p = payload;
	const unsigned char * p_end = p + length;
	
	if((p + sizeof(int32_t) + sizeof(uint64_t) + sizeof(int64_t) + sizeof(msg->addr_recv)) > p_end) goto label_error;

#define load_data(dst, src, size) do { memcpy(dst, src, size); src += size; } while(0)
	load_data(&msg->version, p, sizeof(int32_t));
	load_data(&msg->services, p, sizeof(int64_t));
	load_data(&msg->timestamp, p, sizeof(int64_t));
	load_data(&msg->addr_recv, p, sizeof(msg->addr_recv));
	if(msg->version < 106) return msg;
	
	if((p + sizeof(msg->addr_from) + sizeof(uint64_t)) >= p_end) goto label_error;
	load_data(&msg->addr_from, p, sizeof(msg->addr_from));
	load_data(&msg->nonce, p, sizeof(uint64_t));
	
	size_t cb_user_agent = varstr_size((varstr_t *)p);
	if(cb_user_agent < 1 || (p + cb_user_agent + sizeof(int32_t) > p_end)) goto label_error;
	msg->user_agent = malloc(cb_user_agent);
	assert(msg->user_agent);
	
	load_data(msg->user_agent, p, cb_user_agent);
	load_data(&msg->start_height, p, sizeof(int32_t));
	
	if(msg->version >= 70001) {
		if(p >= p_end) goto label_error;
		msg->relay = *p++;
	}
	assert(p == p_end);
	return msg;
#undef load_data

label_error:
	bitcoin_message_version_cleanup(msg);
	if(NULL == _msg) free(msg);
	return NULL;
}
