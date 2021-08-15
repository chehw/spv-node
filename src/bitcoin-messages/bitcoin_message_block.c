/*
 * bitcoin_message_block.c
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

bitcoin_message_block_t * bitcoin_message_block_parse(bitcoin_message_block_t * msg, 
	const unsigned char * payload, 
	size_t length)
{
	if(length < sizeof(struct satoshi_block_header)) return NULL;
	
	if(NULL == msg) msg = calloc(1, sizeof(*msg));
	assert(msg);
	
	ssize_t cb_msg = satoshi_block_parse(msg, length, payload);
	if(cb_msg != length) {
		free(msg);
		msg = NULL;
	}
	return msg;
}

void bitcoin_message_block_cleanup(bitcoin_message_block_t * msg)
{
	satoshi_block_cleanup(msg);
}

ssize_t bitcoin_message_block_serialize(const bitcoin_message_block_t * msg, unsigned char ** p_data)
{
	return satoshi_block_serialize(msg, p_data);
}

void bitcoin_message_block_dump(const bitcoin_message_block_t * msg)
{
	satoshi_block_dump(msg);
}
