/*
 * spv_node_message_handlers.c
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

static int on_message_unknown(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_version(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_verack(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_addr(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_inv(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_getdata(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_notefound(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_getblocks(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_getheaders(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_tx(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_block(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_headers(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_getaddr(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_mempool(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_checkorder(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_submitorder(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_reply(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_ping(struct spv_node_context * spv, const bitcoin_message_t * in_msg); 
static int on_message_pong(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_reject(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_filterload(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_filteradd(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_filterclear(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_merkle_block(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_alert(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_sendheaders(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_feefilter(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_sendcmpct(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_cmpctblock(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_getblocktxn(struct spv_node_context * spv, const bitcoin_message_t * in_msg);
static int on_message_blocktxn(struct spv_node_context * spv, const bitcoin_message_t * in_msg);

spv_node_message_callback_fn s_spv_node_callbacks[bitcoin_message_types_count] = 
{
	[bitcoin_message_type_unknown] = on_message_unknown,
	[bitcoin_message_type_version] = on_message_version,
	[bitcoin_message_type_verack] = on_message_verack,
	[bitcoin_message_type_addr] = on_message_addr,
	[bitcoin_message_type_inv] = on_message_inv,
	[bitcoin_message_type_getdata] = on_message_getdata,
	[bitcoin_message_type_notefound] = on_message_notefound,
	[bitcoin_message_type_getblocks] = on_message_getblocks,
	[bitcoin_message_type_getheaders] = on_message_getheaders,
	[bitcoin_message_type_tx] = on_message_tx,
	[bitcoin_message_type_block] = on_message_block,
	[bitcoin_message_type_headers] = on_message_headers,
	[bitcoin_message_type_getaddr] = on_message_getaddr,
	[bitcoin_message_type_mempool] = on_message_mempool,
	[bitcoin_message_type_checkorder] = on_message_checkorder,
	[bitcoin_message_type_submitorder] = on_message_submitorder,
	[bitcoin_message_type_reply] = on_message_reply,
	[bitcoin_message_type_ping] = on_message_ping, 
	[bitcoin_message_type_pong] = on_message_pong,
	[bitcoin_message_type_reject] = on_message_reject,
	[bitcoin_message_type_filterload] = on_message_filterload,
	[bitcoin_message_type_filteradd] = on_message_filteradd,
	[bitcoin_message_type_filterclear] = on_message_filterclear,
	[bitcoin_message_type_merkle_block] = on_message_merkle_block,
	[bitcoin_message_type_alert] = on_message_alert,
	[bitcoin_message_type_sendheaders] = on_message_sendheaders,
	[bitcoin_message_type_feefilter] = on_message_feefilter,
	[bitcoin_message_type_sendcmpct] = on_message_sendcmpct,
	[bitcoin_message_type_cmpctblock] = on_message_cmpctblock,
	[bitcoin_message_type_getblocktxn] = on_message_getblocktxn,
	[bitcoin_message_type_blocktxn] = on_message_blocktxn,
};


static int on_message_unknown(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return -1;
}

static int on_message_version(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_verack(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_addr(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_inv(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_getdata(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}
static int on_message_notefound(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_getblocks(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}
static int on_message_getheaders(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_tx(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_block(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}
static int on_message_headers(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_getaddr(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_mempool(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_checkorder(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_submitorder(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_reply(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_ping(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}
 
static int on_message_pong(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_reject(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_filterload(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_filteradd(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_filterclear(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_merkle_block(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_alert(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_sendheaders(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_feefilter(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_sendcmpct(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_cmpctblock(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_getblocktxn(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}

static int on_message_blocktxn(struct spv_node_context * spv, const bitcoin_message_t * in_msg)
{
	return 0;
}
