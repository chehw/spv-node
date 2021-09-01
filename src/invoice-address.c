/*
 * invoice-address.c
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

#include <stdint.h>

#include "crypto.h"
#include "base58.h"

#include "utils.h"

// BIP 0173: https://en.bitcoin.it/wiki/BIP_0173

enum bech32_encode_type
{
	bech32_encode_type_default = 0,
	bech32_encode_type_bech32m = 1
};

static const char s_bech32_digits[32] = 
	"qpzry9x8"
	"gf2tvdw0"
	"s3jn54kh"
	"ce6mua7l";

static const uint32_t s_bech32_final_constants[2] = {
		[bech32_encode_type_default] = 1, 
		[bech32_encode_type_bech32m] = 0x2bc830a3,
	};

/**
 * Example: 
 *  https://en.bitcoin.it/wiki/Bech32
 *  ripemd160: 751e76e8199196d454941c45d1b3a323f1433bd6
**/

static inline void base32_to_base256_chunk(const uint8_t b32[static restrict 8], uint8_t b256[static restrict 5])
{
	b256[0] = (b32[0]<<3) | (b32[1]>>2);
	b256[1] = ((b32[1]&0x03)<<6) | (b32[2]<<1) | (b32[3]>>4);
	b256[2] = ((b32[3]&0x0F)<<4) | (b32[4]>>1);
	b256[3] = ((b32[4]&0x01)<<7) | (b32[5]<<2) | (b32[6]>>3);
	b256[4] = ((b32[6]&0x07)<<5) | (b32[7] & 0x1F);
	return;
}
static inline size_t base32_to_base256_padding(const uint8_t * restrict b32, size_t length, uint8_t * restrict b256)
{
	assert(length > 0 && length < 8);
	if(length == 0 || length > 7) return 0;
	
	uint8_t * u = b256;
	if(length > 0) {
		*u    = (b32[0]<<3);
	}
	if(length > 1) {
		*u++ |= (b32[1]>>2);
		*u    = (b32[1]<<6);
	}
	if(length > 2) {
		*u   |= (b32[2]<<1);
	}
	if(length > 3) {
		*u++ |= (b32[3]>>4);
		*u    = (b32[3]<<4);
	}
	if(length > 4) {
		*u++ |= (b32[4]>>1);
		*u    = (b32[4]<<7);
	}
	if(length > 5) {
		*u  |= (b32[5]<<2);
	}
	if(length > 6) {
		*u  |= (b32[6]>>3);   
		
		// discard padding zeros 
		assert((b32[6] & 0x07) == 0);
	}
	
	return (u - b256) + 1;
}



//~ 01110101 00011110 01110110 11101000 00011001 
//~ 10010001 10010110 11010100 01010100 10010100
//~ 00011100 01000101 11010001 10110011 10100011
//~ 00100011 11110001 01000011 00111011 11010110

//~ 01110 10100 01111 00111 01101 11010 00000 11001 
//~ 10010 00110 01011 01101 01000 10101 00100 10100 
//~ 00011 10001 00010 11101 00011 01100 11101 00011 
//~ 00100 01111 11000 10100 00110 01110 11110 10110
static inline void base256_to_base32_chunk(const uint8_t b256[static restrict 5], uint8_t b32[static restrict 8])
{
	/*
	 * 12345678 | 12345678 | 12345678 | 12345678 | 12345678
	 * 12345 | 67812 | 34567 | 81234 | 56781 | 23456 | 78123 | 45678
	*/
	b32[0] = (b256[0] >> 3) & 0x1F;
	b32[1] = ((b256[0] & 0x07)<<2) | ((b256[1]>>6) & 0x03);
	b32[2] = ((b256[1] & 0x3F)>>1);
	b32[3] = ((b256[1] & 0x01)<<4) | ((b256[2]>>4) & 0x0F);
	b32[4] = ((b256[2] & 0x0F)<<1) | ((b256[3]>>7) & 0x01);
	b32[5] = ((b256[3] & 0x7F)>>2);
	b32[6] = ((b256[3] & 0x03)<<3) | ((b256[4]>>5) & 0x07);
	b32[7] = (b256[4] & 0x1F);
	return;
}
static inline size_t base256_to_base32_padding(const uint8_t * restrict b256, size_t length, uint8_t * restrict b32)
{
	assert(length < 5);
	
	uint8_t * b = b32;
	if(length > 0) {
		*b++  = (b256[0] >> 3) & 0x1F;
		*b    = ((b256[0] & 0x07)<<2);
	}
	if(length > 1) {
		*b++ |= ((b256[1]>>6) & 0x03);
		*b++  = ((b256[1] & 0x3F)>>1);
		*b    = ((b256[1] & 0x01)<<4);
	}
	if(length > 2) {
		*b++ |= ((b256[2]>>4) & 0x0F);
		*b    = ((b256[2] & 0x0F)<<1);
	}
	if(length > 3) {
		*b++ |= ((b256[3]>>7) & 0x01);
		*b++  = ((b256[3] & 0x7F)>>2);
		*b    = ((b256[3] & 0x03)<<3);
	}
	return (b - b32) + 1;
}

static inline uint32_t bech32_polymod(uint32_t checksum)
{
	uint8_t b = checksum >> 25;
	checksum = ((checksum & 0x01FFFFFF)<<5) 
			^ (-((b>>0) & 1) & 0x3b6a57b2) 
			^ (-((b>>1) & 1) & 0x26508e6d) 
			^ (-((b>>2) & 1) & 0x1ea119fa) 
			^ (-((b>>3) & 1) & 0x3d4233dd) 
			^ (-((b>>4) & 1) & 0x2a1462b3);
	return checksum;
}

ssize_t bech32_encode(uint8_t version, 
	const char * hrp, // "bc" for mainnet, or "tb" for testnet
	const unsigned char * data, size_t length, // pubkey hash
	char * bech32)
{
	assert(length >= 2 && length <= 40);
	assert(version <= 16);
	
	uint8_t b32[65] = { version };
	uint32_t checksum = 1;
	
	char * output = bech32;
	const char * p = hrp;
	
	// encode human-readable part
	int c = 0;
	while((c = *p++)) {
		assert(c > 32 && c < 127);
		if(c < 33 || c > 126) return -1;
		if(c >= 'A' && c <= 'Z') return -1;
		
		checksum = bech32_polymod(checksum) ^ (c >> 5);
	}
	if(((p - hrp) + 7 + length) > 90) return -1;
	
	checksum = bech32_polymod(checksum);
	while((c = *hrp++)) {
		checksum = bech32_polymod(checksum) ^ (c & 0x1f);
		*output++ = c;
	}

	// add seperator
	*output++ = '1';
	
	// encode data part
	const unsigned char * in_chunk = data;
	const unsigned char * p_end = in_chunk + length;
	
	unsigned char * b32_data = &b32[1];
	size_t cb_b32 = 0;
	
	for(size_t i = 0; i < length / 5; ++i) {
		base256_to_base32_chunk(in_chunk, b32_data);
		in_chunk += 5;
		b32_data += 8;
	}
	
	if(in_chunk < p_end) {
		size_t cb = base256_to_base32_padding(in_chunk, p_end - in_chunk, b32_data);
		assert(cb > 1);
		b32_data += cb;
	}
	
	cb_b32 = b32_data - b32;

	for(int i = 0; i < cb_b32; ++i) {
		assert((b32[i] >> 5) == 0);
		uint8_t c = b32[i];
		checksum = bech32_polymod(checksum) ^ c;
		*output++ = s_bech32_digits[b32[i]];
	}

	for(int i = 0; i < 6; ++i) {
		checksum = bech32_polymod(checksum);
	}
	// write checksum
	uint32_t final_const = s_bech32_final_constants[(version > 0)];
	checksum ^= final_const;
	
	for(int i = 0; i < 6; ++i) {
		int chk = (checksum >> ((5 - i) * 5)) & 0x1F;
		*output++ = s_bech32_digits[chk];
	}
	*output = '\0';
	return (output - bech32);
}

size_t pubkey_to_bech32(const unsigned char pubkey[], size_t cb_pubkey, char bech[static 90])
{
	unsigned char hash[32];
	//hash160(pubkey, cb_pubkey, hash);
	
	sha256_hash(pubkey, cb_pubkey, hash);
//	dump_line("sha256: ", hash, 32);
	
	ripemd160_hash(hash, 32, hash);
//	dump_line("ripemd: ", hash, 20);
	
	ssize_t cb_bech = bech32_encode(0, "bc", hash, 20, bech);
	assert(cb_bech > 0 && cb_bech < 90);
	
	return 0;
}

#if defined(_TEST_INVOICE_ADDRESS) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
#define VERIFY_BECH32_ADDR "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	
	char * pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
	unsigned char pubkey[33] = {0};
	void * p_pubkey = pubkey;
	
	ssize_t cb_pubkey = hex2bin(pubkey_hex, -1, &p_pubkey);
	assert(cb_pubkey);
	
	printf("(Reference: %s)\n", "https://en.bitcoin.it/wiki/Bech32");
	dump_line("pubkey: ", pubkey, cb_pubkey);
	
	char bech[100] = "";
	pubkey_to_bech32(pubkey, cb_pubkey, bech);
	
	printf("bech32: %s\n", bech);
	printf("verify: %s\n", VERIFY_BECH32_ADDR); 


	assert(0 == strcmp(bech, VERIFY_BECH32_ADDR));
	
	
	/**
	 * test 1. test chunk_encode
	**/
	// 75 1e 76 e8 19 9196d454941c45d1b3a323f1433bd6
	// test padding
	// 0e 14 0f 07 0d 1a 00 19 12060b0d081504140311021d030c1d03040f1814060e1e16
	
	if(1) {
		printf("\n========== TEST chunk encode/decode =====================\n");
		uint8_t hash[20];
		uint8_t b32[32] = { 0 };
		
		hash160(pubkey, cb_pubkey, hash);
		dump_line("hash: ", hash, 20);
		
		for(int i = 0; i < 4; ++i){
			base256_to_base32_chunk(&hash[i*5], &b32[i*8]);
		}
		dump_line("b32 : ", b32, 32);
		
		uint8_t b256[20] = { 0 };
		for(int i = 0; i < 4; ++i) {
			base32_to_base256_chunk(&b32[i * 8], &b256[i * 5]);
		}
		dump_line("b256: ", b256, 20);
	}
	
	
	/**
	 * test 2. test paddings encode/decode
	**/
	if(1) {
		printf("\n========== TEST paddings encode/decode =====================\n");
		
		//~ 01110101 00011110 01110110 11101000 00011001 
		//~ 01110 10100 01111 00111 01101 11010 00000 11001 
		uint8_t b256[] = { 0x75, 0x1e, 0x76, 0xe8, 0x19 };
		uint8_t b32[8] = { 0 };
		ssize_t cb = base256_to_base32_padding(b256, 4, b32);
		
		printf("padding_encode::cb=%d\n", (int)cb);
		for(int i = 0; i < cb; ++i) {
			// print bits
			uint8_t c = b32[i];
			printf("%d%d%d%d%d(%.2x) ", 
				((c & 0x10) != 0), 
				((c & 0x08) != 0), 
				((c & 0x04) != 0), 
				((c & 0x02) != 0), 
				((c & 0x01) != 0),
				c
				); 
			
		}
		printf("\n");
		
		uint8_t u[5] = { 0 };
		cb = base32_to_base256_padding(b32, cb, u);
		printf("padding_decode::cb = %d\n", (int)cb);
		for(int i = 0; i < cb; ++i) printf("%.2x ", u[i]);
		printf("\n");
	}
	
	return 0;
}
#endif

