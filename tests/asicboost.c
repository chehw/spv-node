/*
 * asicboost.c
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
#include <endian.h>
#include <byteswap.h>

#include "sha.h"
#include "utils.h"

static const uint32_t H[8] = {
	[0] = 0x6a09e667,
	[1] = 0xbb67ae85,
	[2] = 0x3c6ef372,
	[3] = 0xa54ff53a,
	[4] = 0x510e527f,
	[5] = 0x9b05688c,
	[6] = 0x1f83d9ab,
	[7] = 0x5be0cd19,
};

// sequence constant
static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


// https://datatracker.ietf.org/doc/html/rfc4634#section-5.1
#define ROTR_32(x, n) ((x>>n) | x<<(32-n))

#define CH(x,y,z)	(z ^ (x & (y ^ z))) 		// ((x & y) ^ ((~x) & z))
#define MAJ(x,y,z)	((x & y) | (z & (x | y))) 	// ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x)	(ROTR_32(x,2) ^ ROTR_32(x,13) ^ ROTR_32(x,22))
#define BSIG1(x)	(ROTR_32(x,6) ^ ROTR_32(x,11) ^ ROTR_32(x,25))
#define SSIG0(x)	(ROTR_32(x,7) ^ ROTR_32(x,18) ^ (x>>3))
#define SSIG1(x)	(ROTR_32(x,17) ^ ROTR_32(x,19) ^ (x>>10))

void sha256_chunk(const uint32_t chunk[static 16], uint32_t s[static 8])
{
	uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
	uint32_t w[64];
	
	// copy the first 16 bytes to the message schedule array w[]
	for(int t = 0; t < 16; ++t) w[t] = be32toh(chunk[t]);

	// Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
	for(int t = 16; t < 64; ++t) {
		w[t] = SSIG1(w[t - 2]) + w[t - 7] + SSIG0(w[t-15]) + w[t - 16];
	}
	
	// Perform the main hash computation:
	for(int t = 0; t < 64; ++t) {
		uint32_t tmp1 = h + BSIG1(e) + CH(e,f,g) + K[t] + w[t];
		uint32_t tmp2 = BSIG0(a) + MAJ(a,b,c);
		
		h = g;
		g = f;
		f = e;
		e = d + tmp1;
		d = c;
		c = b;
		b = a;
		a = tmp1 + tmp2;
	}
	
	s[0] += a;
	s[1] += b;
	s[2] += c;
	s[3] += d;
	s[4] += e;
	s[5] += f;
	s[6] += g;
	s[7] += h;
	
	return;
}

void sha256_chunk_init(uint32_t * s, const uint32_t * s0)
{
	if(NULL == s0) s0 = H;
	memcpy(s, s0, sizeof(uint32_t) * 8);
	return;
}

static inline void htobe32_array(uint32_t h[], int length, const uint32_t s[])
{
	for(int i = 0; i < length; ++i) h[i] = htobe32(s[i]);
}

#if defined(_TEST_ASIC_BOOST) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	unsigned char msg[128] = { 
		[1] = 1,
		[2] = 2,
		[10] = 10,
		[32] = 0x80,
		
		[80] = 0x80,
	};
	
	unsigned char hash_padding[64] = { 
		[32] = 0x80,
	};
	
	uint64_t bits = 80 * 8;
	*(uint64_t *)(msg + 120) = htobe64(bits);
	
	bits = 32 * 8;
	*(uint64_t *)(hash_padding + 56) = htobe64(bits);
	
	
	uint32_t s0[8];
	sha256_chunk_init(s0, NULL);
	sha256_chunk((uint32_t *)msg, s0);
	
	unsigned char hash[32];
	unsigned char asicboost_hash[32];
	for(int nonce = 0; nonce < 100; ++nonce) {
		printf("nonce: %u\n", nonce);
		
		uint32_t s[8];
		sha256_chunk_init(s, s0);
		*(uint32_t *)(msg + 76) = nonce;
		
		sha256_chunk((uint32_t *)(msg + 64), s);
		htobe32_array((uint32_t *)hash_padding, 8, s);
		dump_line("sha: ", hash_padding, 32);
		
		memcpy(s, H, sizeof(s));
		sha256_chunk((uint32_t *)hash_padding, s);
		
		htobe32_array((uint32_t *)asicboost_hash, 8, s);
		printf("asicboost hash: "); dump(asicboost_hash, 32); printf("\n");
		
		
		sha256_hash(msg, 80, hash);
		printf("gnutls sha   : "); dump(hash, 32); printf("\n");
	
		sha256_hash(hash_padding, 32, hash);
		printf("gnutls hash   : "); dump(hash, 32); printf("\n");
		
		assert(0 == memcmp(asicboost_hash, hash, 32));

	} 
	return 0;
}
#endif

