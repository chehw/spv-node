/*
 * hash256-asicboost.cl
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

typedef unsigned long uint64_t; 
typedef int int32_t;
typedef unsigned int uint32_t;

#ifndef bswap_32
#define bswap_32(x) (uint32_t)(							\
		    (((uint32_t)(x) & 0xff000000U) >> 24) 		\
		  | (((uint32_t)(x) & 0x00ff0000U) >>  8) 		\
		  | (((uint32_t)(x) & 0x0000ff00U) <<  8) 		\
		  | (((uint32_t)(x) & 0x000000ffU) << 24)		\
		)
#endif

#ifndef bswap_64
#define bswap_64(x) (uint64_t)(									\
		    (((uint64_t)(x) & 0xff00000000000000ul) >> 56)		\
		  | (((uint64_t)(x) & 0x00ff000000000000ul) >> 40)		\
		  | (((uint64_t)(x) & 0x0000ff0000000000ul) >> 24)		\
		  | (((uint64_t)(x) & 0x000000ff00000000ul) >> 8)			\
		  | (((uint64_t)(x) & 0x00000000ff000000ul) << 8)			\
		  | (((uint64_t)(x) & 0x0000000000ff0000ul) << 24)		\
		  | (((uint64_t)(x) & 0x000000000000ff00ul) << 40)		\
		  | (((uint64_t)(x) & 0x00000000000000fful) << 56)		\
		)
#endif

#define be32toh(x) bswap_32(x)


__constant uint32_t H[8] = {
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
__constant uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


static inline void uint256_u32swap(uint32_t hash[static 8], const uint32_t s[static 8])
{
	for(int i = 0; i < 8; ++i) hash[i] = bswap_32(s[i]);
}


// https://datatracker.ietf.org/doc/html/rfc4634#section-5.1
#define ROTR_32(x, n) ((x>>n) | x<<(32-n))

#define CH(x,y,z)	(z ^ (x & (y ^ z))) 		// ((x & y) ^ ((~x) & z))
#define MAJ(x,y,z)	((x & y) | (z & (x | y))) 	// ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x)	(ROTR_32(x,2) ^ ROTR_32(x,13) ^ ROTR_32(x,22))
#define BSIG1(x)	(ROTR_32(x,6) ^ ROTR_32(x,11) ^ ROTR_32(x,25))
#define SSIG0(x)	(ROTR_32(x,7) ^ ROTR_32(x,18) ^ (x>>3))
#define SSIG1(x)	(ROTR_32(x,17) ^ ROTR_32(x,19) ^ (x>>10))

static void sha256_chunk(const uint32_t chunk[static 16], uint32_t s[static 8])
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


static uint32_t uint256_to_compact(const unsigned char * hash)
{
	int zeros = 0;
	for(int i = 31; i >= 0; --i, ++zeros) {
		if(hash[i] != 0) break;
	}
	//~ assert(zeros <= 32);
	int exp = 32 - zeros;
	//~ printf("exp: %d\n", exp);
	
	unsigned char result[4];
	result[0] = hash[exp - 3];
	result[1] = hash[exp - 2];
	result[2] = hash[exp - 1];
	result[3] = exp;
	
	if(result[2] & 0x80) { 
		result[0] = result[1];
		result[1] = result[2];
		result[2] = 0;
		++result[3];
	}
	
	return *(uint32_t *)result;
}

static int compact_uint256_compare(const uint32_t hashed, const uint32_t target)
{
	int exp1 = hashed >> 24;
	int exp2 = target >> 24;
	if(exp1 != exp2) return (exp1 - exp2);
	
	int value1 = hashed & 0x00FFFFFF;
	int value2 = target & 0x00FFFFFF;
	return value1 - value2;
}

struct nonce_status
{
	uint32_t status;
	uint32_t nonce;
	unsigned char hash[32];
}__attribute__((packed));


typedef union part2_data{
	unsigned char data[64];
	uint32_t u32[16];
	struct {
		uint32_t merkle_root_suffix;
		uint32_t timestamp;
		uint32_t bits;
		uint32_t nonce;
		unsigned char paddings[48];
	}__attribute__((packed));
}part2_data_t;


#define NONCE_MAX (0xFFFFFFFF)
__kernel void hash256_asicboost(
	const uint32_t num_items, 
	__global const uint32_t s0[static restrict 8], 
	__global const unsigned char first_16bytes[static restrict 16], 
	__global struct nonce_status * restrict results, 
	__global uint32_t * item_index,
	__global volatile uint32_t * flags)
{
	if(*flags) return;
	
	int idx = get_global_id(0);
	
	uint32_t s[8];
	part2_data_t part2 = {
		.paddings = {
			[0] = 0x80,
			
			// bswap_64(80 * 8)
			[46] = 0x02,
			[47] = 0x80
		},
	};
	
	unsigned char hash_paddings[64] = {
		[32] = 0x80,
		
		// bswap_64(32 * 8)
		[62] = 0x01,
		[63] = 0x00,
	};

	for(int i = 0; i < 16; ++i) part2.data[i] = first_16bytes[i];
	
	uint32_t timestamp = part2.timestamp;
	unsigned char hash[32];
		
	for(uint64_t nonce = 0; nonce < NONCE_MAX  && (0 == *flags); ++nonce) {
		part2.timestamp = timestamp + idx;
		part2.nonce = nonce;
		
		for(int i = 0; i < 8; ++i) s[i] = s0[i];
		//~ printf("s0: %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n",
			//~ s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]);
		
		sha256_chunk(part2.u32, s);
		uint256_u32swap((uint32_t *)hash_paddings, s);
		
	
		for(int i = 0; i < 8; ++i) s[i] = H[i];
		sha256_chunk(hash_paddings, s);
		uint256_u32swap((uint32_t *)hash, s);
		
		uint32_t bits = uint256_to_compact((unsigned char *)hash);
		int cmp = compact_uint256_compare(bits, part2.bits);
		
		if(cmp <= 0) {
			*flags = 1;
			*item_index = idx;
			results[idx].status = 1;
			results[idx].nonce = nonce;
			
			for(int i = 0; i < 32; ++i) results[idx].hash[i] = hash[i];
			
			
			printf("idx: %d, bits: 0x%.8x, hdr.bits: 0x%.8x, timestamp: %u, nonce: %u\n"
				"s0: %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n",
				idx,
				bits,
				part2.bits, part2.timestamp, nonce,
				s0[0],s0[1],s0[2],s0[3],s0[4],s0[5],s0[6],s0[7]
				);
			break;
		}
	}
	

	return;
}
