/*
 * hash256.cl
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


//~ typedef unsigned char uint256_t[32];
struct satoshi_block_header
{
	int32_t version;
	unsigned char prev_hash[32];
	unsigned char merkle_root[32];
	uint32_t timestamp;
	uint32_t bits;
	uint32_t nonce;
}__attribute__((packed));

struct nonce_status
{
	uint32_t status;
	uint32_t nonce;
	unsigned char hash[32];
}__attribute__((packed));


typedef struct sha256_ctx
{
	uint32_t s[8];
	unsigned char buf[64];
	size_t bytes;
}sha256_ctx_t;


#ifndef bswap_32
#define bswap_32(x) (uint32_t)(						\
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


static inline void WriteBE32(void * ptr, uint32_t value) {
	*(uint32_t *)(ptr) = bswap_32((value));
}

static inline void WriteBE64(void * ptr, uint64_t value) {
	*(uint64_t *)(ptr) = bswap_64((value));
}

static inline uint32_t ReadBE32(void * ptr) {
	uint32_t value = *(uint32_t *)ptr;
	return bswap_32(value);
}

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
static inline uint32_t Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
static inline uint32_t Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }
static inline uint32_t sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }
static inline uint32_t sigma1(uint32_t x) { return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10); }

static inline void Round(uint32_t a, uint32_t b, uint32_t c, 
	uint32_t *d, 
	uint32_t e, uint32_t f, uint32_t g, 
	uint32_t *h, 
	uint32_t k, uint32_t w)
{
    uint32_t t1 = *h + Sigma1(e) + Ch(e, f, g) + k + w;
    uint32_t t2 = Sigma0(a) + Maj(a, b, c);
    *d += t1;
    *h = t1 + t2;
}

/** Initialize SHA-256 state. */
static void Initialize(uint32_t* s)
{
    s[0] = 0x6a09e667ul;
    s[1] = 0xbb67ae85ul;
    s[2] = 0x3c6ef372ul;
    s[3] = 0xa54ff53aul;
    s[4] = 0x510e527ful;
    s[5] = 0x9b05688cul;
    s[6] = 0x1f83d9abul;
    s[7] = 0x5be0cd19ul;
}

/** Perform one SHA-256 transformation, processing a 64-byte chunk. */
static void Transform(uint32_t* s, const unsigned char* chunk)
{
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;


    Round(a, b, c, &d, e, f, g, &h, 0x428a2f98, w0 = ReadBE32(chunk + 0));
    Round(h, a, b, &c, d, e, f, &g, 0x71374491, w1 = ReadBE32(chunk + 4));
    Round(g, h, a, &b, c, d, e, &f, 0xb5c0fbcf, w2 = ReadBE32(chunk + 8));
    Round(f, g, h, &a, b, c, d, &e, 0xe9b5dba5, w3 = ReadBE32(chunk + 12));
    Round(e, f, g, &h, a, b, c, &d, 0x3956c25b, w4 = ReadBE32(chunk + 16));
    Round(d, e, f, &g, h, a, b, &c, 0x59f111f1, w5 = ReadBE32(chunk + 20));
    Round(c, d, e, &f, g, h, a, &b, 0x923f82a4, w6 = ReadBE32(chunk + 24));
    Round(b, c, d, &e, f, g, h, &a, 0xab1c5ed5, w7 = ReadBE32(chunk + 28));
    Round(a, b, c, &d, e, f, g, &h, 0xd807aa98, w8 = ReadBE32(chunk + 32));
    Round(h, a, b, &c, d, e, f, &g, 0x12835b01, w9 = ReadBE32(chunk + 36));
    Round(g, h, a, &b, c, d, e, &f, 0x243185be, w10 = ReadBE32(chunk + 40));
    Round(f, g, h, &a, b, c, d, &e, 0x550c7dc3, w11 = ReadBE32(chunk + 44));
    Round(e, f, g, &h, a, b, c, &d, 0x72be5d74, w12 = ReadBE32(chunk + 48));
    Round(d, e, f, &g, h, a, b, &c, 0x80deb1fe, w13 = ReadBE32(chunk + 52));
    Round(c, d, e, &f, g, h, a, &b, 0x9bdc06a7, w14 = ReadBE32(chunk + 56));
    Round(b, c, d, &e, f, g, h, &a, 0xc19bf174, w15 = ReadBE32(chunk + 60));

    Round(a, b, c, &d, e, f, g, &h, 0xe49b69c1, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, &c, d, e, f, &g, 0xefbe4786, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, &b, c, d, e, &f, 0x0fc19dc6, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, &a, b, c, d, &e, 0x240ca1cc, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, &h, a, b, c, &d, 0x2de92c6f, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, &g, h, a, b, &c, 0x4a7484aa, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, &f, g, h, a, &b, 0x5cb0a9dc, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, &e, f, g, h, &a, 0x76f988da, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, &d, e, f, g, &h, 0x983e5152, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, &c, d, e, f, &g, 0xa831c66d, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, &b, c, d, e, &f, 0xb00327c8, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, &a, b, c, d, &e, 0xbf597fc7, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, &h, a, b, c, &d, 0xc6e00bf3, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, &g, h, a, b, &c, 0xd5a79147, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, &f, g, h, a, &b, 0x06ca6351, w14 += sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, &e, f, g, h, &a, 0x14292967, w15 += sigma1(w13) + w8 + sigma0(w0));

    Round(a, b, c, &d, e, f, g, &h, 0x27b70a85, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, &c, d, e, f, &g, 0x2e1b2138, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, &b, c, d, e, &f, 0x4d2c6dfc, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, &a, b, c, d, &e, 0x53380d13, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, &h, a, b, c, &d, 0x650a7354, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, &g, h, a, b, &c, 0x766a0abb, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, &f, g, h, a, &b, 0x81c2c92e, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, &e, f, g, h, &a, 0x92722c85, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, &d, e, f, g, &h, 0xa2bfe8a1, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, &c, d, e, f, &g, 0xa81a664b, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, &b, c, d, e, &f, 0xc24b8b70, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, &a, b, c, d, &e, 0xc76c51a3, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, &h, a, b, c, &d, 0xd192e819, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, &g, h, a, b, &c, 0xd6990624, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, &f, g, h, a, &b, 0xf40e3585, w14 += sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, &e, f, g, h, &a, 0x106aa070, w15 += sigma1(w13) + w8 + sigma0(w0));

    Round(a, b, c, &d, e, f, g, &h, 0x19a4c116, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, &c, d, e, f, &g, 0x1e376c08, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, &b, c, d, e, &f, 0x2748774c, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, &a, b, c, d, &e, 0x34b0bcb5, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, &h, a, b, c, &d, 0x391c0cb3, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, &g, h, a, b, &c, 0x4ed8aa4a, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, &f, g, h, a, &b, 0x5b9cca4f, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, &e, f, g, h, &a, 0x682e6ff3, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, &d, e, f, g, &h, 0x748f82ee, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, &c, d, e, f, &g, 0x78a5636f, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, &b, c, d, e, &f, 0x84c87814, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, &a, b, c, d, &e, 0x8cc70208, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, &h, a, b, c, &d, 0x90befffa, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, &g, h, a, b, &c, 0xa4506ceb, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, &f, g, h, a, &b, 0xbef9a3f7, w14 + sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, &e, f, g, h, &a, 0xc67178f2, w15 + sigma1(w13) + w8 + sigma0(w0));

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}


static void * memset(void * s, int c, size_t n)
{
	for(size_t i = 0; i < n; ++i) ((unsigned char *)s)[i] = c;
	return s;
}

static void * memcpy(void * _dst, void * _src, size_t n)
{
	unsigned char * dst = _dst;
	unsigned char * src = _src;
	for(int i = 0; i < n; ++i) {
		dst[i] = src[i];
	}
	return dst;
}


void sha256_init(sha256_ctx_t * sha)
{
	memset(sha, 0, sizeof(sha256_ctx_t));
	Initialize(sha->s);
}
void sha256_update(sha256_ctx_t * sha, const unsigned char * data, size_t len)
{
	const unsigned char* end = data + len;
    size_t bufsize = sha->bytes % 64;
    if (bufsize && bufsize + len >= 64) {
        // Fill the buffer, and process it.
        memcpy(sha->buf + bufsize, data, 64 - bufsize);
        sha->bytes += 64 - bufsize;
        data += 64 - bufsize;
        Transform(sha->s, sha->buf);
        bufsize = 0;
    }
    while (end >= data + 64) {
        // Process full chunks directly from the source.
        Transform(sha->s, data);
        sha->bytes += 64;
        data += 64;
    }
    if (end > data) {
        // Fill the buffer with what remains.
        memcpy(sha->buf + bufsize, data, end - data);
        sha->bytes += end - data;
    }
}

void sha256_final(sha256_ctx_t * sha, unsigned char * hash)
{
	const unsigned char pad[64] = {0x80};
	unsigned char sizedesc[8];
	uint32_t * s = sha->s;
	WriteBE64(sizedesc, sha->bytes << 3);
	sha256_update(sha, pad, 1 + ((119 - (sha->bytes % 64)) % 64));
	sha256_update(sha, sizedesc, 8);
	WriteBE32(hash, s[0]);
	WriteBE32(hash + 4, s[1]);
	WriteBE32(hash + 8, s[2]);
	WriteBE32(hash + 12, s[3]);
	WriteBE32(hash + 16, s[4]);
	WriteBE32(hash + 20, s[5]);
	WriteBE32(hash + 24, s[6]);
	WriteBE32(hash + 28, s[7]);
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

static int compact_uint256_compare(uint32_t hashed, uint32_t target)
{
	int exp1 = hashed >> 24;
	int exp2 = target >> 24;
	if(exp1 != exp2) return (exp1 - exp2);
	
	int value1 = hashed & 0x00FFFFFF;
	int value2 = target & 0x00FFFFFF;
	return value1 - value2;
}

__kernel void hash256(const uint64_t num_jobs, 
	__global const struct satoshi_block_header * in_hdrs, 
	__global struct nonce_status * nonces, 
	volatile __global int32_t * flags)
{
	int idx = get_global_id(0);
	struct satoshi_block_header hdr = in_hdrs[idx];
	unsigned char hash[32];
	sha256_ctx_t sha[1];
	
#define nonce_max  1024UL

	for(uint64_t nonce = 0; nonce <= nonce_max; nonce++) 
	{
		if(flags[0] != 0) break;
		hdr.nonce = nonce;
		
		sha256_init(sha);
		sha256_update(sha, &hdr, sizeof(hdr));
		sha256_final(sha, hash);
		
		sha256_init(sha);
		sha256_update(sha, hash, 32);
		sha256_final(sha, hash);
		
		uint32_t bits = 0;
		bits = uint256_to_compact(hash);
		int cmp = compact_uint256_compare(bits, hdr.bits);
		
		if(cmp <= 0) {
			flags[0] = 1;
			
			nonces[idx].status = 1;
			nonces[idx].nonce = nonce;
			for(int i = 0; i < 32; ++i) nonces[idx].hash[i] = hash[i];
			
			printf("idx: %d, hdr.bits: 0x%.8x, timestamp: %u, nonce: %u\n",
				idx,
				hdr.bits, hdr.timestamp, nonce);
			break;
		}
	}
	return;
}

