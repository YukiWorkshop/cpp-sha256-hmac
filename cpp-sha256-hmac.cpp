/*
    This file is part of cpp-sha256-hmac.
    Copyright (C) 2020 ReimuNotMoe

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    Algorithm credits: https://github.com/jb55/sha256.c
                       https://github.com/aperezdc/hmac-sha256

*/

#include "cpp-sha256-hmac.hpp"

#define _SHA256_UNROLL
#define _SHA256_UNROLL2

#define U8V(v) ((uint8_t)(v) & 0xFFU)
#define U16V(v) ((uint16_t)(v) & 0xFFFFU)
#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFU)
#define U64V(v) ((uint64_t)(v) & 0xFFFFFFFFFFFFFFFFU)

#define ROTL32(v, n) \
  (U32V((uint32_t)(v) << (n)) | ((uint32_t)(v) >> (32 - (n))))

// tests fail if we don't have this cast...
#define ROTL64(v, n) \
  (U64V((uint64_t)(v) << (n)) | ((uint64_t)(v) >> (64 - (n))))

#define ROTR32(v, n) ROTL32(v, 32 - (n))
#define ROTR64(v, n) ROTL64(v, 64 - (n))


#define S0(x) (ROTR32(x, 2) ^ ROTR32(x,13) ^ ROTR32(x, 22))
#define S1(x) (ROTR32(x, 6) ^ ROTR32(x,11) ^ ROTR32(x, 25))
#define s0(x) (ROTR32(x, 7) ^ ROTR32(x,18) ^ (x >> 3))
#define s1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ (x >> 10))

#define blk0(i) (W[i] = data[i])
#define blk2(i) (W[i&15] += s1(W[(i-2)&15]) + W[(i-7)&15] + s0(W[(i-15)&15]))

#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) ((x&y)|(z&(x|y)))

#define a(i) T[(0-(i))&7]
#define b(i) T[(1-(i))&7]
#define c(i) T[(2-(i))&7]
#define d(i) T[(3-(i))&7]
#define e(i) T[(4-(i))&7]
#define f(i) T[(5-(i))&7]
#define g(i) T[(6-(i))&7]
#define h(i) T[(7-(i))&7]


#ifdef _SHA256_UNROLL2

#define R(a,b,c,d,e,f,g,h, i) h += S1(e) + Ch(e,f,g) + K[i+j] + (j?blk2(i):blk0(i));\
  d += h; h += S0(a) + Maj(a, b, c)

#define RX_8(i) \
  R(a,b,c,d,e,f,g,h, i); \
  R(h,a,b,c,d,e,f,g, (i+1)); \
  R(g,h,a,b,c,d,e,f, (i+2)); \
  R(f,g,h,a,b,c,d,e, (i+3)); \
  R(e,f,g,h,a,b,c,d, (i+4)); \
  R(d,e,f,g,h,a,b,c, (i+5)); \
  R(c,d,e,f,g,h,a,b, (i+6)); \
  R(b,c,d,e,f,g,h,a, (i+7))

#else

#define R(i) h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[i+j] + (j?blk2(i):blk0(i));\
  d(i) += h(i); h(i) += S0(a(i)) + Maj(a(i), b(i), c(i))

#ifdef _SHA256_UNROLL

#define RX_8(i) R(i+0); R(i+1); R(i+2); R(i+3); R(i+4); R(i+5); R(i+6); R(i+7);

#endif

#endif

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(uint32_t *state, const uint32_t *data) {
	uint32_t W[16];
	unsigned j;
#ifdef _SHA256_UNROLL2
	uint32_t a,b,c,d,e,f,g,h;
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];
#else
	uint32_t T[8];
	for (j = 0; j < 8; j++)
		T[j] = state[j];
#endif

	for (j = 0; j < 64; j += 16)
	{
#if defined(_SHA256_UNROLL) || defined(_SHA256_UNROLL2)
		RX_8(0); RX_8(8);
#else
		unsigned i;
		for (i = 0; i < 16; i++) { R(i); }
#endif
	}

#ifdef _SHA256_UNROLL2
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
#else
	for (j = 0; j < 8; j++)
		state[j] += T[j];
#endif

	/* Wipe variables */
	/* memset(W, 0, sizeof(W)); */
	/* memset(T, 0, sizeof(T)); */
}

#undef S0
#undef S1
#undef s0
#undef s1

using namespace YukiWorkshop::Crypto;

void SHA256::sha256_write_byte_block() {
	uint32_t data32[16];
	unsigned i;
	for (i = 0; i < 16; i++)
		data32[i] =
			((uint32_t)(buffer[i * 4    ]) << 24) +
			((uint32_t)(buffer[i * 4 + 1]) << 16) +
			((uint32_t)(buffer[i * 4 + 2]) <<  8) +
			((uint32_t)(buffer[i * 4 + 3]));
	sha256_transform(state, data32);
}

void SHA256::reset() noexcept {
	state[0] = 0x6a09e667;
	state[1] = 0xbb67ae85;
	state[2] = 0x3c6ef372;
	state[3] = 0xa54ff53a;
	state[4] = 0x510e527f;
	state[5] = 0x9b05688c;
	state[6] = 0x1f83d9ab;
	state[7] = 0x5be0cd19;
	count = 0;
}

void SHA256::__update(SHA256 *p, const void *__data, size_t __len) noexcept {
	auto *data = (uint8_t *)__data;

	uint32_t curBufferPos = (uint32_t)p->count & 0x3F;
	while (__len > 0)
	{
		p->buffer[curBufferPos++] = *data++;
		p->count++;
		__len--;
		if (curBufferPos == 64)
		{
			curBufferPos = 0;
			p->sha256_write_byte_block();
		}
	}
}


void SHA256::__finalize(SHA256 *p, void *__digest) noexcept {
	auto *digest = (uint8_t *)__digest;
	uint64_t lenInBits = (p->count << 3);
	uint32_t curBufferPos = (uint32_t)p->count & 0x3F;
	unsigned i;
	p->buffer[curBufferPos++] = 0x80;
	while (curBufferPos != (64 - 8)) {
		curBufferPos &= 0x3F;
		if (curBufferPos == 0)
			p->sha256_write_byte_block();
		p->buffer[curBufferPos++] = 0;
	}
	for (i = 0; i < 8; i++) {
		p->buffer[curBufferPos++] = (unsigned char)(lenInBits >> 56);
		lenInBits <<= 8;
	}
	p->sha256_write_byte_block();

	for (i = 0; i < 8; i++) {
		*digest++ = (unsigned char)(p->state[i] >> 24);
		*digest++ = (unsigned char)(p->state[i] >> 16);
		*digest++ = (unsigned char)(p->state[i] >> 8);
		*digest++ = (unsigned char)(p->state[i]);
	}

	p->reset();
}

void SHA256::update(const void *__data, size_t __len) noexcept {
	__update(this, __data, __len);
}

void SHA256::finalize(void *__digest) noexcept {
	__finalize(this, __digest);
}

/*
 * HMAC(H, K) == H(K ^ opad, H(K ^ ipad, text))
 *
 *    H: Hash function (sha256)
 *    K: Secret key
 *    B: Block byte length
 *    L: Byte length of hash function output
 *
 * https://tools.ietf.org/html/rfc2104
 */

#define SHA256_DIGEST_SIZE 32
#define B 64
#define L (SHA256_DIGEST_SIZE)
#define K (SHA256_DIGEST_SIZE * 2)

#define I_PAD 0x36
#define O_PAD 0x5C

void SHA256_HMAC::set_key(const void *__data, size_t __len) {

	/*
	 * If the key length is bigger than the buffer size B, apply the hash
	 * function to it first and use the result instead.
	 */

	if (__len > B) {
		__update(this, __data, __len);
		key_buf.resize(SHA256_DIGEST_SIZE);
		__finalize(this, key_buf.data());
	} else {
		key_buf.insert(key_buf.begin(), (uint8_t *)__data, ((uint8_t *)__data)+__len);
	}

	/*
	 * (1) append zeros to the end of K to create a B byte string
	 *     (e.g., if K is of length 20 bytes and B=64, then K will be
	 *     appended with 44 zero bytes 0x00)
	 * (2) XOR (bitwise exclusive-OR) the B byte string computed in step
	 *     (1) with ipad
	 */
	for (size_t i = 0; i < key_buf.size(); i++) kx[i] = I_PAD ^ key_buf[i];
	for (size_t i = key_buf.size(); i < B; i++) kx[i] = I_PAD ^ 0;

	/*
	 * (3) append the stream of data 'text' to the B byte string resulting
	 *     from step (2)
	 * (4) apply H to the stream generated in step (3)
	 */
	__update(this, kx, B);
}

void SHA256_HMAC::__hmac_finalize(SHA256_HMAC *p, void *__digest) noexcept {
	__finalize(p, __digest);
	/*
	 * (5) XOR (bitwise exclusive-OR) the B byte string computed in
	 *     step (1) with opad
	 *
	 * NOTE: The "kx" variable is reused.
	 */
	for (size_t i = 0; i < p->key_buf.size(); i++) p->kx[i] = O_PAD ^ p->key_buf[i];
	for (size_t i = p->key_buf.size(); i < B; i++) p->kx[i] = O_PAD ^ 0;

	/*
	 * (6) append the H result from step (4) to the B byte string
	 *     resulting from step (5)
	 * (7) apply H to the stream generated in step (6) and output
	 *     the result
	 */

	__update(p, p->kx, B);
	__update(p, __digest, SHA256_DIGEST_SIZE);
	__finalize(p, __digest);
}
