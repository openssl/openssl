/* ====================================================================
 * Copyright (c) 2011-2013 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/* This implementation of poly1305 is by Andrew Moon
 * (https://github.com/floodyberry/poly1305-donna) and released as public
 * domain. */

#include <string.h>
#include <stdint.h>
#include <openssl/opensslconf.h>

#if !defined(OPENSSL_NO_POLY1305)

#include <openssl/poly1305.h>

#if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
/* We can assume little-endian. */
static uint32_t U8TO32_LE(const unsigned char *m)
	{
	uint32_t r;
	memcpy(&r, m, sizeof(r));
	return r;
	}

static void U32TO8_LE(unsigned char *m, uint32_t v)
	{
	memcpy(m, &v, sizeof(v));
	}
#else
static uint32_t U8TO32_LE(const unsigned char *m)
	{
	return (uint32_t)m[0] |
	       (uint32_t)m[1] << 8 |
	       (uint32_t)m[2] << 16 |
	       (uint32_t)m[3] << 24;
	}

static void U32TO8_LE(unsigned char *m, uint32_t v)
	{
	m[0] = v;
	m[1] = v >> 8;
	m[2] = v >> 16;
	m[3] = v >> 24;
	}
#endif

static uint64_t
mul32x32_64(uint32_t a, uint32_t b)
	{
	return (uint64_t)a * b;
	}


struct poly1305_state_st
	{
	uint32_t r0,r1,r2,r3,r4;
	uint32_t s1,s2,s3,s4;
	uint32_t h0,h1,h2,h3,h4;
	unsigned char buf[16];
	unsigned int buf_used;
	unsigned char key[16];
	};

/* poly1305_blocks updates |state| given some amount of input data. This
 * function may only be called with a |len| that is not a multiple of 16 at the
 * end of the data. Otherwise the input must be buffered into 16 byte blocks.
 * */
static void poly1305_update(struct poly1305_state_st *state,
			    const unsigned char *in, size_t len)
	{
	uint32_t t0,t1,t2,t3;
	uint64_t t[5];
	uint32_t b;
	uint64_t c;
	size_t j;
	unsigned char mp[16];

	if (len < 16)
		goto poly1305_donna_atmost15bytes;

poly1305_donna_16bytes:
	t0 = U8TO32_LE(in);
	t1 = U8TO32_LE(in+4);
	t2 = U8TO32_LE(in+8);
	t3 = U8TO32_LE(in+12);

	in += 16;
	len -= 16;

	state->h0 += t0 & 0x3ffffff;
	state->h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
	state->h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
	state->h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
	state->h4 += (t3 >> 8) | (1 << 24);

poly1305_donna_mul:
	t[0] = mul32x32_64(state->h0,state->r0) +
	       mul32x32_64(state->h1,state->s4) +
	       mul32x32_64(state->h2,state->s3) +
	       mul32x32_64(state->h3,state->s2) +
	       mul32x32_64(state->h4,state->s1);
	t[1] = mul32x32_64(state->h0,state->r1) +
	       mul32x32_64(state->h1,state->r0) +
	       mul32x32_64(state->h2,state->s4) +
	       mul32x32_64(state->h3,state->s3) +
	       mul32x32_64(state->h4,state->s2);
	t[2] = mul32x32_64(state->h0,state->r2) +
	       mul32x32_64(state->h1,state->r1) +
	       mul32x32_64(state->h2,state->r0) +
	       mul32x32_64(state->h3,state->s4) +
	       mul32x32_64(state->h4,state->s3);
	t[3] = mul32x32_64(state->h0,state->r3) +
	       mul32x32_64(state->h1,state->r2) +
	       mul32x32_64(state->h2,state->r1) +
	       mul32x32_64(state->h3,state->r0) +
	       mul32x32_64(state->h4,state->s4);
	t[4] = mul32x32_64(state->h0,state->r4) +
	       mul32x32_64(state->h1,state->r3) +
	       mul32x32_64(state->h2,state->r2) +
	       mul32x32_64(state->h3,state->r1) +
	       mul32x32_64(state->h4,state->r0);

	           state->h0 = (uint32_t)t[0] & 0x3ffffff; c =           (t[0] >> 26);
	t[1] += c; state->h1 = (uint32_t)t[1] & 0x3ffffff; b = (uint32_t)(t[1] >> 26);
	t[2] += b; state->h2 = (uint32_t)t[2] & 0x3ffffff; b = (uint32_t)(t[2] >> 26);
	t[3] += b; state->h3 = (uint32_t)t[3] & 0x3ffffff; b = (uint32_t)(t[3] >> 26);
	t[4] += b; state->h4 = (uint32_t)t[4] & 0x3ffffff; b = (uint32_t)(t[4] >> 26);
	state->h0 += b * 5;

	if (len >= 16)
		goto poly1305_donna_16bytes;

	/* final bytes */
poly1305_donna_atmost15bytes:
	if (!len)
		return;

	for (j = 0; j < len; j++)
		mp[j] = in[j];
	mp[j++] = 1;
	for (; j < 16; j++)
		mp[j] = 0;
	len = 0;

	t0 = U8TO32_LE(mp+0);
	t1 = U8TO32_LE(mp+4);
	t2 = U8TO32_LE(mp+8);
	t3 = U8TO32_LE(mp+12);

	state->h0 += t0 & 0x3ffffff;
	state->h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
	state->h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
	state->h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
	state->h4 += (t3 >> 8);

	goto poly1305_donna_mul;
	}

void CRYPTO_poly1305_init(poly1305_state *statep, const unsigned char key[32])
	{
	struct poly1305_state_st *state = (struct poly1305_state_st*) statep;
	uint32_t t0,t1,t2,t3;

	t0 = U8TO32_LE(key+0);
	t1 = U8TO32_LE(key+4);
	t2 = U8TO32_LE(key+8);
	t3 = U8TO32_LE(key+12);

	/* precompute multipliers */
	state->r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
	state->r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
	state->r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
	state->r3 = t2 & 0x3f03fff; t3 >>= 8;
	state->r4 = t3 & 0x00fffff;

	state->s1 = state->r1 * 5;
	state->s2 = state->r2 * 5;
	state->s3 = state->r3 * 5;
	state->s4 = state->r4 * 5;

	/* init state */
	state->h0 = 0;
	state->h1 = 0;
	state->h2 = 0;
	state->h3 = 0;
	state->h4 = 0;

	state->buf_used = 0;
	memcpy(state->key, key + 16, sizeof(state->key));
	}

void CRYPTO_poly1305_update(poly1305_state *statep, const unsigned char *in,
		     size_t in_len)
	{
	unsigned int i;
	struct poly1305_state_st *state = (struct poly1305_state_st*) statep;

	if (state->buf_used)
		{
		unsigned int todo = 16 - state->buf_used;
		if (todo > in_len)
			todo = in_len;
		for (i = 0; i < todo; i++)
			state->buf[state->buf_used + i] = in[i];
		state->buf_used += todo;
		in_len -= todo;
		in += todo;

		if (state->buf_used == 16)
			{
			poly1305_update(state, state->buf, 16);
			state->buf_used = 0;
			}
		}

	if (in_len >= 16)
		{
		size_t todo = in_len & ~0xf;
		poly1305_update(state, in, todo);
		in += todo;
		in_len &= 0xf;
		}

	if (in_len)
		{
		for (i = 0; i < in_len; i++)
			state->buf[i] = in[i];
		state->buf_used = in_len;
		}
	}

void CRYPTO_poly1305_finish(poly1305_state *statep, unsigned char mac[16])
	{
	struct poly1305_state_st *state = (struct poly1305_state_st*) statep;
	uint64_t f0,f1,f2,f3;
	uint32_t g0,g1,g2,g3,g4;
	uint32_t b, nb;

	if (state->buf_used)
		poly1305_update(state, state->buf, state->buf_used);

	                    b = state->h0 >> 26; state->h0 = state->h0 & 0x3ffffff;
	state->h1 +=     b; b = state->h1 >> 26; state->h1 = state->h1 & 0x3ffffff;
	state->h2 +=     b; b = state->h2 >> 26; state->h2 = state->h2 & 0x3ffffff;
	state->h3 +=     b; b = state->h3 >> 26; state->h3 = state->h3 & 0x3ffffff;
	state->h4 +=     b; b = state->h4 >> 26; state->h4 = state->h4 & 0x3ffffff;
	state->h0 += b * 5;

	g0 = state->h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
	g1 = state->h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
	g2 = state->h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
	g3 = state->h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
	g4 = state->h4 + b - (1 << 26);

	b = (g4 >> 31) - 1;
	nb = ~b;
	state->h0 = (state->h0 & nb) | (g0 & b);
	state->h1 = (state->h1 & nb) | (g1 & b);
	state->h2 = (state->h2 & nb) | (g2 & b);
	state->h3 = (state->h3 & nb) | (g3 & b);
	state->h4 = (state->h4 & nb) | (g4 & b);

	f0 = ((state->h0      ) | (state->h1 << 26)) + (uint64_t)U8TO32_LE(&state->key[0]);
	f1 = ((state->h1 >>  6) | (state->h2 << 20)) + (uint64_t)U8TO32_LE(&state->key[4]);
	f2 = ((state->h2 >> 12) | (state->h3 << 14)) + (uint64_t)U8TO32_LE(&state->key[8]);
	f3 = ((state->h3 >> 18) | (state->h4 <<  8)) + (uint64_t)U8TO32_LE(&state->key[12]);

	U32TO8_LE(&mac[ 0], f0); f1 += (f0 >> 32);
	U32TO8_LE(&mac[ 4], f1); f2 += (f1 >> 32);
	U32TO8_LE(&mac[ 8], f2); f3 += (f2 >> 32);
	U32TO8_LE(&mac[12], f3);
	}

#endif  /* !OPENSSL_NO_POLY1305 */
