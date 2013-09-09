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

/* This implementation was taken from the public domain, neon2 version in
 * SUPERCOP by D. J. Bernstein and Peter Schwabe. */

#include <stdint.h>

#include <openssl/poly1305.h>

#if !defined(OPENSSL_NO_POLY1305)

typedef struct {
  uint32_t v[12]; /* for alignment; only using 10 */
} fe1305x2;

#define addmulmod openssl_poly1305_neon2_addmulmod
#define blocks openssl_poly1305_neon2_blocks

extern void addmulmod(fe1305x2 *r, const fe1305x2 *x, const fe1305x2 *y, const fe1305x2 *c);

extern int blocks(fe1305x2 *h, const fe1305x2 *precomp, const unsigned char *in, unsigned int inlen);

static void freeze(fe1305x2 *r)
	{
	int i;

	uint32_t x0 = r->v[0];
	uint32_t x1 = r->v[2];
	uint32_t x2 = r->v[4];
	uint32_t x3 = r->v[6];
	uint32_t x4 = r->v[8];
	uint32_t y0;
	uint32_t y1;
	uint32_t y2;
	uint32_t y3;
	uint32_t y4;
	uint32_t swap;

	for (i = 0;i < 3;++i)
		{
		x1 += x0 >> 26; x0 &= 0x3ffffff;
		x2 += x1 >> 26; x1 &= 0x3ffffff;
		x3 += x2 >> 26; x2 &= 0x3ffffff;
		x4 += x3 >> 26; x3 &= 0x3ffffff;
		x0 += 5*(x4 >> 26); x4 &= 0x3ffffff;
		}

	y0 = x0 + 5;
	y1 = x1 + (y0 >> 26); y0 &= 0x3ffffff;
	y2 = x2 + (y1 >> 26); y1 &= 0x3ffffff;
	y3 = x3 + (y2 >> 26); y2 &= 0x3ffffff;
	y4 = x4 + (y3 >> 26); y3 &= 0x3ffffff;
	swap = -(y4 >> 26); y4 &= 0x3ffffff;

	y0 ^= x0;
	y1 ^= x1;
	y2 ^= x2;
	y3 ^= x3;
	y4 ^= x4;

	y0 &= swap;
	y1 &= swap;
	y2 &= swap;
	y3 &= swap;
	y4 &= swap;

	y0 ^= x0;
	y1 ^= x1;
	y2 ^= x2;
	y3 ^= x3;
	y4 ^= x4;

	r->v[0] = y0;
	r->v[2] = y1;
	r->v[4] = y2;
	r->v[6] = y3;
	r->v[8] = y4;
	}

static void fe1305x2_tobytearray(unsigned char *r, fe1305x2 *x)
	{
	uint32_t x0 = x->v[0];
	uint32_t x1 = x->v[2];
	uint32_t x2 = x->v[4];
	uint32_t x3 = x->v[6];
	uint32_t x4 = x->v[8];

	x1 += x0 >> 26;
	x0 &= 0x3ffffff;
	x2 += x1 >> 26;
	x1 &= 0x3ffffff;
	x3 += x2 >> 26;
	x2 &= 0x3ffffff;
	x4 += x3 >> 26;
	x3 &= 0x3ffffff;

	*(uint32_t *) r = x0 + (x1 << 26);
	*(uint32_t *) (r + 4) = (x1 >> 6) + (x2 << 20);
	*(uint32_t *) (r + 8) = (x2 >> 12) + (x3 << 14);
	*(uint32_t *) (r + 12) = (x3 >> 18) + (x4 << 8);
	}

/* load32 exists to avoid breaking strict aliasing rules in
 * fe1305x2_frombytearray. */
static uint32_t load32(unsigned char *t)
	{
	uint32_t tmp;
	memcpy(&tmp, t, sizeof(tmp));
	return tmp;
	}

static void fe1305x2_frombytearray(fe1305x2 *r, const unsigned char *x, unsigned long long xlen)
	{
	int i;
	unsigned char t[17];

	for (i = 0; (i < 16) && (i < xlen); i++)
		t[i] = x[i];
	xlen -= i;
	x += i;
	t[i++] = 1;
	for (; i<17; i++)
		t[i] = 0;

	r->v[0] = 0x3ffffff & load32(t);
	r->v[2] = 0x3ffffff & (load32(t + 3) >> 2);
	r->v[4] = 0x3ffffff & (load32(t + 6) >> 4);
	r->v[6] = 0x3ffffff & (load32(t + 9) >> 6);
	r->v[8] = load32(t + 13);

	if (xlen)
		{
		for (i = 0; (i < 16) && (i < xlen); i++)
			t[i] = x[i];
		t[i++] = 1;
		for (; i<17; i++)
			t[i] = 0;

		r->v[1] = 0x3ffffff & load32(t);
		r->v[3] = 0x3ffffff & (load32(t + 3) >> 2);
		r->v[5] = 0x3ffffff & (load32(t + 6) >> 4);
		r->v[7] = 0x3ffffff & (load32(t + 9) >> 6);
		r->v[9] = load32(t + 13);
		}
	else
		r->v[1] = r->v[3] = r->v[5] = r->v[7] = r->v[9] = 0;
	}

static const fe1305x2 zero __attribute__ ((aligned (16)));

struct poly1305_state_st {
	unsigned char data[sizeof(fe1305x2[5]) + 128];
	unsigned char buf[32];
	unsigned int buf_used;
	unsigned char key[16];
};

void CRYPTO_poly1305_init(poly1305_state *state, const unsigned char key[32])
	{
	struct poly1305_state_st *st = (struct poly1305_state_st*) (state);
	fe1305x2 *const r = (fe1305x2 *) (st->data + (15 & (-(int) st->data)));
	fe1305x2 *const h = r + 1;
	fe1305x2 *const c = h + 1;
	fe1305x2 *const precomp = c + 1;
	unsigned int j;

	r->v[1] = r->v[0] = 0x3ffffff & *(uint32_t *) key;
	r->v[3] = r->v[2] = 0x3ffff03 & ((*(uint32_t *) (key + 3)) >> 2);
	r->v[5] = r->v[4] = 0x3ffc0ff & ((*(uint32_t *) (key + 6)) >> 4);
	r->v[7] = r->v[6] = 0x3f03fff & ((*(uint32_t *) (key + 9)) >> 6);
	r->v[9] = r->v[8] = 0x00fffff & ((*(uint32_t *) (key + 12)) >> 8);

	for (j = 0; j < 10; j++)
		h->v[j] = 0; /* XXX: should fast-forward a bit */

	addmulmod(precomp,r,r,&zero);                 /* precompute r^2 */
	addmulmod(precomp + 1,precomp,precomp,&zero); /* precompute r^4 */

	memcpy(st->key, key + 16, 16);
	st->buf_used = 0;
	}

void CRYPTO_poly1305_update(poly1305_state *state, const unsigned char *in, size_t in_len)
	{
	struct poly1305_state_st *st = (struct poly1305_state_st*) (state);
	fe1305x2 *const r = (fe1305x2 *) (st->data + (15 & (-(int) st->data)));
	fe1305x2 *const h = r + 1;
	fe1305x2 *const c = h + 1;
	fe1305x2 *const precomp = c + 1;
	unsigned int i;
	unsigned char data[sizeof(fe1305x2) + 16];
	fe1305x2 *const r2r = (fe1305x2 *) (data + (15 & (-(int) data)));

	if (st->buf_used)
		{
		unsigned int todo = 32 - st->buf_used;
		if (todo > in_len)
			todo = in_len;
		for (i = 0; i < todo; i++)
			st->buf[st->buf_used + i] = in[i];
		st->buf_used += todo;
		in_len -= todo;
		in += todo;

		if (st->buf_used == sizeof(st->buf))
			{
			fe1305x2_frombytearray(c, st->buf, sizeof(st->buf));
			r2r->v[0] = precomp->v[0];
			r2r->v[2] = precomp->v[2];
			r2r->v[4] = precomp->v[4];
			r2r->v[6] = precomp->v[6];
			r2r->v[8] = precomp->v[8];
			r2r->v[1] = r->v[1];
			r2r->v[3] = r->v[3];
			r2r->v[5] = r->v[5];
			r2r->v[7] = r->v[7];
			r2r->v[9] = r->v[9];
			addmulmod(h,h,r2r,c);
			st->buf_used = 0;
			}
		}

	while (in_len > 32)
		{
		unsigned int tlen = 1048576;
		if (in_len < 1048576)
			tlen = in_len;
		tlen -= blocks(h, precomp, in, tlen);
		in_len -= tlen;
		in += tlen;
		}

	if (in_len)
		{
		for (i = 0; i < in_len; i++)
			st->buf[i] = in[i];
		st->buf_used = in_len;
		}
	}

void CRYPTO_poly1305_finish(poly1305_state* state, unsigned char mac[16])
	{
	struct poly1305_state_st *st = (struct poly1305_state_st*) (state);
	fe1305x2 *const r = (fe1305x2 *) (st->data + (15 & (-(int) st->data)));
	fe1305x2 *const h = r + 1;
	fe1305x2 *const c = h + 1;
	fe1305x2 *const precomp = c + 1;

	if (st->buf_used > 16)
		{
		fe1305x2_frombytearray(c, st->buf, st->buf_used);
		precomp->v[1] = r->v[1];
		precomp->v[3] = r->v[3];
		precomp->v[5] = r->v[5];
		precomp->v[7] = r->v[7];
		precomp->v[9] = r->v[9];
		addmulmod(h,h,precomp,c);
		}
	else if (st->buf_used > 0)
		{
		fe1305x2_frombytearray(c, st->buf, st->buf_used);
		r->v[1] = 1;
		r->v[3] = 0;
		r->v[5] = 0;
		r->v[7] = 0;
		r->v[9] = 0;
		addmulmod(h,h,r,c);
		}

	h->v[0] += h->v[1];
	h->v[2] += h->v[3];
	h->v[4] += h->v[5];
	h->v[6] += h->v[7];
	h->v[8] += h->v[9];
	freeze(h);

	fe1305x2_frombytearray(c, st->key, 16);
	c->v[8] ^= (1 << 24);

	h->v[0] += c->v[0];
	h->v[2] += c->v[2];
	h->v[4] += c->v[4];
	h->v[6] += c->v[6];
	h->v[8] += c->v[8];
	fe1305x2_tobytearray(mac, h);
	}

#endif  /* !OPENSSL_NO_POLY1305 */
