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

#ifndef OPENSSL_NO_POLY1305

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/poly1305.h>

struct poly1305_test
	{
	const char *inputhex;
	const char *keyhex;
	const char *outhex;
	};

static const struct poly1305_test poly1305_tests[] = {
	{
		"",
		"c8afaac331ee372cd6082de134943b174710130e9f6fea8d72293850a667d86c",
		"4710130e9f6fea8d72293850a667d86c",
	},
	{
		"48656c6c6f20776f726c6421",
		"746869732069732033322d62797465206b657920666f7220506f6c7931333035",
		"a6f745008f81c916a20dcc74eef2b2f0",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"746869732069732033322d62797465206b657920666f7220506f6c7931333035",
		"49ec78090e481ec6c26b33b91ccc0307",
	},
};

static unsigned char hex_digit(char h)
	{
	if (h >= '0' && h <= '9')
		return h - '0';
	else if (h >= 'a' && h <= 'f')
		return h - 'a' + 10;
	else if (h >= 'A' && h <= 'F')
		return h - 'A' + 10;
	else
		abort();
	}

static void hex_decode(unsigned char *out, const char* hex)
	{
	size_t j = 0;

	while (*hex != 0)
		{
		unsigned char v = hex_digit(*hex++);
		v <<= 4;
		v |= hex_digit(*hex++);
		out[j++] = v;
		}
	}

static void hexdump(unsigned char *a, size_t len)
	{
	size_t i;

	for (i = 0; i < len; i++)
		printf("%02x", a[i]);
	}

int main()
	{
	static const unsigned num_tests =
		sizeof(poly1305_tests) / sizeof(struct poly1305_test);
	unsigned i;
	unsigned char key[32], out[16], expected[16];
	poly1305_state poly1305;

	for (i = 0; i < num_tests; i++)
		{
		const struct poly1305_test *test = &poly1305_tests[i];
		unsigned char *in;
		size_t inlen = strlen(test->inputhex);

		if (strlen(test->keyhex) != sizeof(key)*2 ||
		    strlen(test->outhex) != sizeof(out)*2 ||
		    (inlen & 1) == 1)
			return 1;

		inlen /= 2;

		hex_decode(key, test->keyhex);
		hex_decode(expected, test->outhex);

		in = malloc(inlen);

		hex_decode(in, test->inputhex);
		CRYPTO_poly1305_init(&poly1305, key);
		CRYPTO_poly1305_update(&poly1305, in, inlen);
		CRYPTO_poly1305_finish(&poly1305, out);

		if (memcmp(out, expected, sizeof(expected)) != 0)
			{
			printf("Poly1305 test #%d failed.\n", i);
			printf("got:      ");
			hexdump(out, sizeof(out));
			printf("\nexpected: ");
			hexdump(expected, sizeof(expected));
			printf("\n");
			return 1;
			}

		free(in);
		}

	printf("PASS\n");
	return 0;
	}

#else  /* OPENSSL_NO_POLY1305 */

int main() { return 0; }

#endif
