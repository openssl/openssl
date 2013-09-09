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

#ifndef OPENSSL_NO_CHACHA

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/chacha.h>

struct chacha_test {
	const char *keyhex;
	const char *noncehex;
	const char *outhex;
};

static const struct chacha_test chacha_tests[] = {
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000",
		"4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000001",
		"de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e31afab757",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000",
		"ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b",
	},
	{
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"0001020304050607",
		"f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb",
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

/* misalign returns a pointer that points 0 to 15 bytes into |in| such that the
 * returned pointer has alignment 1 mod 16. */
static void* misalign(void* in)
	{
	intptr_t x = (intptr_t) in;
	x += (17 - (x % 16)) % 16;
	return (void*) x;
	}

int main()
	{
	static const unsigned num_tests =
		sizeof(chacha_tests) / sizeof(struct chacha_test);
	unsigned i;
	unsigned char key_bytes[32 + 16];
	unsigned char nonce_bytes[8 + 16] = {0};

	unsigned char *key = misalign(key_bytes);
	unsigned char *nonce = misalign(nonce_bytes);

	for (i = 0; i < num_tests; i++)
		{
		const struct chacha_test *test = &chacha_tests[i];
		unsigned char *expected, *out_bytes, *zero_bytes, *out, *zeros;
		size_t len = strlen(test->outhex);

		if (strlen(test->keyhex) != 32*2 ||
		    strlen(test->noncehex) != 8*2 ||
		    (len & 1) == 1)
			return 1;

		len /= 2;

		hex_decode(key, test->keyhex);
		hex_decode(nonce, test->noncehex);

		expected = malloc(len);
		out_bytes = malloc(len+16);
		zero_bytes = malloc(len+16);
		/* Attempt to test unaligned inputs. */
		out = misalign(out_bytes);
		zeros = misalign(zero_bytes);
		memset(zeros, 0, len);

		hex_decode(expected, test->outhex);
		CRYPTO_chacha_20(out, zeros, len, key, nonce, 0);

		if (memcmp(out, expected, len) != 0)
			{
			printf("ChaCha20 test #%d failed.\n", i);
			printf("got:      ");
			hexdump(out, len);
			printf("\nexpected: ");
			hexdump(expected, len);
			printf("\n");
			return 1;
			}

		/* The last test has a large output. We test whether the
		 * counter works as expected by skipping the first 64 bytes of
		 * it. */
		if (i == num_tests - 1)
			{
			CRYPTO_chacha_20(out, zeros, len - 64, key, nonce, 1);
			if (memcmp(out, expected + 64, len - 64) != 0)
				{
				printf("ChaCha20 skip test failed.\n");
				return 1;
				}
			}

		free(expected);
		free(zero_bytes);
		free(out_bytes);
		}


	printf("PASS\n");
	return 0;
	}

#else  /* OPENSSL_NO_CHACHA */

int main() { return 0; }

#endif /* OPENSSL_NO_CHACHA */
