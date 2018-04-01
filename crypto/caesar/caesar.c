/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include <openssl/caesar.h>

#include <assert.h>
#include <string.h>
#include <stdio.h>

void CAESAR_set_key(CAESAR_KEY *key, int len, const unsigned char *data)
{
	int i;

	key->len = len >= 0 ? len : 0;
	if (len >= sizeof key->data)
		key->len = sizeof key->data - 1;

	for (i = 0; i < key->len; i++)
		key->data[i] = (unsigned)data[i] % 26;
}

static void caesar_round(unsigned char *outdata, const unsigned char *indata, size_t len, int key)
{
	size_t i;
	signed char c, uc, thresh = 'A' - 1 - (key - 26);
	signed isgeA, isleZ, isgtthresh;

	fprintf(stderr, "key = %d\n", key);

	for (i = 0; i < len; i++) {
		c = (signed char)indata[i];
		uc = c & ~0x20;				/* c in upper case */
		isgeA = -('A' <= uc);
		isleZ = -(uc <= 'Z');
		isgtthresh = -(thresh < uc);
		c += (key & isgeA & ~isgtthresh) | (key - 26 & isleZ & isgtthresh);
		outdata[i] = (unsigned char)c;
	}
}

void CAESAR(CAESAR_KEY *key, size_t len, const unsigned char *indata, unsigned char *outdata)
{
	size_t i;

	for (i = 0; i < key->len; i++)
		caesar_round(outdata, indata, len, (unsigned char)key->data[i]);
}
