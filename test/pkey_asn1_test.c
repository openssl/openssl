/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Check ordering in standard_methods array */

#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <internal/asn1_int.h>

int
main(int argc, char *argv[])
{
	int num = EVP_PKEY_asn1_get_count();
	int i;
	const EVP_PKEY_ASN1_METHOD *prev = NULL;
	int result = 0;

	for (i = 0; i < num; i++) {
		const EVP_PKEY_ASN1_METHOD *cur = EVP_PKEY_asn1_get0(i);
		if (prev && prev->pkey_id > cur->pkey_id) {
			printf("standard_methods[%d] method %s is out of order\n",
			       i - 1, OBJ_nid2sn(prev->pkey_id));
			result = 1;
		}
		prev = cur;
	}

	if (result)
		printf("bsearch ordering test of standard_methods array failed\n");

	return result;
}
