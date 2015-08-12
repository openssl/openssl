/*------------------------------------------------------------------
 * kdf/kdf_802_11i.c - Key Derivation Function for 802.11i
 *
 * This product contains software written by:
 * Barry Fussell (bfussell@cisco.com)
 * Cisco Systems, February 2015
 *
 * Copyright (c) 2015 by Cisco Systems, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cryptlib.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

/*
 * kdf_802_11i - in compliance with SP800-108/802.11i to calculate
 *               a master key using PRF.
 *
 *	Note: This KDF was written with 802.11i users in mind and per that spec
 *	      starts its counter at zero and the result is returned at the
 *	      start of the "out" buffer.  When used for SP800-108 callers
 *	      are required to add 1 md_size to the "len" and 1 md_size
 *	      to the "out" buffer so that an extra pass is performed, simulating
 *	      a starting counter of 1. In addition the result should be pulled
 *	      from 1 md_size into the "out" buffer.
 */
int kdf_802_11i(unsigned char *key, int key_len,
                unsigned char *prefix, int prefix_len,
		unsigned char *data, int data_len,
		unsigned char *out, unsigned int len, const EVP_MD *evp_md)
{
    unsigned int outlen = -1;
    HMAC_CTX hctx;
    unsigned char *input; /* Buffer to hold complete input to HMAC funcion */
    int currentindex = 0, i, hmac_data_len;


    if (!key || !key_len || !data || !data_len || !out || !len || !evp_md) {
        KDFerr(KDF_F_KDF_802_11I, KDF_R_INPUT_PARAMETER_ERROR);
        return -1;
    }

    input = OPENSSL_malloc(prefix_len + data_len + 2);
    if (!input) {
        KDFerr(KDF_F_KDF_802_11I, KDF_R_MALLOC);
        return -1;
    }
    /*
     * For PRF as per 802.11i   - loop counter starts from 0
     * For PRF as per SP800-108 - loop counter starts from 1
     */
    if ((prefix != NULL) && (prefix_len > 0)) {
        memcpy(input, prefix, prefix_len);
        input[prefix_len] = 0; /* Single octet 0 for 'Y' as in: HMAC-SHA-1(K, A || Y || B || X) */
        memcpy(&input[prefix_len + 1], data, data_len);
        input[prefix_len + 1 + data_len] = 0; /* single octet 0 for 802.11i */
        hmac_data_len = prefix_len + data_len + 2;
    } else {
        /* 
	 * FIPS validation will be only for counter after fixed data, length
	 * 8 bits and supporting all flavors of SHA.
	 */
        memcpy(input, data, data_len);
        input[data_len] = 0;     /* single octet 0 for SP800-108 */
        hmac_data_len = data_len + 1;
    }

    HMAC_CTX_init(&hctx);
    for (i = 0; i < (len + evp_md->md_size -1)/evp_md->md_size; i++) {
        if (!HMAC_Init_ex(&hctx, key, key_len, evp_md, NULL)) {
	    break;
	}
        if (!HMAC_Update(&hctx, input, hmac_data_len)) {
	    break;
        }
	if (!HMAC_Final(&hctx, &out[currentindex], &outlen)) {
	    break;
	}
        currentindex += evp_md->md_size;  /* Update HMAC output concatenation location */
        input[hmac_data_len - 1]++;       /* Increment counter in HMAC-SHA-*(K, A || Y || B || X) */
    }
    OPENSSL_cleanse(input, (prefix_len + data_len + 2));
    OPENSSL_free(input);
    HMAC_CTX_cleanup(&hctx);
    return outlen;
}
