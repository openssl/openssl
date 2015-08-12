/*------------------------------------------------------------------
 * kdf/kdf_tls.c - Key Derivation Function for TLS
 *
 * This product contains software written by:
 * Barry Fussell (bfussell@cisco.com)
 * Cisco Systems, March 2015
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
#include <openssl/fips.h>


/*
 * kdf_tls12_P_hash - KDF in compliance with SP800-135 for TLS 1.2
 *
 */
int kdf_tls12_P_hash(const EVP_MD *evp_md, const unsigned char *sec,
                     int sec_len,
		     const void *seed1, int seed1_len,
		     const void *seed2, int seed2_len,
		     const void *seed3, int seed3_len,
		     const void *seed4, int seed4_len,
		     const void *seed5, int seed5_len,
		     unsigned char *out, int olen)
{
    HMAC_CTX hctx;
    HMAC_CTX hctx_tmp;
    HMAC_CTX hctx_init;
    unsigned char A1[EVP_MAX_MD_SIZE];
    unsigned int A1_len, j;
    int chunk;
    int ret = 0;

    if (!evp_md || !sec || !sec_len || !out || !olen) {
        KDFerr(KDF_F_KDF_TLS12_P_HASH, KDF_R_INPUT_PARAMETER_ERROR);
        return ret;
    }

    chunk = evp_md->md_size;

    HMAC_CTX_init(&hctx);
    HMAC_CTX_init(&hctx_tmp);
    HMAC_CTX_init(&hctx_init);
    if (!HMAC_Init_ex(&hctx_init, sec, sec_len, evp_md, NULL)) {
        goto err;
    }
    HMAC_CTX_set_flags(&hctx_init, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);

    if (!HMAC_CTX_copy(&hctx, &hctx_init)) {
        goto err;
    }
    if (!HMAC_Update(&hctx, seed1, seed1_len)) {
        goto err;
    }
    if (!HMAC_Update(&hctx, seed2, seed2_len)) {
        goto err;
    }
    if (!HMAC_Update(&hctx, seed3, seed3_len)) {
        goto err;
    }
    if (!HMAC_Update(&hctx, seed4, seed4_len)) {
        goto err;
    }
    if (!HMAC_Update(&hctx, seed5, seed5_len)) {
        goto err;
    }
    if (!HMAC_Final(&hctx, A1, &A1_len)) {
        goto err;
    }

    HMAC_CTX_cleanup(&hctx);
    HMAC_CTX_init(&hctx);

    for (;;) {
	if (!HMAC_CTX_copy(&hctx, &hctx_init)) {
            goto err;
        }
	if (!HMAC_Update(&hctx, A1, A1_len)) {
            goto err;
        }
        if (olen > chunk && !HMAC_CTX_copy(&hctx_tmp, &hctx))
            goto err;

	if (!HMAC_Update(&hctx, seed1, seed1_len)) {
            goto err;
        }
	if (!HMAC_Update(&hctx, seed2, seed2_len)) {
            goto err;
        }
	if (!HMAC_Update(&hctx, seed3, seed3_len)) {
            goto err;
	}
	if (!HMAC_Update(&hctx, seed4, seed4_len)) {
            goto err;
	}
	if (!HMAC_Update(&hctx, seed5, seed5_len)) {
            goto err;
	}

        if (olen > chunk) {
            if (!HMAC_Final(&hctx, out, &j))
                goto err;
            out += j;
            olen -= j;
            /* calc the next A1 value */
            j = HMAC_Final(&hctx_tmp, A1, &A1_len);
	    if (!j)
                goto err;

            HMAC_CTX_cleanup(&hctx);
            HMAC_CTX_cleanup(&hctx_tmp);
        } else {                /* last one */

            if (!HMAC_Final(&hctx, A1, &A1_len))
                goto err;
            memcpy(out, A1, olen);
            break;
        }
    }
    ret = 1;
err:
    HMAC_CTX_cleanup(&hctx);
    HMAC_CTX_cleanup(&hctx_init);
    HMAC_CTX_cleanup(&hctx_tmp);
    OPENSSL_cleanse(A1, sizeof(A1));
    return ret;
}


