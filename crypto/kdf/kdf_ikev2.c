/*------------------------------------------------------------------
 * kdf/kdf_ikev2.c - Key Derivation Functions for IKEv2
 *
 * This product contains software written by:
 * Barry Fussell (bfussell@cisco.com)
 * Cisco Systems, April 2015
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
 * kdf_ikev2_gen - KDF in compliance with SP800-135 for IKEv2,
 *                 generate the seedkey.
 *
 *		   nonce = Ni || Nr
 *		   shared_secret = g^ir
 */
int kdf_ikev2_gen(unsigned char *seedkey, const EVP_MD *evp_md, const void *nonce, 
                  unsigned int nonce_len, const void *shared_secret, 
		  unsigned int shared_secret_len)
{
    HMAC_CTX hctx;
    unsigned int len;
    int ret = -1;

    if (!nonce || !nonce_len || !shared_secret || 
        !shared_secret_len || !evp_md || !seedkey) {
        KDFerr(KDF_F_KDF_IKEV2_GEN, KDF_R_INPUT_PARAMETER_ERROR);
	return ret;
    }

    HMAC_CTX_init(&hctx);
    if (!HMAC_Init_ex(&hctx, nonce, nonce_len, evp_md, NULL)) {
        goto err;
    }
    if (!HMAC_Update(&hctx, shared_secret, shared_secret_len)) {
        goto err;
    }
    if (!HMAC_Final(&hctx, seedkey, &len)) {
        goto err;
    }

    ret = 0;
err:
    HMAC_CTX_cleanup(&hctx);
    return ret;
}

/*
 * kdf_ikev2_rekey - KDF in compliance with SP800-135 for IKEv2,
 *                   re-generate the seedkey.
 *
 *		     nonce = Ni || Nr
 *		     shared_secret = g^ir(new)
 *		     sk_d = DKM (len = md_size)
 */
int kdf_ikev2_rekey(unsigned char *seedkey, const EVP_MD *evp_md, const void *nonce, 
                    unsigned int nonce_len, const void *shared_secret, 
		    unsigned int shared_secret_len, int dh,
		    const void *sk_d, unsigned int skd_len)
{
    HMAC_CTX hctx;
    unsigned int len;
    int ret = -1;

    if (!nonce || !nonce_len || !shared_secret || 
        !shared_secret_len || !evp_md || !seedkey ||
	!sk_d || !skd_len) {
        KDFerr(KDF_F_KDF_IKEV2_REKEY, KDF_R_INPUT_PARAMETER_ERROR);
	return ret;
    }

    HMAC_CTX_init(&hctx);
    if (!HMAC_Init_ex(&hctx, sk_d, skd_len, evp_md, NULL)) {
        goto err;
    }

    /* If used for DH then also include secret */
    if (dh) {
        if (!HMAC_Update(&hctx, shared_secret, shared_secret_len)) {
            goto err;
        }
    }

    if (!HMAC_Update(&hctx, nonce, nonce_len)) {
        goto err;
    }

    if (!HMAC_Final(&hctx, seedkey, &len)) {
        goto err;
    }
    ret = 0;
err:
    HMAC_CTX_cleanup(&hctx);
    return ret;
}


/*
 * kdf_ikev2_dkm - KDF in compliance with SP800-135 for IKEv2,
 *                 generate the Derived Keying Material. For DKM,
 *		   DKM(Child SA) and DKM(Child SA D-H).
 *
 *		   seedkey(DKM) = SEEDKEY
 *		   seedkey(DKM SA) = DKM
 *		   seedkey(DKM SA DH) = DKM
 *		   nonce(DKM) = Ni || Nr || SPIi || SPIr
 *		   nonce(DKM SA) = Ni || Nr
 *		   nonce(DKM SA DH) = Ni || Nr
 *		   shared_secret(DKM) = Null
 *		   shared_secret(DKM SA) = Null
 *		   shared_secret(DKM SA DH) = g^ir (new)
 */
int kdf_ikev2_dkm(unsigned char *dkm, unsigned int len_out, const EVP_MD *evp_md, 
	          const void *seedkey, unsigned int seedkey_len,
		  unsigned char *nonce, unsigned int nonce_len,
		  unsigned char *shared_secret, unsigned int shared_secret_len)
{
    HMAC_CTX hctx;
    unsigned int len = 0;
    int i, value_len, ret = -1;
    unsigned char *value;

    if (!nonce || !nonce_len || !evp_md || !seedkey || 
        !seedkey_len || !dkm || !len_out) {
        KDFerr(KDF_F_KDF_IKEV2_DKM, KDF_R_INPUT_PARAMETER_ERROR);
	return ret;
    }

    /* if len is defined, ss must be defined */
    if (shared_secret_len && !shared_secret) {
        KDFerr(KDF_F_KDF_IKEV2_DKM, KDF_R_INPUT_PARAMETER_ERROR);
	return ret;
    }

    value_len = shared_secret_len + nonce_len + 1;
    value = OPENSSL_malloc(value_len);
    if (!value) {
        KDFerr(KDF_F_KDF_IKEV2_DKM, KDF_R_MALLOC);
        return ret;
    }

    /* concatenate and add counter to end */
    value[value_len - 1] = 01;
    if (shared_secret_len) {
        memcpy(value, shared_secret, shared_secret_len);
    }
    memcpy(value + shared_secret_len, nonce, nonce_len);

    HMAC_CTX_init(&hctx);
    
    for (i=0; i<len_out; i+=evp_md->md_size) {

        if (!HMAC_Init_ex(&hctx, seedkey, seedkey_len, evp_md, NULL)) {
	    goto err;
        }
	/* after first pass hash in the dkm */
	if (i != 0) {
            if (!HMAC_Update(&hctx, &dkm[i - evp_md->md_size], len)) {
	        goto err;
            }
        }

	if (!HMAC_Update(&hctx, value, value_len)) {
	    goto err;
        }

        if (!HMAC_Final(&hctx, &dkm[i], &len)) {
            goto err;
        }
	value[value_len - 1]++; 
    }

    ret = 0;
err:
    OPENSSL_cleanse(value, value_len);
    OPENSSL_free(value);
    HMAC_CTX_cleanup(&hctx);
    return ret;
}
