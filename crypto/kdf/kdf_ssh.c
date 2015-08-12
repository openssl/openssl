/*------------------------------------------------------------------
 * kdf/kdf_ssh.c - Key Derivation Function for SSH
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
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

/*
 * kdf_ssh - in compliance with SP800-135 and RFC 4253, calculate
 *            IVs and keys.
 *
 */
int kdf_ssh(const EVP_MD *evp_md, int id, unsigned int need, char *shared_secret, 
            int ss_len, char *session_id, int session_id_len, char *hash, 
	    int hash_len, unsigned char *digest)
{

    char c = id;
    EVP_MD_CTX md;
    unsigned int mdsz, have;

    if (!evp_md || !id || !need || !shared_secret || !ss_len || !session_id ||
        !session_id_len || !hash || !hash_len || !digest) {
        KDFerr(KDF_F_KDF_SSH, KDF_R_INPUT_PARAMETER_ERROR);
        return -1;
    }

    mdsz = evp_md->md_size;
    switch(evp_md->type) {
        case NID_sha1:
        case NID_sha224:
        case NID_sha256:
        case NID_sha384:
        case NID_sha512:
	    EVP_MD_CTX_init(&md);
	    /* K1 = HASH(K || H || "A" || session_id) */
	    if (!EVP_DigestInit_ex(&md, evp_md, NULL)) {
	        goto err;
	    }
	    if (!EVP_DigestUpdate(&md, shared_secret, ss_len)) {
	        goto err;
	    }
	    if (!EVP_DigestUpdate(&md, hash, hash_len)) {
	        goto err;
	    }
	    if (!EVP_DigestUpdate(&md, &c, 1)) {
	        goto err;
	    }
	    if (!EVP_DigestUpdate(&md, session_id, session_id_len)) {
	        goto err;
	    }
	    if (!EVP_DigestFinal_ex(&md, digest, NULL)) {
	        goto err;
	    }

	    /*
	     * expand key:
	     * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	     * Key = K1 || K2 || ... || Kn
	     */
	    for (have = mdsz; need > have; have += mdsz) {
	        if (!EVP_DigestInit_ex(&md, evp_md, NULL)) {
	            goto err;
                 }
		 if (!EVP_DigestUpdate(&md, shared_secret, ss_len)) {
 		     goto err;
                 }
		 if (!EVP_DigestUpdate(&md, hash, hash_len)) {
 		     goto err;
                 }
		 if (!EVP_DigestUpdate(&md, digest, have)) {
 		     goto err;
                 }
		 if (!EVP_DigestFinal_ex(&md, digest + have, NULL)) {
 		     goto err;
                 }
	    }
	    break;
        default:
            KDFerr(KDF_F_KDF_SSH, KDF_R_BAD_DIGEST);
	    return -1;
	    break;
    }    
err:
    EVP_MD_CTX_cleanup(&md);
    return 0;
}
