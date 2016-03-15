/* ====================================================================
 * Copyright (c) 2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/dsa.h>

struct dsa_st {
    /*
     * This first variable is used to pick up errors where a DSA is passed
     * instead of of a EVP_PKEY
     */
    int pad;
    long version;
    BIGNUM *p;
    BIGNUM *q;                  /* == 20 */
    BIGNUM *g;
    BIGNUM *pub_key;            /* y public key */
    BIGNUM *priv_key;           /* x private key */
    int flags;
    /* Normally used to cache montgomery values */
    BN_MONT_CTX *method_mont_p;
    int references;
    CRYPTO_EX_DATA ex_data;
    const DSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    CRYPTO_RWLOCK *lock;
};

struct dsa_method {
    char *name;
    DSA_SIG *(*dsa_do_sign) (const unsigned char *dgst, int dlen, DSA *dsa);
    int (*dsa_sign_setup) (DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
                           BIGNUM **rp);
    int (*dsa_do_verify) (const unsigned char *dgst, int dgst_len,
                          DSA_SIG *sig, DSA *dsa);
    int (*dsa_mod_exp) (DSA *dsa, BIGNUM *rr, BIGNUM *a1, BIGNUM *p1,
                        BIGNUM *a2, BIGNUM *p2, BIGNUM *m, BN_CTX *ctx,
                        BN_MONT_CTX *in_mont);
    /* Can be null */
    int (*bn_mod_exp) (DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
    int (*init) (DSA *dsa);
    int (*finish) (DSA *dsa);
    int flags;
    void *app_data;
    /* If this is non-NULL, it is used to generate DSA parameters */
    int (*dsa_paramgen) (DSA *dsa, int bits,
                         const unsigned char *seed, int seed_len,
                         int *counter_ret, unsigned long *h_ret,
                         BN_GENCB *cb);
    /* If this is non-NULL, it is used to generate DSA keys */
    int (*dsa_keygen) (DSA *dsa);
};

int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
                         const EVP_MD *evpmd, const unsigned char *seed_in,
                         size_t seed_len, unsigned char *seed_out,
                         int *counter_ret, unsigned long *h_ret,
                         BN_GENCB *cb);

int dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
                          const EVP_MD *evpmd, const unsigned char *seed_in,
                          size_t seed_len, int idx, unsigned char *seed_out,
                          int *counter_ret, unsigned long *h_ret,
                          BN_GENCB *cb);
