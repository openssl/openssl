/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright (c) 1998-2003 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>
#include <limits.h>

#include "internal/cryptlib.h"

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include "ec_lcl.h"

int ossl_ecdh_compute_key(unsigned char **psec, size_t *pseclen,
                          const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    if (ecdh->group->meth->ecdh_compute_key == NULL) {
        ECerr(EC_F_OSSL_ECDH_COMPUTE_KEY, EC_R_CURVE_DOES_NOT_SUPPORT_ECDH);
        return -1;
    }

    return ecdh->group->meth->ecdh_compute_key(psec, pseclen, pub_key, ecdh);
}

/*-
 * This implementation is based on the following primitives in the IEEE 1363 standard:
 *  - ECKAS-DH1
 *  - ECSVDP-DH
 */
int ecdh_simple_compute_key(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    BN_CTX *ctx;
    EC_POINT *tmp = NULL;
    BIGNUM *x = NULL, *y = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    int ret = 0;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);

    priv_key = EC_KEY_get0_private_key(ecdh);
    if (priv_key == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_NO_PRIVATE_VALUE);
        goto err;
    }

    group = EC_KEY_get0_group(ecdh);

    if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
        if (!EC_GROUP_get_cofactor(group, x, NULL) ||
            !BN_mul(x, x, priv_key, ctx)) {
            ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        priv_key = x;
    }

    if ((tmp = EC_POINT_new(group)) == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_mul(group, tmp, NULL, pub_key, priv_key, ctx)) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_POINT_ARITHMETIC_FAILURE);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, tmp, x, y, ctx)) {
            ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_POINT_ARITHMETIC_FAILURE);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, tmp, x, y, ctx)) {
            ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_POINT_ARITHMETIC_FAILURE);
            goto err;
        }
    }
#endif

    buflen = (EC_GROUP_get_degree(group) + 7) / 8;
    len = BN_num_bytes(x);
    if (len > buflen) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((buf = OPENSSL_malloc(buflen)) == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    memset(buf, 0, buflen - len);
    if (len != (size_t)BN_bn2bin(x, buf + buflen - len)) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    *pout = buf;
    *poutlen = buflen;
    buf = NULL;

    ret = 1;

 err:
    EC_POINT_free(tmp);
    if (ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    OPENSSL_free(buf);
    return ret;
}
