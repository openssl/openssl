/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/sm2.h"
#include "internal/sm2err.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <string.h>
#include "internal/numbers.h"

int sm2_compute_userid_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const char *user_id,
                              const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    size_t uid_len = 0;
    uint16_t entla = 0;
    uint8_t e_byte = 0;

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    /* ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA) */

    uid_len = strlen(user_id);
    if (uid_len >= (UINT16_MAX / 8)) {
        /* too large */
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, SM2_R_USER_ID_TOO_LARGE);
        goto done;
    }

    entla = (uint16_t)(8 * uid_len);

    e_byte = entla >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entla & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)
            || !EVP_DigestUpdate(hash, user_id, uid_len)) {
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, ERR_R_EC_LIB);
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(b, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates_GFp(group,
                                                EC_GROUP_get0_generator(group),
                                                xG, yG, ctx)
            || BN_bn2binpad(xG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates_GFp(group,
                                                    EC_KEY_get0_public_key(key),
                                                    xA, yA, ctx)
            || BN_bn2binpad(xA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EVP_DigestFinal(hash, out, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_USERID_DIGEST, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    rc = 1;

 done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}
