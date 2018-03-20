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

#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>

typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

ASN1_SEQUENCE(SM2_Ciphertext) = {
    ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)

static size_t EC_field_size(const EC_GROUP *group)
{
    /* Is there some simpler way to do this? */
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    size_t field_size = 0;

    if (p == NULL || a == NULL || b == NULL)
       goto done;

    EC_GROUP_get_curve_GFp(group, p, a, b, NULL);
    field_size = (BN_num_bits(p) + 7) / 8;

 done:
    BN_free(p);
    BN_free(a);
    BN_free(b);

    return field_size;
}

size_t SM2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len)
{
    const size_t field_size = EC_field_size(EC_KEY_get0_group(key));
    const size_t md_size = EVP_MD_size(digest);

    const size_t overhead = 10 + 2 * field_size + md_size;
    if(msg_len <= overhead)
       return 0;

    return msg_len - overhead;
}

size_t SM2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len)
{
    const size_t field_size = EC_field_size(EC_KEY_get0_group(key));
    const size_t md_size = EVP_MD_size(digest);
    return 10 + 2 * field_size + md_size + msg_len;
}

int SM2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len, uint8_t *ciphertext_buf, size_t *ciphertext_len)
{
    int rc = 0;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;

    EVP_MD_CTX *hash = EVP_MD_CTX_new();

    struct SM2_Ciphertext_st ctext_struct;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    uint8_t *msg_mask = NULL;

    uint8_t *x2y2 = NULL;
    uint8_t *C3 = NULL;

    const size_t field_size = EC_field_size(group);
    const size_t C3_size = EVP_MD_size(digest);

    if (field_size == 0 || C3_size == 0)
       goto done;

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    if (kG == NULL || kP == NULL)
       goto done;

    ctx = BN_CTX_new();
    if (ctx == NULL)
       goto done;

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL)
       goto done;

    x2y2 = OPENSSL_zalloc(2 * field_size);
    C3 = OPENSSL_zalloc(C3_size);

    if (x2y2 == NULL || C3 == NULL)
       goto done;

    memset(ciphertext_buf, 0, *ciphertext_len);

    BN_priv_rand_range(k, order);

    if (EC_POINT_mul(group, kG, k, NULL, NULL, ctx) == 0)
        goto done;

    if (EC_POINT_get_affine_coordinates_GFp(group, kG, x1, y1, ctx) == 0)
        goto done;

    if (EC_POINT_mul(group, kP, NULL, P, k, ctx) == 0)
        goto done;

    if (EC_POINT_get_affine_coordinates_GFp(group, kP, x2, y2, ctx) == 0)
        goto done;

    BN_bn2binpad(x2, x2y2, field_size);
    BN_bn2binpad(y2, x2y2 + field_size, field_size);

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL)
       goto done;

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (ECDH_KDF_X9_62(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)
        == 0)
        goto done;

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    if (EVP_DigestInit(hash, digest) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, x2y2, field_size) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, msg, msg_len) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0)
        goto done;

    if (EVP_DigestFinal(hash, C3, NULL) == 0)
        goto done;

    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;
    ctext_struct.C3 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size);
    ctext_struct.C2 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len);

    *ciphertext_len = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);

    ASN1_OCTET_STRING_free(ctext_struct.C2);
    ASN1_OCTET_STRING_free(ctext_struct.C3);

    rc = 1;

 done:
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(C3);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}

int SM2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len)
{
    int rc = 0;
    int i;

    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct SM2_Ciphertext_st *sm2_ctext = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;

    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;

    const size_t field_size = EC_field_size(group);
    const int hash_size = EVP_MD_size(digest);

    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;

    if (field_size == 0 || hash_size == 0)
       goto done;

    memset(ptext_buf, 0xFF, *ptext_len);

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

    if (sm2_ctext == NULL)
        goto done;

    if (sm2_ctext->C3->length != hash_size)
        goto done;

    C2 = sm2_ctext->C2->data;
    C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;

    ctx = BN_CTX_new();
    if (ctx == NULL)
       goto done;

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if(y2 == NULL)
       goto done;

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    computed_C3 = OPENSSL_zalloc(hash_size);

    if(msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL)
       goto done;

    C1 = EC_POINT_new(group);
    if (C1 == NULL)
        goto done;

    if (EC_POINT_set_affine_coordinates_GFp
        (group, C1, sm2_ctext->C1x, sm2_ctext->C1y, ctx) == 0)
        goto done;

    if (EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx) ==
        0)
        goto done;

    if (EC_POINT_get_affine_coordinates_GFp(group, C1, x2, y2, ctx) == 0)
        goto done;

    BN_bn2binpad(x2, x2y2, field_size);
    BN_bn2binpad(y2, x2y2 + field_size, field_size);

    if (ECDH_KDF_X9_62(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)
        == 0)
        goto done;

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    hash = EVP_MD_CTX_new();

    if (hash == NULL)
       goto done;

    if (EVP_DigestInit(hash, digest) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, x2y2, field_size) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, ptext_buf, msg_len) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0)
        goto done;

    if (EVP_DigestFinal(hash, computed_C3, NULL) == 0)
        goto done;

    if (memcmp(computed_C3, C3, hash_size) != 0)
        goto done;

    rc = 1;
    *ptext_len = msg_len;

 done:

    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(computed_C3);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    SM2_Ciphertext_free(sm2_ctext);
    EVP_MD_CTX_free(hash);

    return rc;
}
