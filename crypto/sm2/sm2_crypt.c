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
#include "internal/ec_int.h" /* ecdh_KDF_X9_63() */
#include <openssl/err.h>
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

static size_t ec_field_size(const EC_GROUP *group)
{
    /* Is there some simpler way to do this? */
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    size_t field_size = 0;

    if (p == NULL || a == NULL || b == NULL)
       goto done;

    if (!EC_GROUP_get_curve(group, p, a, b, NULL))
        goto done;
    field_size = (BN_num_bits(p) + 7) / 8;

 done:
    BN_free(p);
    BN_free(a);
    BN_free(b);

    return field_size;
}

int sm2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                       size_t *pt_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t overhead;

    if (md_size < 0) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_DIGEST);
        return 0;
    }
    if (field_size == 0) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_FIELD);
        return 0;
    }

    overhead = 10 + 2 * field_size + (size_t)md_size;
    if (msg_len <= overhead) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_ENCODING);
        return 0;
    }

    *pt_size = msg_len - overhead;
    return 1;
}

int sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t sz;

    if (field_size == 0 || md_size < 0)
        return 0;

    /* Integer and string are simple type; set constructed = 0, means primitive and definite length encoding. */
    sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
         + ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
         + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
    /* Sequence is structured type; set constructed = 1, means constructed and definite length encoding. */
    *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

    return 1;
}

int sm2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len, uint8_t *ciphertext_buf, size_t *ciphertext_len)
{
    int rc = 0, ciphertext_leni;
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
    size_t field_size;
    const int C3_size = EVP_MD_size(digest);

    /* NULL these before any "goto done" */
    ctext_struct.C2 = NULL;
    ctext_struct.C3 = NULL;

    if (hash == NULL || C3_size <= 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    field_size = ec_field_size(group);
    if (field_size == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_BN_LIB);
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    C3 = OPENSSL_zalloc(C3_size);

    if (x2y2 == NULL || C3 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memset(ciphertext_buf, 0, *ciphertext_len);

    if (!BN_priv_rand_range(k, order)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                        digest)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    if (EVP_DigestInit(hash, digest) == 0
            || EVP_DigestUpdate(hash, x2y2, field_size) == 0
            || EVP_DigestUpdate(hash, msg, msg_len) == 0
            || EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0
            || EVP_DigestFinal(hash, C3, NULL) == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;
    ctext_struct.C3 = ASN1_OCTET_STRING_new();
    ctext_struct.C2 = ASN1_OCTET_STRING_new();

    if (ctext_struct.C3 == NULL || ctext_struct.C2 == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
    }
    if (!ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size)
            || !ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);
    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    rc = 1;

 done:
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(C3);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}

int sm2_decrypt(const EC_KEY *key,
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
    const size_t field_size = ec_field_size(group);
    const int hash_size = EVP_MD_size(digest);
    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;

    if (field_size == 0 || hash_size <= 0)
       goto done;

    memset(ptext_buf, 0xFF, *ptext_len);

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

    if (sm2_ctext == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_ASN1_ERROR);
        goto done;
    }

    if (sm2_ctext->C3->length != hash_size) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_ENCODING);
        goto done;
    }

    C2 = sm2_ctext->C2->data;
    C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_BN_LIB);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    computed_C3 = OPENSSL_zalloc(hash_size);

    if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x,
                                         sm2_ctext->C1y, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key),
                             ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                               digest)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, x2y2, field_size)
            || !EVP_DigestUpdate(hash, ptext_buf, msg_len)
            || !EVP_DigestUpdate(hash, x2y2 + field_size, field_size)
            || !EVP_DigestFinal(hash, computed_C3, NULL)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_DIGEST);
        goto done;
    }

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

#ifndef OPENSSL_NO_CNSM
/* GM/T003_2012 Defined Key Derive Function */
int kdf_gmt003_2012(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *SharedInfo, size_t SharedInfolen, const EVP_MD *md)
{
    EVP_MD_CTX *mctx = NULL;
    unsigned int counter;
    unsigned char ctr[4];
    size_t mdlen;
    int retval = 0;

    if (!out || !outlen) return retval;
    if (md == NULL) md = EVP_sm3();
    mdlen = EVP_MD_size(md);
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        SM2err(SM2_F_KDF_GMT003_2012, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (counter = 1;; counter++)
    {
        unsigned char dgst[EVP_MAX_MD_SIZE];

        EVP_DigestInit(mctx, md);
        ctr[0] = (unsigned char)((counter >> 24) & 0xFF);
        ctr[1] = (unsigned char)((counter >> 16) & 0xFF);
        ctr[2] = (unsigned char)((counter >> 8) & 0xFF);
        ctr[3] = (unsigned char)(counter & 0xFF);
        if (!EVP_DigestUpdate(mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(mctx, SharedInfo, SharedInfolen))
            goto err;
        if (!EVP_DigestFinal(mctx, dgst, NULL))
            goto err;

        if (outlen > mdlen)
        {
            memcpy(out, dgst, mdlen);
            out += mdlen;
            outlen -= mdlen;
        }
        else
        {
            memcpy(out, dgst, outlen);
            memset(dgst, 0, mdlen);
            break;
        }
    }

    retval = 1;

err:
    EVP_MD_CTX_free(mctx);
    return retval;
}


int SM2Kap_compute_key(void *out, size_t outlen, int server,\
    const char *peer_uid, int peer_uid_len, const char *self_uid, int self_uid_len, \
    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key, const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, \
    const EVP_MD *md)
{
    BN_CTX *ctx = NULL;
    EC_POINT *UorV = NULL;
    const EC_POINT *Rs, *Rp;
    BIGNUM *Xs = NULL, *Xp = NULL, *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key, *r;
    const EC_GROUP *group;
    int w;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if (outlen > INT_MAX)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!peer_pub_key || !self_eckey)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    
    priv_key = EC_KEY_get0_private_key(self_eckey);
    if (!priv_key)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!peer_ecdhe_key || !self_ecdhe_key)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    Rs = EC_KEY_get0_public_key(self_ecdhe_key);
    Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
    r = EC_KEY_get0_private_key(self_ecdhe_key);

    if (!Rs || !Rp || !r)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ctx = BN_CTX_new();
    Xs = BN_new();
    Xp = BN_new();
    h = BN_new();
    t = BN_new();
    two_power_w = BN_new();
    order = BN_new();

    if (!Xs || !Xp || !h || !t || !two_power_w || !order)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    group = EC_KEY_get0_group(self_eckey);

    /*Second: Caculate -- w*/
    if (!EC_GROUP_get_order(group, order, ctx) || !EC_GROUP_get_cofactor(group, h, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    UorV = EC_POINT_new(group);

    if (!UorV)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*Test peer public key On curve*/
    if (!EC_POINT_is_on_curve(group, Rp, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Get x*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rs, Xs, NULL, ctx))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rp, Xp, NULL, ctx))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    /*x mod 2 ^ w*/
    /*Caculate Self x*/
    if (!BN_nnmod(Xs, Xs, two_power_w, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xs, Xs, two_power_w))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Caculate Peer x*/
    if (!BN_nnmod(Xp, Xp, two_power_w, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xp, Xp, two_power_w))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Forth: Caculate t*/
    if (!BN_mod_mul(t, Xs, r, order, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(t, t, priv_key, order, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Fifth: Caculate V or U*/
    if (!BN_mul(t, t, h, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /* [x]R */
    if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /* P + [x]R */
    if (!EC_POINT_add(group, UorV, UorV, EC_KEY_get0_public_key(peer_pub_key), ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /* Detect UorV is in */
    if (EC_POINT_is_at_infinity(group, UorV))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/
    {
        /*
        size_t buflen, len;
        unsigned char *buf = NULL;
        */
        size_t elemet_len, idx;

        elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
        buflen = elemet_len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
        buf = (unsigned char *)OPENSSL_malloc(buflen + 10);
        if (!buf)
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        memset(buf, 0, buflen + 10);

        /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
        idx = EC_POINT_point2oct(group, UorV, 4, buf, buflen, ctx);
        if (!idx)
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!server)
        {
            /*SIDE A*/
            len = buflen - idx;
            if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)self_uid, self_uid_len, self_eckey))
            {
                goto err;
            }
            len = 32;
            idx += len;
        }

        /*Caculate Peer Z*/
        len = buflen - idx;
	  if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)peer_uid, peer_uid_len, peer_pub_key))
            {
                goto err;
            }
        len = 32;
        idx += len;

        if (server)
        {
            /*SIDE B*/
            len = buflen - idx;
	     if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)self_uid, self_uid_len, self_eckey))
            {
                goto err;
            }
	     len = 32;
            idx += len;
        }

        len = outlen;
        if (!kdf_gmt003_2012(out, len, (const unsigned char *)(buf + 1), idx - 1, NULL, 0, md))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    ret = outlen;

err:
    if (Xs) BN_free(Xs);
    if (Xp) BN_free(Xp);
    if (h) BN_free(h);
    if (t) BN_free(t);
    if (two_power_w) BN_free(two_power_w);
    if (order) BN_free(order);
    if (UorV) EC_POINT_free(UorV);
    if (buf) OPENSSL_free(buf);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}
#endif
