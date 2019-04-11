/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

#include "self_test_data.c"
#include "internal/nelem.h"

static int self_test_digests(ST_EVENT *event);
static int self_test_ciphers(ST_EVENT *event);
static int self_test_signatures(ST_EVENT *event);
static int self_test_drbgs(ST_EVENT *event);
static int self_test_kdfs(ST_EVENT *event);

/*
 * Run the algorithm KAT's.
 * Return 1 is successful, otherwise return 0.
 * This runs all the tests regardless of if any fail.
 */
int self_test_kats(ST_EVENT *event)
{
    int ret = 1;

    if (!self_test_digests(event))
        ret = 0;
    if (!self_test_ciphers(event))
        ret = 0;
    if (!self_test_signatures(event))
        ret = 0;
    if (!self_test_drbgs(event))
        ret = 0;
    if (!self_test_kdfs(event))
        ret = 0;
    return ret;
}

#if 0

/* Utility function to setup a EC EVP_PKEY */
static EVP_PKEY *ec_set_pkey(const char *curve, BIGNUM *x, BIGNUM *y,
                             BIGNUM *priv)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec = NULL;

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto err;

    ec = EC_KEY_new_by_curve_name(OBJ_sn2nid(curve));
    if (ec == NULL
            || !EC_KEY_set_public_key_affine_coordinates(ec, x, y)
            || !EC_KEY_set_private_key(ec, priv))
        goto err;

    EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec);
    return pkey;

err:
    EC_KEY_free(ec);
    EVP_PKEY_free(pkey);
    return NULL;
}

/* Utility function to setuo a RSA EVP_PKEY */
static EVP_PKEY *rsa_set_pkey(BIGNUM *p, BIGNUM *q,
                              BIGNUM *n, BIGNUM *e, BIGNUM *d,
                              BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto err;

    rsa  = RSA_new();
    if (rsa == NULL
            || !RSA_set0_key(rsa, n, e, d)
            || !RSA_set0_factors(rsa, p, q)
            || !RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp))
        goto err;
    EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
    return pkey;

err:
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    return NULL;
}

/* Utility function to setup a DSA EVP_KEY */
static EVP_PKEY *dsa_set_pkey(BIGNUM *p, BIGNUM *q, BIGNUM *g,
                              BIGNUM *pub, BIGNUM *priv)
{
    EVP_PKEY *pkey = NULL;
    DSA *dsa = NULL;

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto err;

    dsa  = DSA_new();
    if (dsa == NULL
            || !DSA_set0_pqg(dsa, p, q, g)
            || !DSA_set0_key(dsa, pub, priv))
        goto err;

    EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa);
    return pkey;

err:
    DSA_free(dsa);
    EVP_PKEY_free(pkey);
    return NULL;
}

/* Utility function to find keydata by id and convert to a BIGNUM */
static BIGNUM *keydata2bn(ST_KEYDATA *list, int id)
{
    int i;

    for (i = 0; list[i].key.data != NULL; ++i) {
        if (list[i].id == id)
            return BN_bin2bn(list[i].key.data, list[i].key.len, NULL);
    }
    return NULL;
}

/* Utility function to find keydata by id and convert to a string */
static const char *keydata2str(ST_KEYDATA *list, int id)
{
    int i;

    for (i = 0; list[i].key.data != NULL; ++i) {
        if (list[i].id == id)
            return (const char *)list[i].key.data;
    }
    return NULL;
}

/* Utility function to load a EVP_KEY from binary key data */
static EVP_PKEY *bin2pkey(int id, ST_KEYDATA *data)
{
    if (id == EVP_PKEY_RSA)
        return rsa_set_pkey(keydata2bn(data, RSA_P),
                            keydata2bn(data, RSA_Q),
                            keydata2bn(data, RSA_N),
                            keydata2bn(data, RSA_E),
                            keydata2bn(data, RSA_D),
                            keydata2bn(data, RSA_DMP1),
                            keydata2bn(data, RSA_DMQ1),
                            keydata2bn(data, RSA_IQMP));
    else if (id == EVP_PKEY_EC)
        return ec_set_pkey(keydata2str(data, EC_CURVE),
                           keydata2bn(data, EC_X),
                           keydata2bn(data, EC_Y),
                           keydata2bn(data, EC_D));
    else if (id == EVP_PKEY_DSA)
        return dsa_set_pkey(keydata2bn(data, DSA_P),
                            keydata2bn(data, DSA_Q),
                            keydata2bn(data, DSA_G),
                            keydata2bn(data, DSA_PUB),
                            keydata2bn(data, DSA_PRIV));
    else
        return NULL;
}
#endif

/* Test a single KAT for digest algorithm */
static int self_test_digest(ST_DIGEST *t, ST_EVENT *event)
{
#if 0
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    unsigned char out[EVP_MAX_MD_SIZE];

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_KAT_DIGEST, t->desc);

    md = EVP_get_digestbyname(t->md_name);
    if (md == NULL)
        goto end;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto end;

    if (!(EVP_DigestInit(ctx, md)
          && EVP_DigestUpdate(ctx, t->plaintxt.data, t->plaintxt.len)
          && EVP_DigestFinal(ctx, out, NULL)))
        goto end;

    /* Optional corruption */
    SELF_TEST_EVENT_oncorrupt_byte(event, out);

    if (memcmp(t->expected.data, out, t->expected.len) != 0)
        goto end;
    ret = 1;
end:
    SELF_TEST_EVENT_onend(event, ret);

    EVP_MD_CTX_free(ctx);
    return ret;
#else
    return 1;
#endif
}

/* Test a single KAT for sign/verify */
static int self_test_sig(ST_SIGNATURE *t, ST_EVENT *event)
{
#if 0
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    size_t out_len = 0;
    unsigned char out[256];

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_KAT_SIGNATURE, t->desc);

    pkey = bin2pkey(t->id, t->key_data);

    md = EVP_get_digestbyname(t->md_name);
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || md == NULL)
        goto end;

    if (!(EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) > 0
          && EVP_DigestSignUpdate(ctx, t->msg.data, t->msg.len) > 0
          && EVP_DigestSignFinal(ctx, NULL, &out_len) > 0
          && EVP_DigestSignFinal(ctx, out, &out_len) > 0))
        goto end;

    /* Optional corruption */
    SELF_TEST_EVENT_oncorrupt_byte(event, out);

    if (!(EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) > 0
          && EVP_DigestVerifyUpdate(ctx, t->msg.data, t->msg.len) > 0
          && EVP_DigestVerifyFinal(ctx, out, out_len) > 0))
        goto end;
    ret = 1;
end:
    SELF_TEST_EVENT_onend(event, ret);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    return ret;
#else
    return 1;
#endif
}

#if 0
/*
 * Helper function to setup a EVP_CipherInit
 * Used to hide the complexity of Authenticated ciphers.
 */
static int cipher_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ST_CIPHER *t, int enc)
{
    unsigned char *in_tag = NULL;
    int pad = 0, tmp;

    /* Flag required for Key wrapping */
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (t->tag.data == NULL) {
        /* Use a normal cipher init */
        return EVP_CipherInit_ex(ctx, cipher, NULL, t->key.data, t->iv.data, enc)
               && EVP_CIPHER_CTX_set_padding(ctx, pad);
    }

    /* The authenticated cipher init */
    if (!enc)
        in_tag = (unsigned char *)t->tag.data;

    return EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc)
           && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, t->iv.len, NULL)
           && (in_tag == NULL
               || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, t->tag.len,
                                      in_tag))
           && EVP_CipherInit_ex(ctx, NULL, NULL, t->key.data, NULL, enc)
           && EVP_CIPHER_CTX_set_padding(ctx, pad)
           && EVP_CipherUpdate(ctx, NULL, &tmp, t->add.data, t->add.len);
}
#endif

/* Test a single KAT for encrypt/decrypt */
static int self_test_cipher(ST_CIPHER *t, ST_EVENT *event)
{
#if 0
    int ret = 0, encrypt = 1, len, ct_len, pt_len;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    unsigned char ct_buf[256] = { 0 };
    unsigned char pt_buf[256] = { 0 };

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_KAT_CIPHER, t->desc);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto end;
    cipher = EVP_get_cipherbyname(t->name);
    if (cipher == NULL)
        goto end;

    /* Encrypt plain text message */
    if (!(cipher_init(ctx, cipher, t, encrypt)
          && EVP_CipherUpdate(ctx, ct_buf, &len, t->plaintxt.data,
                              t->plaintxt.len)
          && EVP_CipherFinal_ex(ctx, ct_buf + len, &ct_len)))
        goto end;

    if (ct_len != t->ciphertxt.len
        || memcmp(t->ciphertxt.data, ct_buf, ct_len) != 0)
        goto end;

    if (t->tag.data != NULL) {
        unsigned char tag[16] = {0};

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, t->tag.len, tag)
            || memcmp(tag, t->tag.data, t->tag.len) != 0)
            goto end;
    }

    if (!(cipher_init(ctx, cipher, t, !encrypt)
          && EVP_CipherUpdate(ctx, pt_buf, &len, ct_buf, ct_len)
          && EVP_CipherFinal_ex(ctx, pt_buf + len, &pt_len)))
        goto end;
    pt_len += len;

    SELF_TEST_EVENT_oncorrupt_byte(event, ct_buf);

    if (pt_len != t->plaintxt.len
        || memcmp(pt_buf, t->plaintxt.data, pt_len) != 0)
        goto end;

    ret = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    SELF_TEST_EVENT_onend(event, ret);
    return ret;
#else
    return 1;
#endif
}

static int self_test_kdf(ST_KDF *t, ST_EVENT *event)
{
#if 0
    EVP_KDF_CTX *ctx = NULL;
    int ret = 0;
    int i;
    void *obj = NULL;
    unsigned char out[64];

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_KAT_KDF, t->desc);

    ctx = EVP_KDF_CTX_new_id(t->id);
    if (ctx == NULL)
        goto end;

    for (i = 0; i < OSSL_NELEM(test->ctrls); ++i) {
        if (EVP_KDF_ctrl_str(ctx, test->ctrls[i].name,
                             test->ctrls[i].value) <= 0)
            goto end;
    }

    SELF_TEST_EVENT_oncorrupt_byte(event, out);

    if (EVP_KDF_derive(ctx, out, sizeof(out)) <= 0)
        goto end;

    if (decoded_len != plaintxt_len
        || memcmp(decoded, plaintxt,  decoded_len) != 0)
        goto err;

    ret = 1;
end:
    EVP_KDF_CTX_free(ctx);
    SELF_TEST_EVENT_onend(event, ret);
    return ret;
#else
    return 1;
#endif
}

/* Test a single KAT for encrypt/decrypt */
static int self_test_drbg(ST_DRBG *t, ST_EVENT *event)
{
#if 0
    int ret = 1;
/*    unsigned char out[64]; */

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_DRBG, t->desc);

    /* TODO - Add once the DRBG layers exist */
/*    SELF_TEST_EVENT_oncorrupt_byte(event, out); */

    SELF_TEST_EVENT_onend(event, ret);
    return ret;
#else
    return 1;
#endif
}
/*
 * Test a data driven list of KAT for digest algorithms.
 * All tests are run regardless of if they fail or not.
 * Return 0 if any test fails.
 */
static int self_test_digests(ST_EVENT *event)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(digest_tests); ++i) {
        if (!self_test_digest(&digest_tests[i], event))
            ret = 0;
    }
    return ret;
}

/*
 * Test a data driven list of KAT for encrypt/decrypt operations.
 * All tests are run regardless of if they fail or not.
 * Return 0 if any test fails.
 */
static int self_test_ciphers(ST_EVENT *event)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(cipher_tests); ++i) {
        if (!self_test_cipher(&cipher_tests[i], event))
            ret = 0;
    }
    return ret;
}

/*
 * Test a data driven list of KAT for signature algorithms.
 * All tests are run regardless of if they fail or not.
 * Return 0 if any test fails.
 */
static int self_test_signatures(ST_EVENT *event)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(signature_tests); ++i) {
        if (!self_test_sig(&signature_tests[i], event))
            ret = 0;
    }
    return ret;
}

/*
 * Test a data driven list of KAT for DRBG's.
 * All tests are run regardless of if they fail or not.
 * Return 0 if any test fails.
 */
static int self_test_drbgs(ST_EVENT *event)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(drbg_tests); ++i) {
        if (!self_test_drbg(&drbg_tests[i], event))
            ret = 0;
    }
    return ret;
}

static int self_test_kdfs(ST_EVENT *event)
{
    int i, ret = 1;

    for (i = 0; i < (int)OSSL_NELEM(kdf_tests); ++i) {
        if (!self_test_kdf(&kdf_tests[i], event))
            ret = 0;
    }
    return ret;
}
