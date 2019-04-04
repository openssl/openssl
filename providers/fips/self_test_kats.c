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

#include "../../providers/fips/self_test_data.c"
#include "internal/nelem.h"

static int self_test_digests(ST_EVENT *event);
static int self_test_ciphers(ST_EVENT *event);
static int self_test_signatures(ST_EVENT *event);
static int self_test_drbgs(ST_EVENT *event);

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

    return ret;
}

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
static EVP_PKEY *bin2pkey(const EVP_PKEY_METHOD *meth, ST_KEYDATA *data)
{
    if (meth == &rsa_pkey_meth)
        return rsa_set_pkey(keydata2bn(data, RSA_P),
                            keydata2bn(data, RSA_Q),
                            keydata2bn(data, RSA_N),
                            keydata2bn(data, RSA_E),
                            keydata2bn(data, RSA_D),
                            keydata2bn(data, RSA_DMP1),
                            keydata2bn(data, RSA_DMQ1),
                            keydata2bn(data, RSA_IQMP));
    else if (meth == &ec_pkey_meth)
        return ec_set_pkey(keydata2str(data, EC_CURVE),
                           keydata2bn(data, EC_X),
                           keydata2bn(data, EC_Y),
                           keydata2bn(data, EC_D));
    else if (meth == &dsa_pkey_meth)
        return dsa_set_pkey(keydata2bn(data, DSA_P),
                            keydata2bn(data, DSA_Q),
                            keydata2bn(data, DSA_G),
                            keydata2bn(data, DSA_PUB),
                            keydata2bn(data, DSA_PRIV));
    else
        return NULL;
}

/* Test a single KAT for digest algorithm */
static int self_test_digest(ST_DIGEST *t, ST_EVENT *event)
{
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    unsigned char out[EVP_MAX_MD_SIZE];

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_KAT_DIGEST, t->desc);

    md = EVP_get_digestbyname(t->md_name);
    if (md == NULL)
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;

    if (!md->init(ctx))
        goto end;
    if (!md->update(ctx, t->plaintxt.data, t->plaintxt.len))
        goto end;

    if (!md->final(ctx, out))
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
}

/* Test a single KAT for sign/verify */
static int self_test_sig(ST_SIGNATURE *t, ST_EVENT *event)
{
    int ret = 1;
    const EVP_PKEY_METHOD *meth = t->pkey_meth;
    EVP_PKEY *pkey = NULL;

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_KAT_SIGNATURE, t->desc);

    /* TODO - Add after method layers exist */
    pkey = bin2pkey(meth, t->key_data);

    /* Optional corruption */
    /* SELF_TEST_EVENT_oncorrupt_byte(event, sig); */

    SELF_TEST_EVENT_onend(event, ret);
    EVP_PKEY_free(pkey);
    return ret;
}

/* Test a single KAT for encrypt/decrypt */
static int self_test_cipher(ST_CIPHER *t, ST_EVENT *event)
{
    int ret = 1;
    /* unsigned char out[64]; */

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_KAT_CIPHER, t->desc);

    /* TODO - Add once the method layers exist */
    /* SELF_TEST_EVENT_oncorrupt_byte(event, out); */

    SELF_TEST_EVENT_onend(event, ret);
    return ret;
}

#if 0

/* TODO - once KDF API exists */
static int selt_test_kdf(ST_KDF *t, ST_EVENT *event)
{
    int ret = 0;
    int i;
    const EVP_KDF_METHOD *meth = t->meth;
    void *obj = NULL;
    unsigned char out[64];

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_KAT_KDF, t->desc);

    obj = meth->new();
    for (i = 0; i < OSSL_NELEM(test->ctrls); ++i) {
        if (!meth->ctrl_str(obj, test->ctrls[i].name, test->ctrls[i].value))
            goto end;
    }

    SELF_TEST_EVENT_oncorrupt_byte(event, out);

    meth->derive(obj, out, sizeof(out));

    if (decoded_len != plaintxt_len
            || memcmp(decoded, plaintxt,  decoded_len) != 0) {
        goto err;

    ret = 1;
end:
    meth->free(obj);
    SELF_TEST_EVENT_onend(event, ret);
    return ret;
}
#endif

/* Test a single KAT for encrypt/decrypt */
static int self_test_drbg(ST_DRBG *t, ST_EVENT *event)
{
    int ret = 1;
/*    unsigned char out[64]; */

    SELF_TEST_EVENT_onbegin(event, SELF_TEST_TYPE_DRBG, t->desc);

    /* TODO - Add once the DRBG layers exist */
/*    SELF_TEST_EVENT_oncorrupt_byte(event, out); */

    SELF_TEST_EVENT_onend(event, ret);
    return ret;
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
