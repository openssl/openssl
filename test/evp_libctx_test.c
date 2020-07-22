/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*

 * These tests are setup to load null into the default library context.
 * Any tests are expected to use the created 'libctx' to find algorithms.
 * The framework runs the tests twice using the 'default' provider or
 * 'fips' provider as inputs.
 */

/*
 * DSA/DH low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/dsa.h>
#include <openssl/safestack.h>
#include "testutil.h"
#include "internal/nelem.h"
#include "crypto/bn_dh.h"   /* _bignum_ffdhe2048_p */
#include "../e_os.h"        /* strcasecmp */

DEFINE_STACK_OF_CSTRING()

static OPENSSL_CTX *libctx = NULL;
static OSSL_PROVIDER *nullprov = NULL;
static OSSL_PROVIDER *libprov = NULL;
static STACK_OF(OPENSSL_CSTRING) *cipher_names = NULL;

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONFIG_FILE,
    OPT_PROVIDER_NAME,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "config", OPT_CONFIG_FILE, '<',
          "The configuration file to use for the libctx" },
        { "provider", OPT_PROVIDER_NAME, 's',
          "The provider to load (The default value is 'default'" },
        { NULL }
    };
    return test_options;
}

#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_DH)
static const char *getname(int id)
{
    const char *name[] = {"p", "q", "g" };

    if (id >= 0 && id < 3)
        return name[id];
    return "?";
}
#endif

#ifndef OPENSSL_NO_DSA

static int test_dsa_param_keygen(int tstid)
{
    int ret = 0;
    int expected;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY *pkey_parm = NULL;
    EVP_PKEY *pkey = NULL;
    DSA *dsa = NULL;
    int pind, qind, gind;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    /*
     * Just grab some fixed dh p, q, g values for testing,
     * these 'safe primes' should not be used normally for dsa *.
     */
    static const BIGNUM *bn[] = {
        &_bignum_dh2048_256_p,  &_bignum_dh2048_256_q, &_bignum_dh2048_256_g
    };

    /*
     * These tests are using bad values for p, q, g by reusing the values.
     * A value of 0 uses p, 1 uses q and 2 uses g.
     * There are 27 different combinations, with only the 1 valid combination.
     */
    pind = tstid / 9;
    qind = (tstid / 3) % 3;
    gind = tstid % 3;
    expected  = (pind == 0 && qind == 1 && gind == 2);

    TEST_note("Testing with (p, q, g) = (%s, %s, %s)\n", getname(pind),
              getname(qind), getname(gind));

    if (!TEST_ptr(pkey_parm = EVP_PKEY_new())
        || !TEST_ptr(dsa = DSA_new())
        || !TEST_ptr(p = BN_dup(bn[pind]))
        || !TEST_ptr(q = BN_dup(bn[qind]))
        || !TEST_ptr(g = BN_dup(bn[gind]))
        || !TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_true(EVP_PKEY_assign_DSA(pkey_parm, dsa)))
        goto err;
    dsa = NULL;

    if (!TEST_ptr(gen_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey_parm, NULL))
        || !TEST_int_gt(EVP_PKEY_keygen_init(gen_ctx), 0)
        || !TEST_int_eq(EVP_PKEY_keygen(gen_ctx, &pkey), expected))
        goto err;
    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_free(pkey_parm);
    DSA_free(dsa);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
static int do_dh_param_keygen(int tstid, const BIGNUM **bn)
{
    int ret = 0;
    int expected;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY *pkey_parm = NULL;
    EVP_PKEY *pkey = NULL;
    DH *dh = NULL;
    int pind, qind, gind;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    /*
     * These tests are using bad values for p, q, g by reusing the values.
     * A value of 0 uses p, 1 uses q and 2 uses g.
     * There are 27 different combinations, with only the 1 valid combination.
     */
    pind = tstid / 9;
    qind = (tstid / 3) % 3;
    gind = tstid % 3;
    expected  = (pind == 0 && qind == 1 && gind == 2);

    TEST_note("Testing with (p, q, g) = (%s, %s, %s)", getname(pind),
              getname(qind), getname(gind));

    if (!TEST_ptr(pkey_parm = EVP_PKEY_new())
        || !TEST_ptr(dh = DH_new())
        || !TEST_ptr(p = BN_dup(bn[pind]))
        || !TEST_ptr(q = BN_dup(bn[qind]))
        || !TEST_ptr(g = BN_dup(bn[gind]))
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_true(EVP_PKEY_assign_DH(pkey_parm, dh)))
        goto err;
    dh = NULL;

    if (!TEST_ptr(gen_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey_parm, NULL))
        || !TEST_int_gt(EVP_PKEY_keygen_init(gen_ctx), 0)
        || !TEST_int_eq(EVP_PKEY_keygen(gen_ctx, &pkey), expected))
        goto err;
    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_free(pkey_parm);
    DH_free(dh);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    return ret;
}

/*
 * Note that we get the fips186-4 path being run for most of these cases since
 * the internal code will detect that the p, q, g does not match a safe prime
 * group (Except for when tstid = 5, which sets the correct p, q, g)
 */
static int test_dh_safeprime_param_keygen(int tstid)
{
    static const BIGNUM *bn[] = {
        &_bignum_ffdhe2048_p,  &_bignum_ffdhe2048_q, &_bignum_const_2
    };
    return do_dh_param_keygen(tstid, bn);
}
#endif /* OPENSSL_NO_DH */

static int test_cipher_reinit(int test_id)
{
    int ret = 0, out1_len = 0, out2_len = 0, diff, ccm;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char out1[256];
    unsigned char out2[256];
    unsigned char in[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    unsigned char key[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    unsigned char iv[16] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };
    const char *name = sk_OPENSSL_CSTRING_value(cipher_names, test_id);

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
        goto err;

    TEST_note("Fetching %s\n", name);
    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, name, NULL)))
        goto err;

    /* ccm fails on the second update - this matches OpenSSL 1_1_1 behaviour */
    ccm = (EVP_CIPHER_mode(cipher) == EVP_CIPH_CCM_MODE);

    /* DES3-WRAP uses random every update - so it will give a different value */
    diff = EVP_CIPHER_is_a(cipher, "DES3-WRAP");

    if (!TEST_true(EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
        || !TEST_true(EVP_EncryptUpdate(ctx, out1, &out1_len, in, sizeof(in)))
        || !TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        || !TEST_int_eq(EVP_EncryptUpdate(ctx, out2, &out2_len, in, sizeof(in)),
                        ccm ? 0 : 1))
        goto err;

    if (ccm == 0) {
        if (diff) {
            if (!TEST_mem_ne(out1, out1_len, out2, out2_len))
                goto err;
        } else {
            if (!TEST_mem_eq(out1, out1_len, out2, out2_len))
                goto err;
        }
    }
    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int name_cmp(const char * const *a, const char * const *b)
{
    return strcasecmp(*a, *b);
}

static void collect_cipher_names(EVP_CIPHER *cipher, void *cipher_names_list)
{
    STACK_OF(OPENSSL_CSTRING) *names = cipher_names_list;

    sk_OPENSSL_CSTRING_push(names, EVP_CIPHER_name(cipher));
}

int setup_tests(void)
{
    const char *prov_name = "default";
    char *config_file = NULL;
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_PROVIDER_NAME:
            prov_name = opt_arg();
            break;
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            break;
        case OPT_TEST_CASES:
           break;
        default:
        case OPT_ERR:
            return 0;
        }
    }

    nullprov = OSSL_PROVIDER_load(NULL, "null");
    if (!TEST_ptr(nullprov))
        return 0;

    libctx = OPENSSL_CTX_new();

    if (!TEST_ptr(libctx))
        return 0;

    if (config_file != NULL) {
        if (!TEST_true(OPENSSL_CTX_load_config(libctx, config_file)))
            return 0;
    }

    libprov = OSSL_PROVIDER_load(libctx, prov_name);
    if (!TEST_ptr(libprov))
        return 0;

#ifndef OPENSSL_NO_DSA
    ADD_ALL_TESTS(test_dsa_param_keygen, 3 * 3 * 3);
#endif
#ifndef OPENSSL_NO_DH
    ADD_ALL_TESTS(test_dh_safeprime_param_keygen, 3 * 3 * 3);
#endif

    if (!TEST_ptr(cipher_names = sk_OPENSSL_CSTRING_new(name_cmp)))
        return 0;
    EVP_CIPHER_do_all_provided(libctx, collect_cipher_names, cipher_names);

    ADD_ALL_TESTS(test_cipher_reinit, sk_OPENSSL_CSTRING_num(cipher_names));
    return 1;
}

void cleanup_tests(void)
{
    sk_OPENSSL_CSTRING_free(cipher_names);
    OSSL_PROVIDER_unload(libprov);
    OPENSSL_CTX_free(libctx);
    OSSL_PROVIDER_unload(nullprov);
}
