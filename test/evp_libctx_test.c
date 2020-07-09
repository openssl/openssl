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
#include "testutil.h"
#include "internal/nelem.h"
#include "crypto/bn_dh.h"        /* _bignum_ffdhe2048_p */

static OPENSSL_CTX *libctx = NULL;
static OSSL_PROVIDER *nullprov = NULL;
static OSSL_PROVIDER *libprov = NULL;

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
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(libprov);
    OPENSSL_CTX_free(libctx);
    OSSL_PROVIDER_unload(nullprov);
}
