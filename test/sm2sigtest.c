/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "testutil.h"

#ifndef OPENSSL_NO_SM2

# include <openssl/sm2.h>

static RAND_METHOD fake_rand;
static const RAND_METHOD *saved_rand;

static uint8_t *fake_rand_bytes = NULL;
static size_t fake_rand_bytes_offset = 0;

static int get_faked_bytes(unsigned char *buf, int num)
{
    int i;

    if (fake_rand_bytes == NULL)
        return saved_rand->bytes(buf, num);

    for (i = 0; i != num; ++i)
        buf[i] = fake_rand_bytes[fake_rand_bytes_offset + i];
    fake_rand_bytes_offset += num;
    return 1;
}

static int start_fake_rand(const char *hex_bytes)
{
    /* save old rand method */
    if (!TEST_ptr(saved_rand = RAND_get_rand_method()))
        return 0;

    fake_rand = *saved_rand;
    /* use own random function */
    fake_rand.bytes = get_faked_bytes;

    fake_rand_bytes = OPENSSL_hexstr2buf(hex_bytes, NULL);
    fake_rand_bytes_offset = 0;

    /* set new RAND_METHOD */
    if (!TEST_true(RAND_set_rand_method(&fake_rand)))
        return 0;
    return 1;
}

static int restore_rand(void)
{
    OPENSSL_free(fake_rand_bytes);
    fake_rand_bytes = NULL;
    fake_rand_bytes_offset = 0;
    if (!TEST_true(RAND_set_rand_method(saved_rand)))
        return 0;
    return 1;
}

static EC_GROUP *create_EC_group(const char *p_hex, const char *a_hex,
                                 const char *b_hex, const char *x_hex,
                                 const char *y_hex, const char *order_hex,
                                 const char *cof_hex)
{
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *g_x = NULL;
    BIGNUM *g_y = NULL;
    BIGNUM *order = NULL;
    BIGNUM *cof = NULL;
    EC_POINT *generator = NULL;
    EC_GROUP *group = NULL;

    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);

    group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    BN_free(p);
    BN_free(a);
    BN_free(b);

    if (group == NULL)
        return NULL;

    generator = EC_POINT_new(group);
    if (generator == NULL)
        return NULL;

    BN_hex2bn(&g_x, x_hex);
    BN_hex2bn(&g_y, y_hex);

    if (EC_POINT_set_affine_coordinates_GFp(group, generator, g_x, g_y, NULL) ==
        0)
        return NULL;

    BN_free(g_x);
    BN_free(g_y);

    BN_hex2bn(&order, order_hex);
    BN_hex2bn(&cof, cof_hex);

    if (EC_GROUP_set_generator(group, generator, order, cof) == 0)
        return NULL;

    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);

    return group;
}


static int test_sm2(const EC_GROUP *group,
                    const char *userid,
                    const char *privkey_hex,
                    const char *message,
                    const char *k_hex, const char *r_hex, const char *s_hex)
{
    const size_t msg_len = strlen(message);
    int ok = -1;
    BIGNUM *priv = NULL;
    EC_POINT *pt = NULL;
    EC_KEY *key = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;

    BN_hex2bn(&priv, privkey_hex);

    key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_KEY_set_private_key(key, priv);

    pt = EC_POINT_new(group);
    EC_POINT_mul(group, pt, priv, NULL, NULL, NULL);
    EC_KEY_set_public_key(key, pt);

    start_fake_rand(k_hex);
    sig = SM2_do_sign(key, EVP_sm3(), userid, (const uint8_t *)message, msg_len);
    restore_rand();

    if (sig == NULL)
        return 0;

    ECDSA_SIG_get0(sig, &sig_r, &sig_s);

    BN_hex2bn(&r, r_hex);
    BN_hex2bn(&s, s_hex);

    if (BN_cmp(r, sig_r) != 0) {
        printf("Signature R mismatch: ");
        BN_print_fp(stdout, r);
        printf(" != ");
        BN_print_fp(stdout, sig_r);
        printf("\n");
        ok = 0;
    }
    if (BN_cmp(s, sig_s) != 0) {
        printf("Signature S mismatch: ");
        BN_print_fp(stdout, s);
        printf(" != ");
        BN_print_fp(stdout, sig_s);
        printf("\n");
        ok = 0;
    }

    ok = SM2_do_verify(key, EVP_sm3(), sig, userid, (const uint8_t *)message, msg_len);

    ECDSA_SIG_free(sig);
    EC_POINT_free(pt);
    EC_KEY_free(key);
    BN_free(priv);
    BN_free(r);
    BN_free(s);

    return ok;
}

static int sm2_sig_test(void)
{
    int rc = 0;
    /* From draft-shen-sm2-ecdsa-02 */
    EC_GROUP *test_group =
        create_EC_group
        ("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
         "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
         "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
         "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
         "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
         "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
         "1");

    if (test_group == NULL)
        return 0;

    rc = test_sm2(test_group,
                    "ALICE123@YAHOO.COM",
                    "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
                    "message digest",
                    "006CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",
                    "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1",
                    "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7");

    EC_GROUP_free(test_group);

    return rc;
}

#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_SM2
    TEST_note("SM2 is disabled.");
#else
    ADD_TEST(sm2_sig_test);
#endif
    return 1;
}
