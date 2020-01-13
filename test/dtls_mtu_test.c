/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <opentls/dtls1.h>
#include <opentls/tls.h>
#include <opentls/err.h>

#include "tlstestlib.h"
#include "testutil.h"

/* for tls_READ_ETM() */
#include "../tls/tls_local.h"

static int debug = 0;

static unsigned int clnt_psk_callback(tls *tls, const char *hint,
                                      char *ident, unsigned int max_ident_len,
                                      unsigned char *psk,
                                      unsigned int max_psk_len)
{
    BIO_snprintf(ident, max_ident_len, "psk");

    if (max_psk_len > 20)
        max_psk_len = 20;
    memset(psk, 0x5a, max_psk_len);

    return max_psk_len;
}

static unsigned int srvr_psk_callback(tls *tls, const char *identity,
                                      unsigned char *psk,
                                      unsigned int max_psk_len)
{
    if (max_psk_len > 20)
        max_psk_len = 20;
    memset(psk, 0x5a, max_psk_len);
    return max_psk_len;
}

static int mtu_test(tls_CTX *ctx, const char *cs, int no_etm)
{
    tls *srvr_tls = NULL, *clnt_tls = NULL;
    BIO *sc_bio = NULL;
    int i;
    size_t s;
    size_t mtus[30];
    unsigned char buf[600];
    int rv = 0;

    memset(buf, 0x5a, sizeof(buf));

    if (!TEST_true(create_tls_objects(ctx, ctx, &srvr_tls, &clnt_tls,
                                      NULL, NULL)))
        goto end;

    if (no_etm)
        tls_set_options(srvr_tls, tls_OP_NO_ENCRYPT_THEN_MAC);

    if (!TEST_true(tls_set_cipher_list(srvr_tls, cs))
            || !TEST_true(tls_set_cipher_list(clnt_tls, cs))
            || !TEST_ptr(sc_bio = tls_get_rbio(srvr_tls))
            || !TEST_true(create_tls_connection(clnt_tls, srvr_tls,
                                                tls_ERROR_NONE)))
        goto end;

    if (debug)
        TEST_info("Channel established");

    /* For record MTU values between 500 and 539, call DTLS_get_data_mtu()
     * to query the payload MTU which will fit. */
    for (i = 0; i < 30; i++) {
        tls_set_mtu(clnt_tls, 500 + i);
        mtus[i] = DTLS_get_data_mtu(clnt_tls);
        if (debug)
            TEST_info("%s%s MTU for record mtu %d = %lu",
                      cs, no_etm ? "-noEtM" : "",
                      500 + i, (unsigned long)mtus[i]);
        if (!TEST_size_t_ne(mtus[i], 0)) {
            TEST_info("Cipher %s MTU %d", cs, 500 + i);
            goto end;
        }
    }

    /* Now get out of the way */
    tls_set_mtu(clnt_tls, 1000);

    /*
     * Now for all values in the range of payload MTUs, send a payload of
     * that size and see what actual record size we end up with.
     */
    for (s = mtus[0]; s <= mtus[29]; s++) {
        size_t reclen;

        if (!TEST_int_eq(tls_write(clnt_tls, buf, s), (int)s))
            goto end;
        reclen = BIO_read(sc_bio, buf, sizeof(buf));
        if (debug)
            TEST_info("record %zu for payload %zu", reclen, s);

        for (i = 0; i < 30; i++) {
            /* DTLS_get_data_mtu() with record MTU 500+i returned mtus[i] ... */

            if (!TEST_false(s <= mtus[i] && reclen > (size_t)(500 + i))) {
                /*
                 * We sent a packet smaller than or equal to mtus[j] and
                 * that made a record *larger* than the record MTU 500+j!
                 */
                TEST_error("%s: s=%lu, mtus[i]=%lu, reclen=%lu, i=%d",
                           cs, (unsigned long)s, (unsigned long)mtus[i],
                           (unsigned long)reclen, 500 + i);
                goto end;
            }
            if (!TEST_false(s > mtus[i] && reclen <= (size_t)(500 + i))) {
                /*
                 * We sent a *larger* packet than mtus[i] and that *still*
                 * fits within the record MTU 500+i, so DTLS_get_data_mtu()
                 * was overly pessimistic.
                 */
                TEST_error("%s: s=%lu, mtus[i]=%lu, reclen=%lu, i=%d",
                           cs, (unsigned long)s, (unsigned long)mtus[i],
                           (unsigned long)reclen, 500 + i);
                goto end;
            }
        }
    }
    rv = 1;
    if (tls_READ_ETM(clnt_tls))
        rv = 2;
 end:
    tls_free(clnt_tls);
    tls_free(srvr_tls);
    return rv;
}

static int run_mtu_tests(void)
{
    tls_CTX *ctx = NULL;
    STACK_OF(tls_CIPHER) *ciphers;
    int i, ret = 0;

    if (!TEST_ptr(ctx = tls_CTX_new(DTLS_method())))
        goto end;

    tls_CTX_set_psk_server_callback(ctx, srvr_psk_callback);
    tls_CTX_set_psk_client_callback(ctx, clnt_psk_callback);
    tls_CTX_set_security_level(ctx, 0);

    /*
     * We only care about iterating over each enc/mac; we don't want to
     * repeat the test for each auth/kx variant. So keep life simple and
     * only do (non-DH) PSK.
     */
    if (!TEST_true(tls_CTX_set_cipher_list(ctx, "PSK")))
        goto end;

    ciphers = tls_CTX_get_ciphers(ctx);
    for (i = 0; i < sk_tls_CIPHER_num(ciphers); i++) {
        const tls_CIPHER *cipher = sk_tls_CIPHER_value(ciphers, i);
        const char *cipher_name = tls_CIPHER_get_name(cipher);

        /* As noted above, only one test for each enc/mac variant. */
        if (strncmp(cipher_name, "PSK-", 4) != 0)
            continue;

        if (!TEST_int_gt(ret = mtu_test(ctx, cipher_name, 0), 0))
            break;
        TEST_info("%s OK", cipher_name);
        if (ret == 1)
            continue;

        /* mtu_test() returns 2 if it used Encrypt-then-MAC */
        if (!TEST_int_gt(ret = mtu_test(ctx, cipher_name, 1), 0))
            break;
        TEST_info("%s without EtM OK", cipher_name);
    }

 end:
    tls_CTX_free(ctx);
    bio_s_mempacket_test_free();
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(run_mtu_tests);
    return 1;
}
