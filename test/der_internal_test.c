/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the DER writer and reader */

#include <string.h>

#include <openssl/bn.h>
#include "internal/der.h"
#include "internal/nelem.h"
#include "testutil.h"

static int test_write_boolean(void)
{
    /* DER FALSE and TRUE, the only two valid encodings */
    static const unsigned char der_false[] = { 0x01, 0x01, 0x00 };
    static const unsigned char der_true[] = { 0x01, 0x01, 0xFF };
    /* TRUE wrapped in context tag [1]: A1 03 01 01 FF */
    static const unsigned char der_true_ctx[] = {
        0xA1, 0x03, 0x01, 0x01, 0xFF
    };
    unsigned char buf[16];
    int testresult = 0;

    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        int ok = 0;

        if (WPACKET_init_der(&wpkt, buf, sizeof(buf))) {
            ok = ossl_DER_w_boolean(&wpkt, -1, 0)
                && WPACKET_finish(&wpkt)
                && WPACKET_get_total_written(&wpkt, &derlen)
                && (der = WPACKET_get_curr(&wpkt)) != NULL;
            WPACKET_cleanup(&wpkt);
        }
        if (!TEST_true(ok)
            || !TEST_mem_eq(der, derlen, der_false, sizeof(der_false)))
            goto end;
    }

    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        int ok = 0;

        if (WPACKET_init_der(&wpkt, buf, sizeof(buf))) {
            ok = ossl_DER_w_boolean(&wpkt, -1, 1)
                && WPACKET_finish(&wpkt)
                && WPACKET_get_total_written(&wpkt, &derlen)
                && (der = WPACKET_get_curr(&wpkt)) != NULL;
            WPACKET_cleanup(&wpkt);
        }
        if (!TEST_true(ok)
            || !TEST_mem_eq(der, derlen, der_true, sizeof(der_true)))
            goto end;
    }

    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        int ok = 0;

        if (WPACKET_init_der(&wpkt, buf, sizeof(buf))) {
            ok = ossl_DER_w_boolean(&wpkt, 1, 1)
                && WPACKET_finish(&wpkt)
                && WPACKET_get_total_written(&wpkt, &derlen)
                && (der = WPACKET_get_curr(&wpkt)) != NULL;
            WPACKET_cleanup(&wpkt);
        }
        if (!TEST_true(ok)
            || !TEST_mem_eq(der, derlen, der_true_ctx, sizeof(der_true_ctx)))
            goto end;
    }

    testresult = 1;
 end:
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_write_boolean);
    return 1;
}
