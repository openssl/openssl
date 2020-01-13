/*
 * Copyright 2017-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>

#include "tlstestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

#define TEST_PLAINTEXT_OVERFLOW_OK      0
#define TEST_PLAINTEXT_OVERFLOW_NOT_OK  1
#define TEST_ENCRYPTED_OVERFLOW_TLS1_3_OK       2
#define TEST_ENCRYPTED_OVERFLOW_TLS1_3_NOT_OK   3
#define TEST_ENCRYPTED_OVERFLOW_TLS1_2_OK       4
#define TEST_ENCRYPTED_OVERFLOW_TLS1_2_NOT_OK   5

#define TOTAL_RECORD_OVERFLOW_TESTS 6

static int write_record(BIO *b, size_t len, int rectype, int recversion)
{
    unsigned char header[tls3_RT_HEADER_LENGTH];
    size_t written;
    unsigned char buf[256];

    memset(buf, 0, sizeof(buf));

    header[0] = rectype;
    header[1] = (recversion >> 8) & 0xff;
    header[2] = recversion & 0xff;
    header[3] = (len >> 8) & 0xff;
    header[4] = len & 0xff;

    if (!BIO_write_ex(b, header, tls3_RT_HEADER_LENGTH, &written)
            || written != tls3_RT_HEADER_LENGTH)
        return 0;

    while (len > 0) {
        size_t outlen;

        if (len > sizeof(buf))
            outlen = sizeof(buf);
        else
            outlen = len;

        if (!BIO_write_ex(b, buf, outlen, &written)
                || written != outlen)
            return 0;

        len -= outlen;
    }

    return 1;
}

static int fail_due_to_record_overflow(int enc)
{
    long err = ERR_peek_error();
    int reason;

    if (enc)
        reason = tls_R_ENCRYPTED_LENGTH_TOO_LONG;
    else
        reason = tls_R_DATA_LENGTH_TOO_LONG;

    if (ERR_GET_LIB(err) == ERR_LIB_tls
            && ERR_GET_REASON(err) == reason)
        return 1;

    return 0;
}

static int test_record_overflow(int idx)
{
    tls_CTX *cctx = NULL, *sctx = NULL;
    tls *clienttls = NULL, *servertls = NULL;
    int testresult = 0;
    size_t len = 0;
    size_t written;
    int overf_expected;
    unsigned char buf;
    BIO *serverbio;
    int recversion;

#ifdef OPENtls_NO_TLS1_2
    if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_OK
            || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_NOT_OK)
        return 1;
#endif
#ifdef OPENtls_NO_TLS1_3
    if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_OK
            || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_NOT_OK)
        return 1;
#endif

    ERR_clear_error();

    if (!TEST_true(create_tls_ctx_pair(TLS_server_method(), TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_OK
            || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_NOT_OK) {
        len = tls3_RT_MAX_ENCRYPTED_LENGTH;
#ifndef OPENtls_NO_COMP
        len -= tls3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
        tls_CTX_set_max_proto_version(sctx, TLS1_2_VERSION);
    } else if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_OK
               || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_NOT_OK) {
        len = tls3_RT_MAX_TLS13_ENCRYPTED_LENGTH;
    }

    if (!TEST_true(create_tls_objects(sctx, cctx, &servertls, &clienttls,
                                      NULL, NULL)))
        goto end;

    serverbio = tls_get_rbio(servertls);

    if (idx == TEST_PLAINTEXT_OVERFLOW_OK
            || idx == TEST_PLAINTEXT_OVERFLOW_NOT_OK) {
        len = tls3_RT_MAX_PLAIN_LENGTH;

        if (idx == TEST_PLAINTEXT_OVERFLOW_NOT_OK)
            len++;

        if (!TEST_true(write_record(serverbio, len,
                                    tls3_RT_HANDSHAKE, TLS1_VERSION)))
            goto end;

        if (!TEST_int_le(tls_accept(servertls), 0))
            goto end;

        overf_expected = (idx == TEST_PLAINTEXT_OVERFLOW_OK) ? 0 : 1;
        if (!TEST_int_eq(fail_due_to_record_overflow(0), overf_expected))
            goto end;

        goto success;
    }

    if (!TEST_true(create_tls_connection(servertls, clienttls,
                                         tls_ERROR_NONE)))
        goto end;

    if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_NOT_OK
            || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_NOT_OK) {
        overf_expected = 1;
        len++;
    } else {
        overf_expected = 0;
    }

    recversion = TLS1_2_VERSION;

    if (!TEST_true(write_record(serverbio, len, tls3_RT_APPLICATION_DATA,
                                recversion)))
        goto end;

    if (!TEST_false(tls_read_ex(servertls, &buf, sizeof(buf), &written)))
        goto end;

    if (!TEST_int_eq(fail_due_to_record_overflow(1), overf_expected))
        goto end;

 success:
    testresult = 1;

 end:
    tls_free(servertls);
    tls_free(clienttls);
    tls_CTX_free(sctx);
    tls_CTX_free(cctx);
    return testresult;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!TEST_ptr(cert = test_get_argument(0))
            || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_record_overflow, TOTAL_RECORD_OVERFLOW_TESTS);
    return 1;
}

void cleanup_tests(void)
{
    bio_s_mempacket_test_free();
}
