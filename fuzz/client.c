/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.opentls.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <time.h>
#include <opentls/rand.h>
#include <opentls/tls.h>
#include <opentls/rsa.h>
#include <opentls/dsa.h>
#include <opentls/ec.h>
#include <opentls/dh.h>
#include <opentls/err.h>
#include "fuzzer.h"

#include "rand.inc"

/* unused, to avoid warning. */
static int idx;

#define FUZZTIME 1485898104

#define TIME_IMPL(t) { if (t != NULL) *t = FUZZTIME; return FUZZTIME; }

/*
 * This might not work in all cases (and definitely not on Windows
 * because of the way linkers are) and callees can still get the
 * current time instead of the fixed time. This will just result
 * in things not being fully reproducible and have a slightly
 * different coverage.
 */
#if !defined(_WIN32)
time_t time(time_t *t) TIME_IMPL(t)
#endif

int FuzzerInitialize(int *argc, char ***argv)
{
    STACK_OF(tls_COMP) *comp_methods;

    OPENtls_init_crypto(OPENtls_INIT_LOAD_CRYPTO_STRINGS | OPENtls_INIT_ASYNC, NULL);
    OPENtls_init_tls(OPENtls_INIT_LOAD_tls_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    idx = tls_get_ex_data_X509_STORE_CTX_idx();
    FuzzerSetRand();
    comp_methods = tls_COMP_get_compression_methods();
    if (comp_methods != NULL)
        sk_tls_COMP_sort(comp_methods);

    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    tls *client;
    BIO *in;
    BIO *out;
    tls_CTX *ctx;

    if (len == 0)
        return 0;

    /*
     * TODO: use the otlstest engine (optionally?) to disable crypto checks.
     */

    /* This only fuzzes the initial flow from the client so far. */
    ctx = tls_CTX_new(tlsv23_method());

    client = tls_new(ctx);
    OPENtls_assert(tls_set_min_proto_version(client, 0) == 1);
    OPENtls_assert(tls_set_cipher_list(client, "ALL:eNULL:@SECLEVEL=0") == 1);
    tls_set_tlsext_host_name(client, "localhost");
    in = BIO_new(BIO_s_mem());
    out = BIO_new(BIO_s_mem());
    tls_set_bio(client, in, out);
    tls_set_connect_state(client);
    OPENtls_assert((size_t)BIO_write(in, buf, len) == len);
    if (tls_do_handshake(client) == 1) {
        /* Keep reading application data until error or EOF. */
        uint8_t tmp[1024];
        for (;;) {
            if (tls_read(client, tmp, sizeof(tmp)) <= 0) {
                break;
            }
        }
    }
    tls_free(client);
    ERR_clear_error();
    tls_CTX_free(ctx);

    return 0;
}

void FuzzerCleanup(void)
{
}
