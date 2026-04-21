/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Test PKCS12 parsing with fuzzed input.
 */

#include "internal/deprecated.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);

    return 1;
}

static void fuzz_pkcs12_parse(PKCS12 *p12, const char *pass)
{
    PKCS12_PARSE_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    ctx = PKCS12_PARSE_CTX_new();
    if (ctx == NULL)
        return;
    PKCS12_PARSE_CTX_set_pkey(ctx, &pkey);
    PKCS12_PARSE_CTX_set_cert(ctx, &cert);
    PKCS12_PARSE_CTX_set_ca(ctx, &ca);
    PKCS12_parse_ex(p12, pass, ctx, NULL, NULL);
    PKCS12_PARSE_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    PKCS12 *p12;
    BIO *in;

    if (len == 0 || len > INT_MAX)
        return 0;

    in = BIO_new(BIO_s_mem());
    OPENSSL_assert((size_t)BIO_write(in, buf, (int)len) == len);
    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 != NULL) {
        PKCS12_verify_mac(p12, NULL, 0);
        PKCS12_verify_mac(p12, "", 0);

        fuzz_pkcs12_parse(p12, NULL);
        fuzz_pkcs12_parse(p12, "");

        PKCS12_free(p12);
    }

    BIO_free(in);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}
