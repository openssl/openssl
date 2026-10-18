/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include "fuzzer.h"

#define MAX_INPUT_SIZE 16384
#define MAX_LOADS 4

#define MODE_EXPECT_MASK 7u
#define MODE_INPUT_SHIFT 3u
#define MODE_INPUT_MASK 3u

/*
 * OSSL_STORE_INFO_NAME is excluded, because it links
 * to other files/URIs which wouldn't be practical for fuzzing.
 */
static const int expected_types[] = {
    0, /* any */
    OSSL_STORE_INFO_PARAMS,
    OSSL_STORE_INFO_PUBKEY,
    OSSL_STORE_INFO_PKEY,
    OSSL_STORE_INFO_CERT,
    OSSL_STORE_INFO_CRL,
    OSSL_STORE_INFO_SKEY,
    0, /* any */
};

int FuzzerInitialize(int *argc, char ***argv)
{
    FuzzerSetRand();
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    BIO *in = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    const OSSL_PARAM *attach_params = NULL;
    char *input_type = NULL;
    unsigned int mode = 0;
    int expected_type = 0;
    size_t i;

    if (len < 2 || len > MAX_INPUT_SIZE)
        return 0;

    /*
     * The first input byte selects the STORE configuration:
     *   mode bits 0-2: any, params, pubkey, pkey, cert, crl, skey, any
     */
    expected_type = expected_types[buf[0] & MODE_EXPECT_MASK];
    /*
     *  mode bits 3-4: auto, PEM, DER, auto
     */
    mode = ((buf[0] >> MODE_INPUT_SHIFT) & MODE_INPUT_MASK);
    input_type = mode == 1u ? "PEM" : mode == 2u ? "DER"
                                                 : NULL;
    buf++;
    len--;

    if (input_type != NULL) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE, input_type, 0);
        attach_params = params;
    }

    in = BIO_new_mem_buf(buf, (int)len);
    if (in == NULL)
        goto end;

    ctx = OSSL_STORE_attach(in, "file", NULL, NULL, UI_null(), NULL,
        attach_params, NULL, NULL);
    if (ctx == NULL)
        goto end;

    if (!OSSL_STORE_expect(ctx, expected_type))
        goto end;

    for (i = 0; i < MAX_LOADS && !OSSL_STORE_eof(ctx); i++) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);

        if (info == NULL) {
            if (OSSL_STORE_error(ctx))
                break;
            continue;
        }

        switch (OSSL_STORE_INFO_get_type(info)) {
        case OSSL_STORE_INFO_NAME:
            OPENSSL_free(OSSL_STORE_INFO_get1_NAME(info));
            OPENSSL_free(OSSL_STORE_INFO_get1_NAME_description(info));
            break;
        case OSSL_STORE_INFO_PARAMS:
            EVP_PKEY_free(OSSL_STORE_INFO_get1_PARAMS(info));
            break;
        case OSSL_STORE_INFO_PUBKEY:
            EVP_PKEY_free(OSSL_STORE_INFO_get1_PUBKEY(info));
            break;
        case OSSL_STORE_INFO_PKEY:
            EVP_PKEY_free(OSSL_STORE_INFO_get1_PKEY(info));
            break;
        case OSSL_STORE_INFO_CERT:
            X509_free(OSSL_STORE_INFO_get1_CERT(info));
            break;
        case OSSL_STORE_INFO_CRL:
            X509_CRL_free(OSSL_STORE_INFO_get1_CRL(info));
            break;
        case OSSL_STORE_INFO_SKEY:
            EVP_SKEY_free(OSSL_STORE_INFO_get1_SKEY(info));
            break;
        default:
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

end:
    OSSL_STORE_close(ctx);
    BIO_free(in);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
    FuzzerClearRand();
}
