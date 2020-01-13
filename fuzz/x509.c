/*
 * Copyright 2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.opentls.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <opentls/x509.h>
#include <opentls/bio.h>
#include <opentls/err.h>
#include <opentls/rand.h>
#include "fuzzer.h"

#include "rand.inc"

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENtls_init_crypto(OPENtls_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    FuzzerSetRand();
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const unsigned char *p = buf;
    unsigned char *der = NULL;

    X509 *x509 = d2i_X509(NULL, &p, len);
    if (x509 != NULL) {
        BIO *bio = BIO_new(BIO_s_null());
        /* This will load and print the public key as well as extensions */
        X509_print(bio, x509);
        BIO_free(bio);

        i2d_X509(x509, &der);
        OPENtls_free(der);

        X509_free(x509);
    }
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}
