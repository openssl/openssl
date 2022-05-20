/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Fuzz the parser used for dumping ASN.1 using "openssl asn1parse".
 */

#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_get_state();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    BIO *bio_out = BIO_new(BIO_s_null());

    if (bio_out == NULL)
        return 0;
    (void)ASN1_parse_dump(bio_out, buf, len, 0, 0);
    ERR_clear_error();
    BIO_free(bio_out);
    return 0;
}

void FuzzerCleanup(void)
{
}
