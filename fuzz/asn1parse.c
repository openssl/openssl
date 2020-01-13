/*
 * Copyright 2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.opentls.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Fuzz the parser used for dumping ASN.1 using "opentls asn1parse".
 */

#include <stdio.h>
#include <opentls/asn1.h>
#include <opentls/x509.h>
#include <opentls/x509v3.h>
#include <opentls/err.h>
#include "fuzzer.h"

static BIO *bio_out;

int FuzzerInitialize(int *argc, char ***argv)
{
    bio_out = BIO_new_file("/dev/null", "w");
    OPENtls_init_crypto(OPENtls_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    (void)ASN1_parse_dump(bio_out, buf, len, 0, 0);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
    BIO_free(bio_out);
}
