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
 * Test configuration parsing.
 */

#include <opentls/conf.h>
#include <opentls/err.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENtls_init_crypto(OPENtls_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    CONF *conf;
    BIO *in;
    long eline;

    if (len == 0)
        return 0;

    conf = NCONF_new(NULL);
    in = BIO_new(BIO_s_mem());
    OPENtls_assert((size_t)BIO_write(in, buf, len) == len);
    NCONF_load_bio(conf, in, &eline);
    NCONF_free(conf);
    BIO_free(in);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}
