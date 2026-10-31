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
#include <openssl/cms.h>
#include <openssl/err.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    BIO *indata = NULL;
    BIO *out = NULL;
    CMS_ContentInfo *cms = NULL;
    const unsigned char *in;
    size_t consumed;
    size_t remaining;

    if (len > LONG_MAX)
        return 0;

    in = buf;
    cms = d2i_CMS_ContentInfo(NULL, &in, (long)len);
    if (cms == NULL)
        goto err;

    consumed = (size_t)(in - buf);
    remaining = len - consumed;
    if (remaining > INT_MAX)
        goto err;

    if (consumed < len) {
        indata = BIO_new_mem_buf(in, (int)remaining);
        if (indata == NULL)
            goto err;
    }

    out = BIO_new(BIO_s_null());
    if (out == NULL)
        goto err;

    CMS_verify(cms, NULL, NULL, indata, out,
        CMS_NO_SIGNER_CERT_VERIFY);

err:
    BIO_free(out);
    CMS_ContentInfo_free(cms);
    BIO_free(indata);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}
