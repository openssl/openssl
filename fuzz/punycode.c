/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/punycode.h"
#include "internal/nelem.h"
#include <openssl/crypto.h>
#include "fuzzer.h"

#include <stdio.h>
#include <string.h>

int FuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    char b[256];  /* Stack buffer for small input strings */
    unsigned int out[16], outlen = OSSL_NELEM(out);
    char outc[16];

    /* Only process if input fits in our stack buffer */
    if (len < sizeof(b)) {
        memcpy(b, buf, len);
        b[len] = '\0';
        ossl_punycode_decode((const char *)buf, len, out, &outlen);
        ossl_a2ulabel(b, outc, sizeof(outc));
    }
    return 0;
}

void FuzzerCleanup(void)
{
}
