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
 * Test CMS DER parsing.
 */

#include <openssl/bio.h>
#include <openssl/cms.h>
#include "fuzzer.h"

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    BIO *in = BIO_new(BIO_s_mem());
    OPENSSL_assert((size_t)BIO_write(in, buf, len) == len);
    CMS_ContentInfo *i = d2i_CMS_bio(in, NULL);
    CMS_ContentInfo_free(i);
    BIO_free(in);
    return 0;
}
