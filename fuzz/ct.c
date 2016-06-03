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
 * Fuzz the SCT parser.
 */

#include <stdio.h>
#include <openssl/ct.h>
#include "fuzzer.h"

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    const uint8_t **pp = &buf;
    STACK_OF(SCT) *scts = d2i_SCT_LIST(NULL, pp, len);
    SCT_LIST_free(scts);
    return 0;
}
