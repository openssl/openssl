/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/nelem.h"
#include "testutil.h"
#include "../ssl/ssl_local.h"

static int cipher_overhead(void)
{
    int ret = 1, i, n = ssl3_num_ciphers();
    const SSL_CIPHER *ciph;
    size_t mac, in, blk, ex;

    for (i = 0; i < n; i++) {
        ciph = ssl3_get_cipher(i);
        if (!ciph->min_dtls)
            continue;
        if (!TEST_true(ssl_cipher_get_overhead(ciph, &mac, &in, &blk, &ex))) {
            TEST_info("Failed getting %s", ciph->name);
            ret = 0;
        } else {
            TEST_info("Cipher %s: %zu %zu %zu %zu",
                      ciph->name, mac, in, blk, ex);
        }
    }
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(cipher_overhead);
    return 1;
}
