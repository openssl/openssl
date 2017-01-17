/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include "../ssl/ssl_locl.h"

int main(void)
{
    int i, n = ssl3_num_ciphers();
    const SSL_CIPHER *ciph;
    size_t mac, in, blk, ex;

    for (i = 0; i < n; i++) {
        ciph = ssl3_get_cipher(i);
        if (!ciph->min_dtls)
            continue;
        if (!ssl_cipher_get_overhead(ciph, &mac, &in, &blk, &ex)) {
            printf("Error getting overhead for %s\n", ciph->name);
            exit(1);
        } else {
            printf("Cipher %s: %"OSSLzu" %"OSSLzu" %"OSSLzu" %"OSSLzu"\n",
                   ciph->name, mac, in, blk, ex);
        }
    }
    exit(0);
}
