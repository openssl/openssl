/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * TODO (OpenSSL 1.2):
 * This whole file should be removed in OpenSSL 1.2, the next version
 * we can make some API- and ABI-breaking changes (as well as all related
 * SSLv23 stuff in other code).
 *
 * For OpenSSL 1.1.1, since breaking changes are not permitted, we limit
 * ourselves to replacing the "remove padding" function with a stub that
 * always returns an error -- this is not considered an ABI-breaking change
 * because OpenSSL 1.1.0 removed support for native SSLv2; for all other inputs
 * this function could never succeed.  The "add padding" function will remain
 * until OpenSSL 1.2.0.
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                           const unsigned char *from, int flen)
{
    int i, j;
    unsigned char *p;

    if (flen > (tlen - 11)) {
        RSAerr(RSA_F_RSA_PADDING_ADD_SSLV23,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return 0;
    }

    p = (unsigned char *)to;

    *(p++) = 0;
    *(p++) = 2;                 /* Public Key BT (Block Type) */

    /* pad out with non-zero random data */
    j = tlen - 3 - 8 - flen;

    if (RAND_bytes(p, j) <= 0)
        return 0;
    for (i = 0; i < j; i++) {
        if (*p == '\0')
            do {
                if (RAND_bytes(p, 1) <= 0)
                    return 0;
            } while (*p == '\0');
        p++;
    }

    memset(p, 3, 8);
    p += 8;
    *(p++) = '\0';

    memcpy(p, from, (unsigned int)flen);
    return 1;
}

int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                             const unsigned char *from, int flen, int num)
{
    RSAerr(RSA_F_RSA_PADDING_CHECK_SSLV23, RSA_R_SSLV3_ROLLBACK_ATTACK);
    return -1;
}
