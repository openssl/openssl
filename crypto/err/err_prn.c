/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

void ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u)
{
    CRYPTO_THREAD_ID tid = CRYPTO_THREAD_get_current_id();
    unsigned long l;
    char buf[256];
    char buf2[4096], *hex;
    const char *file, *data;
    int line, flags;

    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        ERR_error_string_n(l, buf, sizeof(buf));
        hex = OPENSSL_buf2hexstr((const unsigned char *)&tid, sizeof(tid));
        BIO_snprintf(buf2, sizeof(buf2), "%s:%s:%s:%d:%s\n", hex, buf, file,
                     line, (flags & ERR_TXT_STRING) ? data : "");
        OPENSSL_free(hex);
        if (cb(buf2, strlen(buf2), u) <= 0)
            break;              /* abort outputting the error report */
    }
}

static int print_bio(const char *str, size_t len, void *bp)
{
    return BIO_write((BIO *)bp, str, len);
}

void ERR_print_errors(BIO *bp)
{
    ERR_print_errors_cb(print_bio, bp);
}

#ifndef OPENSSL_NO_STDIO
void ERR_print_errors_fp(FILE *fp)
{
    BIO *bio = BIO_new_fp(fp, BIO_NOCLOSE);
    if (bio == NULL)
        return;

    ERR_print_errors_cb(print_bio, bio);
    BIO_free(bio);
}
#endif
