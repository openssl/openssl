/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* TODO: When ERR_STATE becomes opaque, this musts be removed */
#define OSSL_FORCE_ERR_STATE

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include "err_local.h"

void ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u)
{
    CRYPTO_THREAD_ID tid = CRYPTO_THREAD_get_current_id();
    unsigned long l;
    char buf[4096], *hex;
    const char *lib, *reason;
    const char *file, *data, *func;
    int line, flags;

    while ((l = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        lib = ERR_lib_error_string(l);
        reason = ERR_reason_error_string(l);
        if (func == NULL)
            func = "unknown function";
        if ((flags & ERR_TXT_STRING) == 0)
            data = "";
        hex = OPENSSL_buf2hexstr((const unsigned char *)&tid, sizeof(tid));
        BIO_snprintf(buf, sizeof(buf), "%s:error:%s:%s:%s:%s:%d:%s\n",
                     hex == NULL ? "<null>" : hex, lib, func, reason, file,
                     line, data);
        OPENSSL_free(hex);
        if (cb(buf, strlen(buf), u) <= 0)
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
