/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"

int ossl_vasprintf(char **str, const char *format, va_list args)
{
    char *candidate = NULL;
    size_t candidate_len = 64;
    size_t tmp_len = 0;
    char *tmp = NULL;
    int ret;

    if ((candidate = OPENSSL_malloc(candidate_len)) == NULL)
        goto err;
    va_list args_copy;
    va_copy(args_copy, args);
    ret = vsnprintf(candidate, candidate_len, format, args_copy);
    va_end(args_copy);
    if (ret < 0)
        goto err;
    if ((size_t)ret >= candidate_len) {
        /*  Too big to fit in allocation. */

        tmp_len = (size_t)ret + 1;
        if ((tmp = OPENSSL_malloc(tmp_len)) == NULL)
            goto err;
        OPENSSL_clear_free(candidate, candidate_len);
        candidate = tmp;
        candidate_len = tmp_len;
        tmp = NULL;
        ret = vsnprintf(candidate, candidate_len, format, args);
    }
    /* At this point this should not happen unless vsnprintf is insane. */
    if (ret < 0 || (size_t)ret >= candidate_len)
        goto err;
    *str = candidate;
    return ret;

err:
    OPENSSL_clear_free(candidate, candidate_len);
    OPENSSL_clear_free(tmp, tmp_len);
    *str = NULL;
    return -1;
}

int ossl_asprintf(char **str, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = ossl_vasprintf(str, format, args);
    va_end(args);
    return ret;
}
