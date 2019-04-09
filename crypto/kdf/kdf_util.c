/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdarg.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "internal/evp_int.h"
#include "internal/numbers.h"
#include "kdf_local.h"

int call_ctrl(int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
              EVP_KDF_IMPL *impl, int cmd, ...)
{
    int ret;
    va_list args;

    va_start(args, cmd);
    ret = ctrl(impl, cmd, args);
    va_end(args);

    return ret;
}

/* Utility functions to send a string or hex string to a ctrl */

int kdf_str2ctrl(EVP_KDF_IMPL *impl,
                 int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
                 int cmd, const char *str)
{
    return call_ctrl(ctrl, impl, cmd, (const unsigned char *)str, strlen(str));
}

int kdf_hex2ctrl(EVP_KDF_IMPL *impl,
                 int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
                 int cmd, const char *hex)
{
    unsigned char *bin;
    long binlen;
    int ret = -1;

    bin = OPENSSL_hexstr2buf(hex, &binlen);
    if (bin == NULL)
        return 0;

    if (binlen <= INT_MAX)
        ret = call_ctrl(ctrl, impl, cmd, bin, (size_t)binlen);
    OPENSSL_free(bin);
    return ret;
}

/* Pass a message digest to a ctrl */
int kdf_md2ctrl(EVP_KDF_IMPL *impl,
                int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
                int cmd, const char *md_name)
{
    const EVP_MD *md;

    if (md_name == NULL || (md = EVP_get_digestbyname(md_name)) == NULL) {
        KDFerr(KDF_F_KDF_MD2CTRL, KDF_R_INVALID_DIGEST);
        return 0;
    }
    return call_ctrl(ctrl, impl, cmd, md);
}

