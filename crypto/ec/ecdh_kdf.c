/*
 * Copyright 2015-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "ec_lcl.h"

/* Key derivation function from X9.63/SECG */
int ecdh_KDF_X9_63(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const unsigned char *sinfo, size_t sinfolen,
                   const EVP_MD *md)
{
    int ret;
    EVP_KDF_CTX *kctx = NULL;

    kctx = EVP_KDF_CTX_new(EVP_get_kdfbyname(SN_x963kdf));
    ret =
        kctx != NULL
        && EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, md) > 0
        && EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, Z, Zlen) > 0
        && EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SHARED_INFO, sinfo, sinfolen) > 0
        && EVP_KDF_derive(kctx, out, outlen) > 0;

    EVP_KDF_CTX_free(kctx);
    return ret;
}

/*-
 * The old name for ecdh_KDF_X9_63
 * Retained for ABI compatibility
 */
#if !OPENSSL_API_3
int ECDH_KDF_X9_62(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const unsigned char *sinfo, size_t sinfolen,
                   const EVP_MD *md)
{
    return ecdh_KDF_X9_63(out, outlen, Z, Zlen, sinfo, sinfolen, md);
}
#endif
