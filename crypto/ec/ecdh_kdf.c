/*
 * Copyright 2015-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>
#include <opentls/core_names.h>
#include <opentls/ec.h>
#include <opentls/evp.h>
#include <opentls/kdf.h>
#include "ec_local.h"

/* Key derivation function from X9.63/SECG */
int ecdh_KDF_X9_63(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const unsigned char *sinfo, size_t sinfolen,
                   const EVP_MD *md)
{
    int ret = 0;
    EVP_KDF_CTX *kctx = NULL;
    Otls_PARAM params[4], *p = params;
    const char *mdname = EVP_MD_name(md);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, Otls_KDF_NAME_X963KDF, NULL);

    if ((kctx = EVP_KDF_CTX_new(kdf)) != NULL) {
        *p++ = Otls_PARAM_construct_utf8_string(Otls_KDF_PARAM_DIGEST,
                                                (char *)mdname,
                                                strlen(mdname) + 1);
        *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_KEY,
                                                 (void *)Z, Zlen);
        *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_INFO,
                                                 (void *)sinfo, sinfolen);
        *p = Otls_PARAM_construct_end();

        ret = EVP_KDF_CTX_set_params(kctx, params) > 0
            && EVP_KDF_derive(kctx, out, outlen) > 0;
        EVP_KDF_CTX_free(kctx);
    }
    EVP_KDF_free(kdf);
    return ret;
}

/*-
 * The old name for ecdh_KDF_X9_63
 * Retained for ABI compatibility
 */
#ifndef OPENtls_NO_DEPRECATED_3_0
int ECDH_KDF_X9_62(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const unsigned char *sinfo, size_t sinfolen,
                   const EVP_MD *md)
{
    return ecdh_KDF_X9_63(out, outlen, Z, Zlen, sinfo, sinfolen, md);
}
#endif
