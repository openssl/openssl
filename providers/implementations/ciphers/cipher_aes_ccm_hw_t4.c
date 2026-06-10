/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Fujitsu SPARC64 X support for AES CCM.
 * This file is used by cipher_aes_ccm_hw.c
 */

#include "internal/deprecated.h"
#include "cipher_aes_ccm.h"

#if defined(SPARC_AES_CAPABLE)

static int ccm_t4_aes_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
    size_t keylen)
{
    return ossl_cipher_set_ccm_aes_initkey(ctx, key, keylen,
        aes_t4_set_encrypt_key, aes_t4_encrypt, NULL, NULL);
}

static const PROV_CCM_HW t4_aes_ccm = {
    ccm_t4_aes_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};

const PROV_CCM_HW *ossl_prov_aes_hw_ccm_t4(size_t keybits)
{
    if (SPARC_AES_CAPABLE)
        return &t4_aes_ccm;
    return NULL;
}
#endif
