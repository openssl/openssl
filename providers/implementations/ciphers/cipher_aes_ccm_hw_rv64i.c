/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 64 ZKND ZKNE support for AES CCM.
 * This file is used by cipher_aes_ccm_hw.c
 */

#include "internal/deprecated.h"
#include "cipher_aes_ccm.h"

#if defined(OPENSSL_CPUID_OBJ) && defined(__riscv) && __riscv_xlen == 64

static int ccm_rv64i_zknd_zkne_initkey(PROV_CCM_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    return ossl_cipher_set_ccm_aes_initkey(ctx, key, keylen,
        rv64i_zkne_set_encrypt_key, rv64i_zkne_encrypt, NULL, NULL);
}

static const PROV_CCM_HW rv64i_zknd_zkne_ccm = {
    ccm_rv64i_zknd_zkne_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};

/*-
 * RISC-V RV64 ZVKNED support for AES CCM.
 * This file is included by cipher_aes_ccm_hw.c
 */

static int ccm_rv64i_zvkned_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
    size_t keylen)
{
    /* Zvkned only supports 128 and 256 bit keys for key schedule generation. */
    if (keylen * 8 == 128 || keylen * 8 == 256) {
        return ossl_cipher_set_ccm_aes_initkey(ctx, key, keylen,
            rv64i_zvkned_set_encrypt_key, rv64i_zvkned_encrypt, NULL, NULL);
    } else {
        return ossl_cipher_set_ccm_aes_initkey(ctx, key, keylen,
            AES_set_encrypt_key, rv64i_zvkned_encrypt, NULL, NULL);
    }
}

static const PROV_CCM_HW rv64i_zvkned_ccm = {
    ccm_rv64i_zvkned_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};

const PROV_CCM_HW *ossl_prov_aes_hw_ccm_rv64i(size_t keybits)
{
    if (RISCV_HAS_ZVKNED() && riscv_vlen() >= 128)
        return &rv64i_zvkned_ccm;
    else if (RISCV_HAS_ZKND_AND_ZKNE())
        return &rv64i_zknd_zkne_ccm;
    else
        return NULL;
}
#endif
