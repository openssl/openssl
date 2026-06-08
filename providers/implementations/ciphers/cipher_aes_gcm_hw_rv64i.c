/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 64 support for AES GCM.
 * This file is used by cipher_aes_gcm_hw.c
 */
#include "internal/deprecated.h"
#include "cipher_aes_gcm.h"

#if defined(OPENSSL_CPUID_OBJ) && defined(__riscv) && __riscv_xlen == 64

/*-
 * RISC-V 64 ZKND and ZKNE support for AES GCM.
 */
static int rv64i_zknd_zkne_gcm_initkey(PROV_GCM_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    return aes_gcm_hw_initkey(ctx, key, keylen,
        rv64i_zkne_set_encrypt_key, rv64i_zkne_encrypt, NULL);
}

static const PROV_GCM_HW rv64i_zknd_zkne_gcm = {
    rv64i_zknd_zkne_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_aes_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

/*-
 * RISC-V RV64 ZVKNED support for AES GCM.
 */
static int rv64i_zvkned_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
    size_t keylen)
{
    /*
     * Zvkned only supports 128 and 256 bit keys for key schedule generation.
     * For AES-192 case, we could fallback to `AES_set_encrypt_key`.
     */
    if (keylen * 8 == 128 || keylen * 8 == 256) {
        return aes_gcm_hw_initkey(ctx, key, keylen,
            rv64i_zvkned_set_encrypt_key, rv64i_zvkned_encrypt, NULL);
    } else {
        return aes_gcm_hw_initkey(ctx, key, keylen,
            AES_set_encrypt_key, rv64i_zvkned_encrypt, NULL);
    }
}

static const PROV_GCM_HW rv64i_zvkned_gcm = {
    rv64i_zvkned_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_aes_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

/*-
 * RISC-V RV64 ZVKB, ZVKG and ZVKNED support for AES GCM.
 */
static int rv64i_zvkb_zvkg_zvkned_gcm_initkey(PROV_GCM_CTX *ctx,
    const unsigned char *key,
    size_t keylen)
{
    /*
     * Zvkned only supports 128 and 256 bit keys for key schedule generation.
     * For AES-192 case, we could fallback to `AES_set_encrypt_key`.
     */
    if (keylen * 8 == 128 || keylen * 8 == 256) {
        return aes_gcm_hw_initkey(ctx, key, keylen,
            rv64i_zvkned_set_encrypt_key, rv64i_zvkned_encrypt,
            rv64i_zvkb_zvkned_ctr32_encrypt_blocks);
    } else {
        return aes_gcm_hw_initkey(ctx, key, keylen,
            AES_set_encrypt_key, rv64i_zvkned_encrypt,
            rv64i_zvkb_zvkned_ctr32_encrypt_blocks);
    }
}

static const PROV_GCM_HW rv64i_zvkb_zvkg_zvkned_gcm = {
    rv64i_zvkb_zvkg_zvkned_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_aes_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_aes_hw_gcm_rv64i(size_t keybits)
{
    if (RISCV_HAS_ZVKNED() && riscv_vlen() >= 128) {
        if (RISCV_HAS_ZVKB() && RISCV_HAS_ZVKG())
            return &rv64i_zvkb_zvkg_zvkned_gcm;
        return &rv64i_zvkned_gcm;
    }

    if (RISCV_HAS_ZKND_AND_ZKNE()) {
        return &rv64i_zknd_zkne_gcm;
    }

    return NULL;
}

#endif
