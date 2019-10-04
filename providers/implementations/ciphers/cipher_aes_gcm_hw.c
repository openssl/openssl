/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for AES GCM mode */

#include "prov/ciphercommon.h"
#include "prov/cipher_gcm.h"

static int generic_aes_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                                   size_t keylen)
{
    PROV_AES_GCM_CTX *actx = (PROV_AES_GCM_CTX *)ctx;
    AES_KEY *ks = &actx->ks.ks;

# ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
#  ifdef HWAES_ctr32_encrypt_blocks
        GCM_HW_SET_KEY_CTR_FN(ks, HWAES_set_encrypt_key, HWAES_encrypt,
                              HWAES_ctr32_encrypt_blocks);
#  else
        GCM_HW_SET_KEY_CTR_FN(ks, HWAES_set_encrypt_key, HWAES_encrypt, NULL);
#  endif /* HWAES_ctr32_encrypt_blocks */
    } else
# endif /* HWAES_CAPABLE */

# ifdef BSAES_CAPABLE
    if (BSAES_CAPABLE) {
        GCM_HW_SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt,
                              bsaes_ctr32_encrypt_blocks);
    } else
# endif /* BSAES_CAPABLE */

# ifdef VPAES_CAPABLE
    if (VPAES_CAPABLE) {
        GCM_HW_SET_KEY_CTR_FN(ks, vpaes_set_encrypt_key, vpaes_encrypt, NULL);
    } else
# endif /* VPAES_CAPABLE */

    {
# ifdef AES_CTR_ASM
        GCM_HW_SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt,
                              AES_ctr32_encrypt);
# else
        GCM_HW_SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt, NULL);
# endif /* AES_CTR_ASM */
    }
    ctx->key_set = 1;
    return 1;
}

static const PROV_GCM_HW aes_gcm = {
    generic_aes_gcm_initkey,
    gcm_setiv,
    gcm_aad_update,
    gcm_cipher_update,
    gcm_cipher_final,
    gcm_one_shot
};

#if defined(S390X_aes_128_CAPABLE)
# include "cipher_aes_gcm_hw_s390x.inc"
#elif defined(AESNI_CAPABLE)
# include "cipher_aes_gcm_hw_aesni.inc"
#elif defined(SPARC_AES_CAPABLE)
# include "cipher_aes_gcm_hw_t4.inc"
#else
const PROV_GCM_HW *PROV_AES_HW_gcm(size_t keybits)
{
    return &aes_gcm;
}
#endif

