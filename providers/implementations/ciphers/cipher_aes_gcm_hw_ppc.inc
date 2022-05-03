/*
 * Copyright 2001-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * PPC support for AES GCM.
 * This file is included by cipher_aes_gcm_hw.c
 */

static int aes_ppc_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                               size_t keylen)
{
    PROV_AES_GCM_CTX *actx = (PROV_AES_GCM_CTX *)ctx;
    AES_KEY *ks = &actx->ks.ks;

    GCM_HW_SET_KEY_CTR_FN(ks, aes_p8_set_encrypt_key, aes_p8_encrypt,
                          aes_p8_ctr32_encrypt_blocks);
    return 1;
}


extern size_t ppc_aes_gcm_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                                  const void *key, unsigned char ivec[16], u64 *Xi);
extern size_t ppc_aes_gcm_decrypt(const unsigned char *in, unsigned char *out, size_t len,
                                  const void *key, unsigned char ivec[16], u64 *Xi);

static inline u32 UTO32(unsigned char *buf)
{
    return ((u32) buf[0] << 24) | ((u32) buf[1] << 16) | ((u32) buf[2] << 8) | ((u32) buf[3]);
}

static inline u32 add32TOU(unsigned char buf[4], u32 n)
{
    u32 r;

    r = UTO32(buf);
    r += n;
    buf[0] = (unsigned char) (r >> 24) & 0xFF;
    buf[1] = (unsigned char) (r >> 16) & 0xFF;
    buf[2] = (unsigned char) (r >> 8) & 0xFF;
    buf[3] = (unsigned char) r & 0xFF;
    return r;
}

static size_t aes_p10_gcm_crypt(const unsigned char *in, unsigned char *out, size_t len,
                                const void *key, unsigned char ivec[16], u64 *Xi, int encrypt)
{
    int s = 0;
    int ndone = 0;
    int ctr_reset = 0;
    u64 blocks_unused;
    u64 nb = len / 16;
    u64 next_ctr = 0;
    unsigned char ctr_saved[12];

    memcpy(ctr_saved, ivec, 12);

    while (nb) {
        blocks_unused = (u64) 0xffffffffU + 1 - (u64) UTO32 (ivec + 12);
        if (nb > blocks_unused) {
            len = blocks_unused * 16;
            nb -= blocks_unused;
            next_ctr = blocks_unused;
            ctr_reset = 1;
        } else {
            len = nb * 16;
            next_ctr = nb;
            nb = 0;
        }

        s = encrypt ? ppc_aes_gcm_encrypt(in, out, len, key, ivec, Xi)
                    : ppc_aes_gcm_decrypt(in, out, len, key, ivec, Xi);

        /* add counter to ivec */
        add32TOU(ivec + 12, (u32) next_ctr);
        if (ctr_reset) {
            ctr_reset = 0;
            in += len;
            out += len;
        }
        memcpy(ivec, ctr_saved, 12);
        ndone += s;
    }

    return ndone;
}

size_t ppc_aes_gcm_encrypt_wrap(const unsigned char *in, unsigned char *out, size_t len,
                                const void *key, unsigned char ivec[16], u64 *Xi)
{
    return aes_p10_gcm_crypt(in, out, len, key, ivec, Xi, 1);
}

size_t ppc_aes_gcm_decrypt_wrap(const unsigned char *in, unsigned char *out, size_t len,
                                const void *key, unsigned char ivec[16], u64 *Xi)
{
    return aes_p10_gcm_crypt(in, out, len, key, ivec, Xi, 0);
}


static const PROV_GCM_HW aes_ppc_gcm = {
    aes_ppc_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_aes_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_aes_hw_gcm(size_t keybits)
{
    return PPC_AES_GCM_CAPABLE ? &aes_ppc_gcm : &aes_gcm;
}

