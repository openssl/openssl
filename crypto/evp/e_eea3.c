/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2018 BaishanCloud. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_ZUC

# include <openssl/evp.h>
# include <openssl/objects.h>

# include "internal/zuc.h"
# include "internal/evp_int.h"

typedef struct {
    ZUC_KEY zk;                 /* working key */
} EVP_EEA3_KEY;

# define data(ctx) ((EVP_EEA3_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int eea3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);
static int eea3_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
static int eea3_cleanup(EVP_CIPHER_CTX *ctx);

static const EVP_CIPHER zuc_128_eea3_cipher = {
    NID_zuc_128_eea3,
    1, EVP_ZUC_KEY_SIZE, 5,
    EVP_CIPH_VARIABLE_LENGTH,
    eea3_init_key,
    eea3_cipher,
    eea3_cleanup,
    sizeof(EVP_EEA3_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

const EVP_CIPHER *EVP_eea3(void)
{
    return &zuc_128_eea3_cipher;
}

static int eea3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc)
{
    EVP_EEA3_KEY *ek = data(ctx);
    ZUC_KEY *zk = &ek->zk;
    uint32_t count;
    uint32_t bearer;
    uint32_t direction;

    zk->k = key;

    /*
     * This is a lazy approach: we 'borrow' the 'iv' parameter
     * to use it as a place of transfer the EEA3 iv params -
     * count, bearer and direction.
     *
     * count is 32 bits, bearer is 5 bits and direction is 1
     * bit so we read the first 38 bits of iv. And the whole
     * iv is set to 5 bytes (40 bits).
     */

    count = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
    bearer = (iv[4] & 0xF8) >> 3;
    direction = (iv[4] & 0x4) >> 2;

    zk->iv[0] = (count >> 24) & 0xFF;
    zk->iv[1] = (count >> 16) & 0xFF;
    zk->iv[2] = (count >> 8) & 0xFF;
    zk->iv[3] = count;

    zk->iv[4] = ((bearer << 3) | ((direction & 1) << 2)) & 0xFC;
    zk->iv[5] = zk->iv[6] = zk->iv[7] = 0;

    zk->iv[8] = zk->iv[0];
    zk->iv[9] = zk->iv[1];
    zk->iv[10] = zk->iv[2];
    zk->iv[11] = zk->iv[3];
    zk->iv[12] = zk->iv[4];
    zk->iv[13] = zk->iv[5];
    zk->iv[14] = zk->iv[6];
    zk->iv[15] = zk->iv[7];

    ZUC_init(zk);

    return 1;
}

static int eea3_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl)
{
    EVP_EEA3_KEY *ek = data(ctx);
    ZUC_KEY *zk = &ek->zk;
    int i, remain;
    int num = EVP_CIPHER_CTX_num(ctx);

    remain = zk->keystream_len - num;
    if (remain < inl) {
        /* no adequate key, generate more */
        zk->L = ((inl - remain) * 8 + 31) / 32;

        if (!ZUC_generate_keystream(zk))
            return 0;
    }

    /*
     * EEA3 is based on 'bits', but we can only handle 'bytes'.
     *
     * So we choose to output a final whole byte, even if there are some
     * bits at the end of the input. Those trailing bits in the last byte
     * should be discarded by caller.
     */
    for (i = 0; i < inl; i++, num++)
        out[i] = in[i] ^ zk->keystream[num];

    /* num always points to next key byte to use */
    EVP_CIPHER_CTX_set_num(ctx, num);

    return 1;
}

static int eea3_cleanup(EVP_CIPHER_CTX *ctx)
{
    EVP_EEA3_KEY *key = data(ctx);

    ZUC_destroy_keystream(&key->zk);

    return 1;
}
#endif
