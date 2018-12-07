/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * See SP800-185 "Appendix A - KMAC, .... in Terms of Keccak[c]"
 *
 * Inputs are:
 *    K = Key                  (len(K) < 2^2040 bits)
 *    X = Input
 *    L = Output length        (0 <= L < 2^2040 bits)
 *    S = Customization String Default="" (len(S) < 2^2040 bits)
 *
 * KMAC128(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 168) ||  X || right_encode(L).
 *     T = bytepad(encode_string("KMAC") || encode_string(S), 168).
 *     return KECCAK[256](T || newX || 00, L).
 * }
 *
 * KMAC256(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 136) ||  X || right_encode(L).
 *     T = bytepad(encode_string("KMAC") || encode_string(S), 136).
 *     return KECCAK[512](T || newX || 00, L).
 * }
 *
 * KMAC128XOF(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 168) ||  X || right_encode(0).
 *     T = bytepad(encode_string("KMAC") || encode_string(S), 168).
 *     return KECCAK[256](T || newX || 00, L).
 * }
 *
 * KMAC256XOF(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 136) ||  X || right_encode(0).
 *     T = bytepad(encode_string("KMAC") || encode_string(S), 136).
 *     return KECCAK[512](T || newX || 00, L).
 * }
 *
 */

#include <stdlib.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "internal/evp_int.h"

#define KMAC_MAX_BLOCKSIZE ((1600 - 128*2) / 8) /* 168 */
#define KMAC_MIN_BLOCKSIZE ((1600 - 256*2) / 8) /* 136 */

/* Length encoding will be  a 1 byte size + length in bits (2 bytes max) */
#define KMAC_MAX_ENCODED_HEADER_LEN 3

/*
 * Custom string max size is chosen such that:
 *   len(encoded_string(custom) + len(kmac_encoded_string) <= KMAC_MIN_BLOCKSIZE
 *   i.e: (KMAC_MAX_CUSTOM + KMAC_MAX_ENCODED_LEN) + 6 <= 136
 */
#define KMAC_MAX_CUSTOM 127

/* Maximum size of encoded custom string */
#define KMAC_MAX_CUSTOM_ENCODED (KMAC_MAX_CUSTOM + KMAC_MAX_ENCODED_HEADER_LEN)

/* Maximum key size in bytes = 2040 / 8 */
#define KMAC_MAX_KEY 255

/*
 * Maximum Encoded Key size will be padded to a multiple of the blocksize
 * i.e KMAC_MAX_KEY + KMAC_MAX_ENCODED_LEN = 258
 * Padded to a multiple of KMAC_MAX_BLOCKSIZE
 */
#define KMAC_MAX_KEY_ENCODED (KMAC_MAX_BLOCKSIZE * 2)

/* Fixed value of encode_string("KMAC") */
static const unsigned char kmac_string[] = {
    0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43
};


#define KMAC_FLAG_XOF_MODE          1

/* typedef EVP_MAC_IMPL */
struct evp_mac_impl_st {
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    size_t out_len;
    int key_len;
    int custom_len;
    /* If xof_mode = 1 then we use right_encode(0) */
    int xof_mode;
    /* key and custom are stored in encoded form */
    unsigned char key[KMAC_MAX_KEY_ENCODED];
    unsigned char custom[KMAC_MAX_CUSTOM_ENCODED];
};

static int encode_string(unsigned char *out, int *out_len,
                         const unsigned char *in, int in_len);
static int right_encode(unsigned char *out, int *out_len, size_t bits);
static int bytepad(unsigned char *out, int *out_len,
                   const unsigned char *in1, int in1_len,
                   const unsigned char *in2, int in2_len,
                   int w);
static int kmac_bytepad_encode_key(unsigned char *out, int *out_len,
                                   const unsigned char *in, int in_len,
                                   int w);
static int kmac_ctrl_str(EVP_MAC_IMPL *kctx, const char *type,
                         const char *value);


static void kmac_free(EVP_MAC_IMPL *kctx)
{
    if (kctx != NULL) {
        EVP_MD_CTX_free(kctx->ctx);
        OPENSSL_cleanse(kctx->key, kctx->key_len);
        OPENSSL_cleanse(kctx->custom, kctx->custom_len);
        OPENSSL_free(kctx);
    }
}

static EVP_MAC_IMPL *kmac_new(const EVP_MD *md)
{
    EVP_MAC_IMPL *kctx = NULL;

    if ((kctx = OPENSSL_zalloc(sizeof(*kctx))) == NULL
            || (kctx->ctx = EVP_MD_CTX_new()) == NULL) {
        kmac_free(kctx);
        return NULL;
    }
    kctx->md = md;
    kctx->out_len = md->md_size;
    return kctx;
}

static EVP_MAC_IMPL *kmac128_new(void)
{
    return kmac_new(evp_keccak_kmac128());
}

static EVP_MAC_IMPL *kmac256_new(void)
{
    return kmac_new(evp_keccak_kmac256());
}

static int kmac_copy(EVP_MAC_IMPL *gdst, EVP_MAC_IMPL *gsrc)
{
    gdst->md = gsrc->md;
    gdst->out_len = gsrc->out_len;
    gdst->key_len = gsrc->key_len;
    gdst->custom_len = gsrc->custom_len;
    gdst->xof_mode = gsrc->xof_mode;
    memcpy(gdst->key, gsrc->key, gsrc->key_len);
    memcpy(gdst->custom, gsrc->custom, gdst->custom_len);

    return EVP_MD_CTX_copy(gdst->ctx, gsrc->ctx);
}

/*
 * The init() assumes that any ctrl methods are set beforehand for
 * md, key and custom. Setting the fields afterwards will have no
 * effect on the output mac.
 */
static int kmac_init(EVP_MAC_IMPL *kctx)
{
    EVP_MD_CTX *ctx = kctx->ctx;
    unsigned char out[KMAC_MAX_BLOCKSIZE];
    int out_len, block_len;

    /* Check key has been set */
    if (kctx->key_len == 0) {
        EVPerr(EVP_F_KMAC_INIT, EVP_R_NO_KEY_SET);
        return 0;
    }
    if (!EVP_DigestInit_ex(kctx->ctx, kctx->md, NULL))
        return 0;

    block_len = EVP_MD_block_size(kctx->md);

    /* Set default custom string if it is not already set */
    if (kctx->custom_len == 0)
        (void)kmac_ctrl_str(kctx, "custom", "");

    return bytepad(out, &out_len, kmac_string, sizeof(kmac_string),
                   kctx->custom, kctx->custom_len, block_len)
           && EVP_DigestUpdate(ctx, out, out_len)
           && EVP_DigestUpdate(ctx, kctx->key, kctx->key_len);
}

static size_t kmac_size(EVP_MAC_IMPL *kctx)
{
    return kctx->out_len;
}

static int kmac_update(EVP_MAC_IMPL *kctx, const unsigned char *data,
                       size_t datalen)
{
    return EVP_DigestUpdate(kctx->ctx, data, datalen);
}

static int kmac_final(EVP_MAC_IMPL *kctx, unsigned char *out)
{
    EVP_MD_CTX *ctx = kctx->ctx;
    int lbits, len;
    unsigned char encoded_outlen[KMAC_MAX_ENCODED_HEADER_LEN];

    /* KMAC XOF mode sets the encoded length to 0 */
    lbits = (kctx->xof_mode ? 0 : (kctx->out_len * 8));

    return right_encode(encoded_outlen, &len, lbits)
           && EVP_DigestUpdate(ctx, encoded_outlen, len)
           && EVP_DigestFinalXOF(ctx, out, kctx->out_len);
}

/*
 * The following Ctrl functions can be set any time before final():
 *     - EVP_MAC_CTRL_SET_SIZE: The requested output length.
 *     - EVP_MAC_CTRL_SET_XOF: If set, this indicates that right_encoded(0) is
 *                             part of the digested data, otherwise it uses
 *                             right_encoded(requested output length).

 * All other Ctrl functions should be set before init().
 */
static int kmac_ctrl(EVP_MAC_IMPL *kctx, int cmd, va_list args)
{
    const unsigned char *p;
    size_t len;
    size_t size;

    switch (cmd) {
    case EVP_MAC_CTRL_SET_XOF:
        kctx->xof_mode = va_arg(args, int);
        return 1;

    case EVP_MAC_CTRL_SET_SIZE:
        size = va_arg(args, size_t);
        kctx->out_len = size;
        return 1;

    case EVP_MAC_CTRL_SET_KEY:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        if (len < 4 || len > KMAC_MAX_KEY) {
            EVPerr(EVP_F_KMAC_CTRL, EVP_R_INVALID_KEY_LENGTH);
            return 0;
        }
        return kmac_bytepad_encode_key(kctx->key, &kctx->key_len, p, len,
                                       EVP_MD_block_size(kctx->md));

    case EVP_MAC_CTRL_SET_CUSTOM:
        p = va_arg(args, const unsigned char *);
        len = va_arg(args, size_t);
        if (len > KMAC_MAX_CUSTOM) {
            EVPerr(EVP_F_KMAC_CTRL, EVP_R_INVALID_CUSTOM_LENGTH);
            return 0;
        }
        return encode_string(kctx->custom, &kctx->custom_len, p, len);

    default:
        return -2;
    }
}

static int kmac_ctrl_int(EVP_MAC_IMPL *kctx, int cmd, ...)
{
    int rv;
    va_list args;

    va_start(args, cmd);
    rv = kmac_ctrl(kctx, cmd, args);
    va_end(args);

    return rv;
}

static int kmac_ctrl_str_cb(void *kctx, int cmd, void *buf, size_t buflen)
{
    return kmac_ctrl_int(kctx, cmd, buf, buflen);
}

static int kmac_ctrl_str(EVP_MAC_IMPL *kctx, const char *type,
                         const char *value)
{
    if (value == NULL)
        return 0;

    if (strcmp(type, "outlen") == 0)
        return kmac_ctrl_int(kctx, EVP_MAC_CTRL_SET_SIZE, (size_t)atoi(value));
    if (strcmp(type, "xof") == 0)
        return kmac_ctrl_int(kctx, EVP_MAC_CTRL_SET_XOF, atoi(value));
    if (strcmp(type, "key") == 0)
        return EVP_str2ctrl(kmac_ctrl_str_cb, kctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "hexkey") == 0)
        return EVP_hex2ctrl(kmac_ctrl_str_cb, kctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "custom") == 0)
        return EVP_str2ctrl(kmac_ctrl_str_cb, kctx, EVP_MAC_CTRL_SET_CUSTOM,
                            value);
    if (strcmp(type, "hexcustom") == 0)
        return EVP_hex2ctrl(kmac_ctrl_str_cb, kctx, EVP_MAC_CTRL_SET_CUSTOM,
                            value);
    return -2;
}

/*
 * Encoding/Padding Methods.
 */

/* Returns the number of bytes required to store 'bits' into a byte array */
static unsigned int get_encode_size(size_t bits)
{
    unsigned int cnt = 0, sz = sizeof(size_t);

    while (bits && (cnt < sz)) {
        ++cnt;
        bits >>= 8;
    }
    /* If bits is zero 1 byte is required */
    if (cnt == 0)
        cnt = 1;
    return cnt;
}

/*
 * Convert an integer into bytes . The number of bytes is appended
 * to the end of the buffer. Returns an array of bytes 'out' of size
 * *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 *
 */
static int right_encode(unsigned char *out, int *out_len, size_t bits)
{
    unsigned int len = get_encode_size(bits);
    int i;

    /* The length is constrained to a single byte: 2040/8 = 255 */
    if (len > 0xFF)
        return 0;

    /* MSB's are at the start of the bytes array */
    for (i = len - 1; i >= 0; --i) {
        out[i] = (unsigned char)(bits & 0xFF);
        bits >>= 8;
    }
    /* Tack the length onto the end */
    out[len] = (unsigned char)len;

    /* The Returned length includes the tacked on byte */
    *out_len = len + 1;
    return 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (*8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
static int encode_string(unsigned char *out, int *out_len,
                         const unsigned char *in, int in_len)
{
    if (in == NULL) {
        *out_len = 0;
    } else {
        int i, bits, len;

        bits = 8 * in_len;
        len = get_encode_size(bits);
        if (len > 0xFF)
            return 0;

        out[0] = len;
        for (i = len; i > 0; --i) {
            out[i] = (bits & 0xFF);
            bits >>= 8;
        }
        memcpy(out + len + 1, in, in_len);
        *out_len = (1 + len + in_len);
    }
    return 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
static int bytepad(unsigned char *out, int *out_len,
                   const unsigned char *in1, int in1_len,
                   const unsigned char *in2, int in2_len, int w)
{
    int len;
    unsigned char *p = out;
    int sz = w;

    /* Left encoded w */
    *p++ = 1;
    *p++ = w;
    /* || in1 */
    memcpy(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    if (in2 != NULL && in2_len > 0) {
        memcpy(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - out;
    while (len > sz) {
        sz += w;
    }
    /* zero pad the end of the buffer */
    memset(p, 0, sz - len);
    *out_len = sz;
    return 1;
}

/*
 * Returns out = bytepad(encode_string(in), w)
 */
static int kmac_bytepad_encode_key(unsigned char *out, int *out_len,
                                   const unsigned char *in, int in_len,
                                   int w)
{
    unsigned char tmp[KMAC_MAX_KEY + KMAC_MAX_ENCODED_HEADER_LEN];
    int tmp_len;

    if (!encode_string(tmp, &tmp_len, in, in_len))
        return 0;

    return bytepad(out, out_len, tmp, tmp_len, NULL, 0, w);
}

const EVP_MAC kmac128_meth = {
    EVP_MAC_KMAC128,
    kmac128_new,
    kmac_copy,
    kmac_free,
    kmac_size,
    kmac_init,
    kmac_update,
    kmac_final,
    kmac_ctrl,
    kmac_ctrl_str
};

const EVP_MAC kmac256_meth = {
    EVP_MAC_KMAC256,
    kmac256_new,
    kmac_copy,
    kmac_free,
    kmac_size,
    kmac_init,
    kmac_update,
    kmac_final,
    kmac_ctrl,
    kmac_ctrl_str
};

