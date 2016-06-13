/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <string.h>

#include <openssl/evp.h>
#include "evp_locl.h"
#include "internal/cryptlib.h"

static const unsigned char data_bin2ascii[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define conv_bin2ascii(a) (data_bin2ascii[(a)&0x3f])

EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVP_ENCODE_CTX));
}

void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx)
{
    OPENSSL_free(ctx);
}

int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx)
{
    return ctx->data_used;
}

void EVP_EncodeInit(EVP_ENCODE_CTX *ctx)
{
    memset(ctx, 0, sizeof(EVP_ENCODE_CTX));
}

void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *out_len,
                      const unsigned char *in, size_t in_len)
{
    size_t total = 0;

    *out_len = 0;
    if (in_len == 0) {
        return;
    }

    OPENSSL_assert(ctx->data_used < sizeof(ctx->data));

    if (sizeof(ctx->data) - ctx->data_used > in_len) {
        memcpy(&ctx->data[ctx->data_used], in, in_len);
        ctx->data_used += in_len;
        return;
    }

    if (ctx->data_used != 0) {
        size_t encoded;
        const size_t todo = sizeof(ctx->data) - ctx->data_used;
        memcpy(&ctx->data[ctx->data_used], in, todo);
        in += todo;
        in_len -= todo;

        encoded = EVP_EncodeBlock(out, ctx->data, sizeof(ctx->data));
        ctx->data_used = 0;

        out += encoded;
        *(out++) = '\n';
        *out = '\0';

        total = encoded + 1;
    }

    while (in_len >= sizeof(ctx->data)) {
        size_t encoded = EVP_EncodeBlock(out, in, sizeof(ctx->data));
        in += sizeof(ctx->data);
        in_len -= sizeof(ctx->data);

        out += encoded;
        *(out++) = '\n';
        *out = '\0';

        if (total + encoded + 1 < total) {
            *out_len = 0;
            return;
        }

        total += encoded + 1;
    }

    if (in_len != 0) {
        memcpy(ctx->data, in, in_len);
    }

    ctx->data_used = in_len;

    if (total > INT_MAX) {
        /* We cannot signal an error, but we can at least avoid making *out_len
         * negative. */
        total = 0;
    }
    *out_len = total;
}

void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *out_len)
{
    size_t encoded;

    if (ctx->data_used == 0) {
        *out_len = 0;
        return;
    }

    encoded = EVP_EncodeBlock(out, ctx->data, ctx->data_used);
    out[encoded++] = '\n';
    out[encoded] = '\0';
    ctx->data_used = 0;
    *out_len = encoded;
}

size_t EVP_EncodeBlock(unsigned char *dst, const unsigned char *src,
                       size_t src_len)
{
    unsigned int l;
    size_t remaining = src_len, ret = 0;

    while (remaining) {
        if (remaining >= 3) {
            l = (((unsigned int)src[0]) << 16L) |
                (((unsigned int)src[1]) << 8L) |
                src[2];
            *(dst++) = conv_bin2ascii(l >> 18L);
            *(dst++) = conv_bin2ascii(l >> 12L);
            *(dst++) = conv_bin2ascii(l >> 6L);
            *(dst++) = conv_bin2ascii(l);
            remaining -= 3;
        } else {
            l = ((unsigned int)src[0]) << 16L;
            if (remaining == 2) {
                l |= ((unsigned int)src[1] << 8L);
            }

            *(dst++) = conv_bin2ascii(l >> 18L);
            *(dst++) = conv_bin2ascii(l >> 12L);
            *(dst++) = (remaining == 1) ? '=' : conv_bin2ascii(l >> 6L);
            *(dst++) = '=';
            remaining = 0;
        }
        ret += 4;
        src += 3;
    }

    *dst = '\0';
    return ret;
}


/* Decoding. */

void EVP_DecodeInit(EVP_ENCODE_CTX *ctx)
{
    memset(ctx, 0, sizeof(EVP_ENCODE_CTX));
}

/* kBase64ASCIIToBinData maps characters (c < 128) to their base64 value, or
 * else 0xff if they are invalid. As a special case, the padding character
 * ('=') is mapped to zero. */
static const unsigned char kBase64ASCIIToBinData[128] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff,
    0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static unsigned char base64_ascii_to_bin(unsigned char a)
{
#if defined(CHARSET_EBCDIC)
    a = os_toascii[a];
#endif

    if (a >= 128) {
        return 0xff;
    }

    return kBase64ASCIIToBinData[a];
}

/* base64_decode_quad decodes a single “quad” (i.e. four characters) of base64
 * data and writes up to three bytes to |out|. It sets |*out_num_bytes| to the
 * number of bytes written, which will be less than three if the quad ended
 * with padding.  It returns one on success or zero on error. */
static int base64_decode_quad(unsigned char *out, size_t *out_num_bytes,
                              const unsigned char *in)
{
    unsigned int v, padding_pattern;

    const unsigned char a = base64_ascii_to_bin(in[0]);
    const unsigned char b = base64_ascii_to_bin(in[1]);
    const unsigned char c = base64_ascii_to_bin(in[2]);
    const unsigned char d = base64_ascii_to_bin(in[3]);
    if (a == 0xff || b == 0xff || c == 0xff || d == 0xff) {
        return 0;
    }

    v = ((unsigned int)a) << 18 |
        ((unsigned int)b) << 12 |
        ((unsigned int)c) << 6 |
        (unsigned int)d;

    padding_pattern = (in[0] == '=') << 3 |
                      (in[1] == '=') << 2 |
                      (in[2] == '=') << 1 |
                      (in[3] == '=');

    switch (padding_pattern) {
    case 0:
        /* The common case of no padding. */
        *out_num_bytes = 3;
        out[0] = v >> 16;
        out[1] = v >> 8;
        out[2] = v;
        break;

    case 1: /* xxx= */
        *out_num_bytes = 2;
        out[0] = v >> 16;
        out[1] = v >> 8;
        break;

    case 3: /* xx== */
        *out_num_bytes = 1;
        out[0] = v >> 16;
        break;

    default:
        return 0;
    }

    return 1;
}

int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *out_len,
                     const unsigned char *in, size_t in_len)
{
    size_t bytes_out = 0, i;
    *out_len = 0;

    if (ctx->error_encountered) {
        return -1;
    }

    for (i = 0; i < in_len; i++) {
        const char c = in[i];
        switch (c) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            continue;
        }

        if (base64_ascii_to_bin(c) == 0xff || ctx->eof_seen) {
            ctx->error_encountered = 1;
            return -1;
        }

        ctx->data[ctx->data_used++] = c;
        if (ctx->data_used == 4) {
            size_t num_bytes_resulting;
            if (!base64_decode_quad(out, &num_bytes_resulting, ctx->data)) {
                ctx->error_encountered = 1;
                return -1;
            }

            ctx->data_used = 0;
            bytes_out += num_bytes_resulting;
            out += num_bytes_resulting;

            if (num_bytes_resulting < 3) {
                ctx->eof_seen = 1;
            }
        }
    }

    if (bytes_out > INT_MAX) {
        ctx->error_encountered = 1;
        *out_len = 0;
        return -1;
    }
    *out_len = bytes_out;

    if (ctx->eof_seen) {
        return 0;
    }

    return 1;
}

int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *out_len)
{
    *out_len = 0;
    if (ctx->error_encountered || ctx->data_used != 0) {
        return -1;
    }

    return 1;
}

static int decoded_length(size_t *out_len, size_t len) {
  if (len % 4 != 0) {
    return 0;
  }

  *out_len = (len / 4) * 3;
  return 1;
}


static int decode_base64(unsigned char *out, size_t *out_len, size_t max_out,
                         const unsigned char *in, size_t in_len)
{
    size_t i, bytes_out = 0, max_len;
    *out_len = 0;

    if (in_len % 4 != 0) {
        return 0;
    }

    if (!decoded_length(&max_len, in_len) || max_out < max_len) {
        return 0;
    }

    for (i = 0; i < in_len; i += 4) {
        size_t num_bytes_resulting;

        if (!base64_decode_quad(out, &num_bytes_resulting, &in[i])) {
            return 0;
        }

        bytes_out += num_bytes_resulting;
        out += num_bytes_resulting;
        if (num_bytes_resulting != 3 && i != in_len - 4) {
            return 0;
        }
    }

    *out_len = bytes_out;
    return 1;
}

int EVP_DecodeBlock(unsigned char *dst, const unsigned char *src,
                    size_t src_len)
{
    size_t dst_len;

    /* Trim spaces and tabs from the beginning of the input. */
    while (src_len > 0) {
        if (src[0] != ' ' && src[0] != '\t') {
            break;
        }

        src++;
        src_len--;
    }

    /* Trim newlines, spaces and tabs from the end of the line. */
    while (src_len > 0) {
        switch (src[src_len - 1]) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            src_len--;
            continue;
        }

        break;
    }

    if (!decoded_length(&dst_len, src_len) ||
        dst_len > INT_MAX ||
        !decode_base64(dst, &dst_len, dst_len, src, src_len)) {
        return -1;
    }

    /* EVP_DecodeBlock does not take padding into account, so put the
     * NULs back in... so the caller can strip them back out. */
    while (dst_len % 3 != 0) {
        dst[dst_len++] = '\0';
    }
    OPENSSL_assert(dst_len <= INT_MAX);

    return dst_len;
}
