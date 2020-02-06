/*
 * Copyright 2016-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "blake2b.h"
#include <prov/blake2.h>
#include "openssl/core_names.h"
#include "openssl/params.h"

int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen)
{
    int ret = 0;

    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[3];
    size_t params_n = 0;
    size_t out_written;
    size_t blake_outlen = (size_t) outlen;

    if (out == NULL || outlen == 0)
        goto fail;

    if ((mac = EVP_MAC_fetch(NULL, "blake2bmac", NULL)) == NULL)
        goto fail;

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
        goto fail_mac;

    if (key != NULL && keylen != 0)
        params[params_n++] = OSSL_PARAM_construct_octet_string(
                OSSL_MAC_PARAM_KEY,
                (void *) key,
                keylen
        );

    params[params_n++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE,
                                                     &blake_outlen);

    params[params_n++] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_CTX_set_params(ctx, params))
        goto fail_mac;

    if (EVP_MAC_init(ctx) != 1)
        goto fail_ctx;

    if (EVP_MAC_update(ctx, in, inlen) != 1)
        goto fail_ctx;

    if (EVP_MAC_final(ctx, out, (size_t *) &out_written, outlen) != 1)
        goto fail_ctx;

    ret=1;

fail_ctx:
    EVP_MAC_CTX_free(ctx);

fail_mac:
    EVP_MAC_free(mac);

fail:
    return ret;
}

int blake2b_long(void *pout, uint32_t outlen, const void *in, size_t inlen)
{
    int ret = 0;
    unsigned char *out = (unsigned char *)pout;
    uint8_t outlen_bytes[sizeof(uint32_t)] = {0};
    size_t blake_outlen = (size_t) outlen;

    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[3];
    size_t params_n = 0;
    size_t out_written;

    uint32_t toproduce;
    uint8_t out_buffer[BLAKE2B_OUTBYTES];
    uint8_t in_buffer[BLAKE2B_OUTBYTES];
    unsigned int outlen_tmp = BLAKE2B_OUTBYTES;

    if (outlen > UINT32_MAX)
        goto fail;

    if (pout == NULL || outlen == 0)
        goto fail;

    if (outlen > BLAKE2B_OUTBYTES)
        blake_outlen = BLAKE2B_OUTBYTES;

    /* Ensure little-endian byte order! */
    store32(outlen_bytes, (uint32_t)outlen);

    if ((mac = EVP_MAC_fetch(NULL, "blake2bmac", NULL)) == NULL)
        goto fail;

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
        goto fail_mac;

    params[params_n++] = OSSL_PARAM_construct_size_t(
        OSSL_MAC_PARAM_SIZE,
        &blake_outlen
    );

    params[params_n++] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_CTX_set_params(ctx, params))
        goto fail_ctx;

    if (EVP_MAC_init(ctx) != 1)
        goto fail_ctx;

    if (EVP_MAC_update(ctx, outlen_bytes, sizeof(outlen_bytes)) != 1)
        goto fail_ctx;

    if (EVP_MAC_update(ctx, in, inlen) != 1)
        goto fail_ctx;

    if (outlen <= BLAKE2B_OUTBYTES) {
        if (EVP_MAC_final(ctx, out, (size_t *) &out_written, outlen) != 1)
            goto fail_ctx;
        goto finish;
    }

    if (EVP_MAC_final(ctx, out_buffer, (size_t *) &out_written, outlen_tmp) != 1)
        goto fail_ctx;

    memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
    out += BLAKE2B_OUTBYTES / 2;
    toproduce = (uint32_t)outlen - BLAKE2B_OUTBYTES / 2;

    while(toproduce > BLAKE2B_OUTBYTES) {
        memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
        if (blake2b(out_buffer, BLAKE2B_OUTBYTES, in_buffer,
                    BLAKE2B_OUTBYTES, NULL, 0) != 1)
            goto fail_ctx;
        memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
        out += BLAKE2B_OUTBYTES / 2;
        toproduce -= BLAKE2B_OUTBYTES / 2;
    }

    memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
    if (blake2b(out_buffer, toproduce, in_buffer, BLAKE2B_OUTBYTES,
                NULL, 0) != 1)
        goto fail_ctx;
    memcpy(out, out_buffer, toproduce);

finish:
    ret = 1;

fail_ctx:
    EVP_MAC_CTX_free(ctx);

fail_mac:
    EVP_MAC_free(mac);

fail:
    return ret;
}
