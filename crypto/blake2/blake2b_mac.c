/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_BLAKE2

# include <openssl/evp.h>
# include "blake2_locl.h"
# include "internal/cryptlib.h"
# include "internal/evp_int.h"

/* typedef EVP_MAC_IMPL */
struct evp_mac_impl_st {
    BLAKE2B_CTX ctx;
    BLAKE2B_PARAM params;
    unsigned char key[BLAKE2B_KEYBYTES];
};

static EVP_MAC_IMPL *blake2b_mac_new(void)
{
    EVP_MAC_IMPL *macctx = OPENSSL_zalloc(sizeof(*macctx));
    if (macctx != NULL) {
        blake2b_param_init(&macctx->params);
        /* ctx initialization is deferred to BLAKE2b_Init() */
    }
    return macctx;
}

static void blake2b_mac_free(EVP_MAC_IMPL *macctx)
{
    if (macctx != NULL) {
        OPENSSL_cleanse(macctx->key, sizeof(macctx->key));
        OPENSSL_free(macctx);
    }
}

static int blake2b_mac_copy(EVP_MAC_IMPL *dst, EVP_MAC_IMPL *src)
{
    *dst = *src;
    return 1;
}

static int blake2b_mac_init(EVP_MAC_IMPL *macctx)
{
    /* Check key has been set */
    if (macctx->params.key_length == 0) {
        EVPerr(EVP_F_BLAKE2B_MAC_INIT, EVP_R_NO_KEY_SET);
        return 0;
    }

    return BLAKE2b_Init_key(&macctx->ctx, &macctx->params, macctx->key);
}

static int blake2b_mac_update(EVP_MAC_IMPL *macctx, const unsigned char *data,
                              size_t datalen)
{
    return BLAKE2b_Update(&macctx->ctx, data, datalen);
}

static int blake2b_mac_final(EVP_MAC_IMPL *macctx, unsigned char *out)
{
    return BLAKE2b_Final(out, &macctx->ctx);
}

/*
 * ALL Ctrl functions should be set before init().
 */
static int blake2b_mac_ctrl(EVP_MAC_IMPL *macctx, int cmd, va_list args)
{
    const unsigned char *p;
    size_t len;
    size_t size;

    switch (cmd) {
        case EVP_MAC_CTRL_SET_SIZE:
            size = va_arg(args, size_t);
            if (size < 1 || size > BLAKE2B_OUTBYTES) {
                EVPerr(EVP_F_BLAKE2B_MAC_CTRL, EVP_R_NOT_XOF_OR_INVALID_LENGTH);
                return 0;
            }
            blake2b_param_set_digest_length(&macctx->params, (uint8_t)size);
            return 1;

        case EVP_MAC_CTRL_SET_KEY:
            p = va_arg(args, const unsigned char *);
            len = va_arg(args, size_t);
            if (len < 1 || len > BLAKE2B_KEYBYTES) {
                EVPerr(EVP_F_BLAKE2B_MAC_CTRL, EVP_R_INVALID_KEY_LENGTH);
                return 0;
            }
            blake2b_param_set_key_length(&macctx->params, (uint8_t)len);
            memcpy(macctx->key, p, len);
            memset(macctx->key + len, 0, BLAKE2B_KEYBYTES - len);
            return 1;

        case EVP_MAC_CTRL_SET_CUSTOM:
            p = va_arg(args, const unsigned char *);
            len = va_arg(args, size_t);
            if (len > BLAKE2B_PERSONALBYTES) {
                EVPerr(EVP_F_BLAKE2B_MAC_CTRL, EVP_R_INVALID_CUSTOM_LENGTH);
                return 0;
            }
            blake2b_param_set_personal(&macctx->params, p, len);
            return 1;

        case EVP_MAC_CTRL_SET_SALT:
            p = va_arg(args, const unsigned char *);
            len = va_arg(args, size_t);
            if (len > BLAKE2B_SALTBYTES) {
                EVPerr(EVP_F_BLAKE2B_MAC_CTRL, EVP_R_INVALID_SALT_LENGTH);
                return 0;
            }
            blake2b_param_set_salt(&macctx->params, p, len);
            return 1;

        default:
            return -2;
    }
}

static int blake2b_mac_ctrl_int(EVP_MAC_IMPL *macctx, int cmd, ...)
{
    int rv;
    va_list args;

    va_start(args, cmd);
    rv = blake2b_mac_ctrl(macctx, cmd, args);
    va_end(args);

    return rv;
}

static int blake2b_mac_ctrl_str_cb(void *macctx, int cmd, void *buf, size_t buflen)
{
    return blake2b_mac_ctrl_int(macctx, cmd, buf, buflen);
}

static int blake2b_mac_ctrl_str(EVP_MAC_IMPL *macctx, const char *type,
                                const char *value)
{
    if (value == NULL)
        return 0;

    if (strcmp(type, "outlen") == 0)
        return blake2b_mac_ctrl_int(macctx, EVP_MAC_CTRL_SET_SIZE, (size_t)atoi(value));
    if (strcmp(type, "key") == 0)
        return EVP_str2ctrl(blake2b_mac_ctrl_str_cb, macctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "hexkey") == 0)
        return EVP_hex2ctrl(blake2b_mac_ctrl_str_cb, macctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "custom") == 0)
        return EVP_str2ctrl(blake2b_mac_ctrl_str_cb, macctx, EVP_MAC_CTRL_SET_CUSTOM,
                            value);
    if (strcmp(type, "hexcustom") == 0)
        return EVP_hex2ctrl(blake2b_mac_ctrl_str_cb, macctx, EVP_MAC_CTRL_SET_CUSTOM,
                            value);
    if (strcmp(type, "salt") == 0)
        return EVP_str2ctrl(blake2b_mac_ctrl_str_cb, macctx, EVP_MAC_CTRL_SET_SALT,
                            value);
    if (strcmp(type, "hexsalt") == 0)
        return EVP_hex2ctrl(blake2b_mac_ctrl_str_cb, macctx, EVP_MAC_CTRL_SET_SALT,
                            value);
    return -2;
}

static size_t blake2b_mac_size(EVP_MAC_IMPL *macctx)
{
    return macctx->params.digest_length;
}

const EVP_MAC blake2b_mac_meth = {
    EVP_MAC_BLAKE2B,
    blake2b_mac_new,
    blake2b_mac_copy,
    blake2b_mac_free,
    blake2b_mac_size,
    blake2b_mac_init,
    blake2b_mac_update,
    blake2b_mac_final,
    blake2b_mac_ctrl,
    blake2b_mac_ctrl_str
};

#endif
