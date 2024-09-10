/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "../ssl_local.h"

int SSL_CTX_set1_echstore(SSL_CTX *ctx, OSSL_ECHSTORE *es)
{
    return 0;
}

int SSL_set1_echstore(SSL *s, OSSL_ECHSTORE *es)
{
    return 0;
}

OSSL_ECHSTORE *SSL_CTX_get1_echstore(const SSL_CTX *ctx)
{
    return NULL;
}

OSSL_ECHSTORE *SSL_get1_echstore(const SSL *s)
{
    return NULL;
}

int SSL_ech_set_server_names(SSL *s, const char *inner_name,
                             const char *outer_name, int no_outer)
{
    return 0;
}

int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name, int no_outer)
{
    return 0;
}

int SSL_ech_set_outer_alpn_protos(SSL *s, const unsigned char *protos,
                                  const size_t protos_len)
{
    return 0;
}

int SSL_ech_get1_status(SSL *s, char **inner_sni, char **outer_sni)
{
    return 0;
}

int SSL_ech_set_grease_suite(SSL *s, const char *suite)
{
    return 0;
}

int SSL_ech_set_grease_type(SSL *s, uint16_t type)
{
    return 0;
}

void SSL_ech_set_callback(SSL *s, SSL_ech_cb_func f)
{
    return;
}

int SSL_ech_get_retry_config(SSL *s, unsigned char **ec, size_t *eclen)
{
    return 0;
}

int SSL_CTX_ech_set_outer_alpn_protos(SSL_CTX *s, const unsigned char *protos,
                                      const size_t protos_len)
{
    return 0;
}

int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            int *decrypted_ok,
                            char **inner_sni, char **outer_sni,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len,
                            unsigned char **hrrtok, size_t *toklen)
{
    if (ctx == NULL) {
        /*
         * TODO(ECH): this is a bit of a bogus error, just so as
         * to get the `make update` command to add the required
         * error number. We don't need it yet, but it's involved
         * in some of the build artefacts, so may as well jump
         * the gun a bit on it.
         */
        ERR_raise(ERR_LIB_SSL, SSL_R_ECH_REQUIRED);
        return 0;
    }
    return 0;
}

void SSL_CTX_ech_set_callback(SSL_CTX *ctx, SSL_ech_cb_func f)
{
    return;
}
