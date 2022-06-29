/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/macros.h>
#include <openssl/objects.h>
#include "quic_local.h"

int ossl_quic_new(SSL *s)
{
    return s->method->ssl_clear(s);
}

void ossl_quic_free(SSL *s)
{
    return;
}

int ossl_quic_clear(SSL *s)
{
    return 1;
}

int ossl_quic_accept(SSL *s)
{
    s->statem.in_init = 0;
    return 1;
}

int ossl_quic_connect(SSL *s)
{
    s->statem.in_init = 0;
    return 1;
}

int ossl_quic_read(SSL *s, void *buf, size_t len, size_t *readbytes)
{
    int ret;
    BIO *rbio = SSL_get_rbio(s);

    if (rbio == NULL)
        return 0;

    s->rwstate = SSL_READING;
    ret = BIO_read_ex(rbio, buf, len, readbytes);
    if (ret > 0 || !BIO_should_retry(rbio))
        s->rwstate = SSL_NOTHING;
    return ret <= 0 ? -1 : ret;
}

int ossl_quic_peek(SSL *s, void *buf, size_t len, size_t *readbytes)
{
    return -1;
}

int ossl_quic_write(SSL *s, const void *buf, size_t len, size_t *written)
{
    BIO *wbio = SSL_get_wbio(s);
    int ret;

    if (wbio == NULL)
        return 0;

    s->rwstate = SSL_WRITING;
    ret = BIO_write_ex(wbio, buf, len, written);
    if (ret > 0 || !BIO_should_retry(wbio))
        s->rwstate = SSL_NOTHING;
    return ret;
}

int ossl_quic_shutdown(SSL *s)
{
    return 1;
}

long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    switch(cmd) {
    case SSL_CTRL_CHAIN:
        if (larg)
            return ssl_cert_set1_chain(s, NULL, (STACK_OF(X509) *)parg);
        else
            return ssl_cert_set0_chain(s, NULL, (STACK_OF(X509) *)parg);
    }
    return 0;
}

long ossl_quic_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    switch(cmd) {
    case SSL_CTRL_CHAIN:
        if (larg)
            return ssl_cert_set1_chain(NULL, ctx, (STACK_OF(X509) *)parg);
        else
            return ssl_cert_set0_chain(NULL, ctx, (STACK_OF(X509) *)parg);

    case SSL_CTRL_SET_TLSEXT_TICKET_KEYS:
    case SSL_CTRL_GET_TLSEXT_TICKET_KEYS:
        /* TODO(QUIC): these will have to be implemented properly */
        return 1;
    }
    return 0;
}

long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void))
{
    return 0;
}

long ossl_quic_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
{
    return 0;
}

size_t ossl_quic_pending(const SSL *s)
{
    return 0;
}

long ossl_quic_default_timeout(void)
{
    return 0;
}

int ossl_quic_num_ciphers(void)
{
    return 1;
}

const SSL_CIPHER *ossl_quic_get_cipher(unsigned int u)
{
    /*
     * TODO(QUIC): This is needed so the SSL_CTX_set_cipher_list("DEFAULT");
     * produces at least one valid TLS-1.2 cipher.
     * Later we should allow that there are none with QUIC protocol as
     * SSL_CTX_set_cipher_list should still allow setting a SECLEVEL.
     */
    static const SSL_CIPHER ciph = {
        1,
        TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS1_RFC_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        SSL_kECDHE,
        SSL_aRSA,
        SSL_AES256GCM,
        SSL_AEAD,
        TLS1_2_VERSION, TLS1_2_VERSION,
        DTLS1_2_VERSION, DTLS1_2_VERSION,
        SSL_HIGH | SSL_FIPS,
        SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
        256,
        256
    };

    return &ciph;
}

int ossl_quic_renegotiate_check(SSL *ssl, int initok)
{
    return 1;
}
