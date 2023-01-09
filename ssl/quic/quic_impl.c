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

SSL *ossl_quic_new(SSL_CTX *ctx)
{
    QUIC_CONNECTION *qc;
    SSL *ssl = NULL;
    SSL_CONNECTION *sc;

    qc = OPENSSL_zalloc(sizeof(*qc));
    if (qc == NULL)
        goto err;

    ssl = &qc->stream.ssl;
    if (!ossl_ssl_init(ssl, ctx, SSL_TYPE_QUIC_CONNECTION)) {
        OPENSSL_free(qc);
        ssl = NULL;
        goto err;
    }
    qc->tls = ossl_ssl_connection_new(ctx);
    if (qc->tls == NULL || (sc = SSL_CONNECTION_FROM_SSL(qc->tls)) == NULL)
        goto err;
    /* override the user_ssl of the inner connection */
    sc->user_ssl = ssl;

    /* We'll need to set proper TLS method on qc->tls here */
    return ssl;
err:
    ossl_quic_free(ssl);
    return NULL;
}

int ossl_quic_init(SSL *s)
{
    return s->method->ssl_clear(s);
}

void ossl_quic_deinit(SSL *s)
{
    return;
}

void ossl_quic_free(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (qc == NULL) {
        /* TODO(QUIC): Temporarily needed to release the inner tls object */
        SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(s);

        if (sc != NULL)
            ossl_ssl_connection_free(s);
        return;
    }

    SSL_free(qc->tls);
    return;
}

int ossl_quic_reset(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (qc == NULL) {
        /* TODO(QUIC): Temporarily needed to reset the inner tls object */
        SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(s);

        return sc != NULL ? ossl_ssl_connection_reset(s) : 0;
    }

    return ossl_ssl_connection_reset(qc->tls);
}

int ossl_quic_clear(SSL *s)
{
    return 1;
}

int ossl_quic_accept(SSL *s)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_QUIC_SSL(s);

    if (sc == NULL)
        return 0;

    ossl_statem_set_in_init(sc, 0);
    return 1;
}

int ossl_quic_connect(SSL *s)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_QUIC_SSL(s);

    if (sc == NULL)
        return 0;

    ossl_statem_set_in_init(sc, 0);
    return 1;
}

int ossl_quic_read(SSL *s, void *buf, size_t len, size_t *readbytes)
{
    int ret;
    BIO *rbio = SSL_get_rbio(s);
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_QUIC_SSL(s);

    if (sc == NULL || rbio == NULL)
        return 0;

    sc->rwstate = SSL_READING;
    ret = BIO_read_ex(rbio, buf, len, readbytes);
    if (ret > 0 || !BIO_should_retry(rbio))
        sc->rwstate = SSL_NOTHING;
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
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_QUIC_SSL(s);

    if (sc == NULL || wbio == NULL)
        return 0;

    sc->rwstate = SSL_WRITING;
    ret = BIO_write_ex(wbio, buf, len, written);
    if (ret > 0 || !BIO_should_retry(wbio))
        sc->rwstate = SSL_NOTHING;
    return ret;
}

int ossl_quic_shutdown(SSL *s)
{
    return 1;
}

long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_QUIC_SSL(s);

    if (sc == NULL)
        return 0;

    switch(cmd) {
    case SSL_CTRL_CHAIN:
        if (larg)
            return ssl_cert_set1_chain(sc, NULL, (STACK_OF(X509) *)parg);
        else
            return ssl_cert_set0_chain(sc, NULL, (STACK_OF(X509) *)parg);
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

OSSL_TIME ossl_quic_default_timeout(void)
{
    return ossl_time_zero();
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

QUIC_CONNECTION *ossl_quic_conn_from_ssl(SSL *ssl)
{
    return QUIC_CONNECTION_FROM_SSL(ssl);
}

/*
 * The following are getters and setters of pointers, but they don't affect
 * the objects being pointed at.  They are CURRENTLY to be freed separately
 * by the caller the set them in the first place.
 */
int ossl_quic_conn_set_qrx(QUIC_CONNECTION *qc, OSSL_QRX *qrx)
{
    if (qc == NULL)
        return 0;
    qc->qrx = qrx;
    return 1;
}

OSSL_QRX *ossl_quic_conn_get_qrx(QUIC_CONNECTION *qc)
{
    return qc != NULL ? qc->qrx : NULL;
}

int ossl_quic_conn_set_ackm(QUIC_CONNECTION *qc, OSSL_ACKM *ackm)
{
    if (qc == NULL)
        return 0;
    qc->ackm = ackm;
    return 1;
}

OSSL_ACKM *ossl_quic_conn_set_akcm(QUIC_CONNECTION *qc)
{
    return qc != NULL ? qc->ackm : NULL;
}
