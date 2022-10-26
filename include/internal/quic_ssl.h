/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_SSL_H
# define OSSL_QUIC_SSL_H

# include <openssl/ssl.h>
# include "internal/quic_record_rx.h" /* OSSL_QRX */
# include "internal/quic_ackm.h"      /* OSSL_ACKM */

__owur SSL *ossl_quic_new(SSL_CTX *ctx);
__owur int ossl_quic_init(SSL *s);
void ossl_quic_deinit(SSL *s);
void ossl_quic_free(SSL *s);
int ossl_quic_reset(SSL *s);
int ossl_quic_clear(SSL *s);
__owur int ossl_quic_accept(SSL *s);
__owur int ossl_quic_connect(SSL *s);
__owur int ossl_quic_read(SSL *s, void *buf, size_t len, size_t *readbytes);
__owur int ossl_quic_peek(SSL *s, void *buf, size_t len, size_t *readbytes);
__owur int ossl_quic_write(SSL *s, const void *buf, size_t len, size_t *written);
__owur int ossl_quic_shutdown(SSL *s);
__owur long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg);
__owur long ossl_quic_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
__owur long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void));
__owur long ossl_quic_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void));
__owur size_t ossl_quic_pending(const SSL *s);
__owur OSSL_TIME ossl_quic_default_timeout(void);
__owur int ossl_quic_num_ciphers(void);
__owur const SSL_CIPHER *ossl_quic_get_cipher(unsigned int u);
int ossl_quic_renegotiate_check(SSL *ssl, int initok);

typedef struct quic_conn_st QUIC_CONNECTION;
typedef struct quic_stream_st QUIC_STREAM;

__owur QUIC_CONNECTION *ossl_quic_conn_from_ssl(SSL *ssl);
int ossl_quic_conn_set_qrx(QUIC_CONNECTION *qc, OSSL_QRX *qrx);
OSSL_QRX *ossl_quic_conn_get_qrx(QUIC_CONNECTION *qc);
int ossl_quic_conn_set_ackm(QUIC_CONNECTION *qc, OSSL_ACKM *ackm);
OSSL_ACKM *ossl_quic_conn_set_akcm(QUIC_CONNECTION *qc);

#endif
