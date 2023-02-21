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
# include <openssl/bio.h>
# include "internal/quic_record_rx.h" /* OSSL_QRX */
# include "internal/quic_ackm.h"      /* OSSL_ACKM */

# ifndef OPENSSL_NO_QUIC

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
__owur long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg);
__owur long ossl_quic_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
__owur long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void));
__owur long ossl_quic_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void));
__owur size_t ossl_quic_pending(const SSL *s);
__owur int ossl_quic_num_ciphers(void);
__owur const SSL_CIPHER *ossl_quic_get_cipher(unsigned int u);
int ossl_quic_renegotiate_check(SSL *ssl, int initok);

typedef struct quic_conn_st QUIC_CONNECTION;

int ossl_quic_do_handshake(QUIC_CONNECTION *qc);
void ossl_quic_set_connect_state(QUIC_CONNECTION *qc);
void ossl_quic_set_accept_state(QUIC_CONNECTION *qc);

__owur int ossl_quic_has_pending(const QUIC_CONNECTION *qc);
__owur int ossl_quic_tick(QUIC_CONNECTION *qc);
__owur int ossl_quic_get_tick_timeout(QUIC_CONNECTION *qc, struct timeval *tv);
OSSL_TIME ossl_quic_get_tick_deadline(QUIC_CONNECTION *qc);
__owur int ossl_quic_get_rpoll_descriptor(QUIC_CONNECTION *qc, BIO_POLL_DESCRIPTOR *d);
__owur int ossl_quic_get_wpoll_descriptor(QUIC_CONNECTION *qc, BIO_POLL_DESCRIPTOR *d);
__owur int ossl_quic_get_net_read_desired(QUIC_CONNECTION *qc);
__owur int ossl_quic_get_net_write_desired(QUIC_CONNECTION *qc);
__owur int ossl_quic_get_error(const QUIC_CONNECTION *qc, int i);
__owur int ossl_quic_conn_get_blocking_mode(const QUIC_CONNECTION *qc);
__owur int ossl_quic_conn_set_blocking_mode(QUIC_CONNECTION *qc, int blocking);
__owur int ossl_quic_conn_shutdown(QUIC_CONNECTION *qc, uint64_t flags,
                                   const SSL_SHUTDOWN_EX_ARGS *args,
                                   size_t args_len);
__owur int ossl_quic_conn_stream_conclude(QUIC_CONNECTION *qc);
void ossl_quic_conn_set0_net_rbio(QUIC_CONNECTION *qc, BIO *net_wbio);
void ossl_quic_conn_set0_net_wbio(QUIC_CONNECTION *qc, BIO *net_wbio);
BIO *ossl_quic_conn_get_net_rbio(const QUIC_CONNECTION *qc);
BIO *ossl_quic_conn_get_net_wbio(const QUIC_CONNECTION *qc);
__owur int ossl_quic_conn_set_initial_peer_addr(QUIC_CONNECTION *qc,
                                                const BIO_ADDR *peer_addr);

/*
 * Used to override ossl_time_now() for debug purposes. Must be called before
 * connecting.
 */
void ossl_quic_conn_set_override_now_cb(SSL *s,
                                        OSSL_TIME (*now_cb)(void *arg),
                                        void *now_cb_arg);

/*
 * Condvar waiting in the assist thread doesn't support time faking as it relies
 * on the OS's notion of time, thus this is used in test code to force a
 * spurious wakeup instead.
 */
void ossl_quic_conn_force_assist_thread_wake(SSL *s);

# endif

#endif
