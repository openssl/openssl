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
__owur int ossl_quic_writev(SSL *s, const struct iovec *iov, size_t iovcnt,
                            size_t *written);
__owur long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg);
__owur long ossl_quic_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
__owur long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void));
__owur long ossl_quic_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void));
__owur size_t ossl_quic_pending(const SSL *s);
__owur int ossl_quic_num_ciphers(void);
__owur const SSL_CIPHER *ossl_quic_get_cipher(unsigned int u);
int ossl_quic_renegotiate_check(SSL *ssl, int initok);

typedef struct quic_conn_st QUIC_CONNECTION;
typedef struct quic_xso_st QUIC_XSO;

int ossl_quic_do_handshake(SSL *s);
void ossl_quic_set_connect_state(SSL *s);
void ossl_quic_set_accept_state(SSL *s);

__owur int ossl_quic_has_pending(const SSL *s);
__owur int ossl_quic_handle_events(SSL *s);
__owur int ossl_quic_get_event_timeout(SSL *s, struct timeval *tv,
                                       int *is_infinite);
OSSL_TIME ossl_quic_get_event_deadline(SSL *s);
__owur int ossl_quic_get_rpoll_descriptor(SSL *s, BIO_POLL_DESCRIPTOR *d);
__owur int ossl_quic_get_wpoll_descriptor(SSL *s, BIO_POLL_DESCRIPTOR *d);
__owur int ossl_quic_get_net_read_desired(SSL *s);
__owur int ossl_quic_get_net_write_desired(SSL *s);
__owur int ossl_quic_get_error(const SSL *s, int i);
__owur int ossl_quic_conn_get_blocking_mode(const SSL *s);
__owur int ossl_quic_conn_set_blocking_mode(SSL *s, int blocking);
__owur int ossl_quic_conn_shutdown(SSL *s, uint64_t flags,
                                   const SSL_SHUTDOWN_EX_ARGS *args,
                                   size_t args_len);
__owur int ossl_quic_conn_stream_conclude(SSL *s);
void ossl_quic_conn_set0_net_rbio(SSL *s, BIO *net_wbio);
void ossl_quic_conn_set0_net_wbio(SSL *s, BIO *net_wbio);
BIO *ossl_quic_conn_get_net_rbio(const SSL *s);
BIO *ossl_quic_conn_get_net_wbio(const SSL *s);
__owur int ossl_quic_conn_set_initial_peer_addr(SSL *s,
                                                const BIO_ADDR *peer_addr);
__owur SSL *ossl_quic_conn_stream_new(SSL *s, uint64_t flags);
__owur SSL *ossl_quic_get0_connection(SSL *s);
__owur int ossl_quic_get_stream_type(SSL *s);
__owur uint64_t ossl_quic_get_stream_id(SSL *s);
__owur int ossl_quic_set_default_stream_mode(SSL *s, uint32_t mode);
__owur SSL *ossl_quic_detach_stream(SSL *s);
__owur int ossl_quic_attach_stream(SSL *conn, SSL *stream);
__owur int ossl_quic_set_incoming_stream_policy(SSL *s, int policy,
                                                uint64_t aec);
__owur SSL *ossl_quic_accept_stream(SSL *s, uint64_t flags);
__owur size_t ossl_quic_get_accept_stream_queue_len(SSL *s);

__owur int ossl_quic_stream_reset(SSL *ssl,
                                  const SSL_STREAM_RESET_ARGS *args,
                                  size_t args_len);

__owur int ossl_quic_get_stream_read_state(SSL *ssl);
__owur int ossl_quic_get_stream_write_state(SSL *ssl);
__owur int ossl_quic_get_stream_read_error_code(SSL *ssl,
                                                uint64_t *app_error_code);
__owur int ossl_quic_get_stream_write_error_code(SSL *ssl,
                                                 uint64_t *app_error_code);
__owur int ossl_quic_get_conn_close_info(SSL *ssl,
                                         SSL_CONN_CLOSE_INFO *info,
                                         size_t info_len);

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
