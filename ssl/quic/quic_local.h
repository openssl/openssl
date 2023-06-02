/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_LOCAL_H
# define OSSL_QUIC_LOCAL_H

# include <openssl/ssl.h>
# include "internal/quic_ssl.h"       /* QUIC_CONNECTION */
# include "internal/quic_txp.h"
# include "internal/quic_statm.h"
# include "internal/quic_demux.h"
# include "internal/quic_record_rx.h"
# include "internal/quic_tls.h"
# include "internal/quic_fc.h"
# include "internal/quic_stream.h"
# include "internal/quic_channel.h"
# include "internal/quic_reactor.h"
# include "internal/quic_thread_assist.h"
# include "../ssl_local.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC stream SSL object (QSSO) type. This implements the API personality layer
 * for QSSO objects, wrapping the QUIC-native QUIC_STREAM object and tracking
 * state required by the libssl API personality.
 */
struct quic_xso_st {
    /* SSL object common header. */
    struct ssl_st                   ssl;

    /* The connection this stream is associated with. Always non-NULL. */
    QUIC_CONNECTION                 *conn;

    /* The stream object. Always non-NULL for as long as the XSO exists. */
    QUIC_STREAM                     *stream;

    /* Is this stream in blocking mode? */
    unsigned int                    blocking                : 1;

    /*
     * This state tracks SSL_write all-or-nothing (AON) write semantics
     * emulation.
     *
     * Example chronology:
     *
     *   t=0:  aon_write_in_progress=0
     *   t=1:  SSL_write(ssl, b1, l1) called;
     *         too big to enqueue into sstream at once, SSL_ERROR_WANT_WRITE;
     *         aon_write_in_progress=1; aon_buf_base=b1; aon_buf_len=l1;
     *         aon_buf_pos < l1 (depends on how much room was in sstream);
     *   t=2:  SSL_write(ssl, b2, l2);
     *         b2 must equal b1 (validated unless ACCEPT_MOVING_WRITE_BUFFER)
     *         l2 must equal l1 (always validated)
     *         append into sstream from [b2 + aon_buf_pos, b2 + aon_buf_len)
     *         if done, aon_write_in_progess=0
     *
     */
    /* Is an AON write in progress? */
    unsigned int                    aon_write_in_progress   : 1;
    /*
     * The base buffer pointer the caller passed us for the initial AON write
     * call. We use this for validation purposes unless
     * ACCEPT_MOVING_WRITE_BUFFER is enabled.
     *
     * NOTE: We never dereference this, as the caller might pass a different
     * (but identical) buffer if using ACCEPT_MOVING_WRITE_BUFFER. It is for
     * validation by pointer comparison only.
     */
    const unsigned char             *aon_buf_base;
    /* The total length of the AON buffer being sent, in bytes. */
    size_t                          aon_buf_len;
    /*
     * The position in the AON buffer up to which we have successfully sent data
     * so far.
     */
    size_t                          aon_buf_pos;

    /* SSL_set_mode */
    uint32_t                        ssl_mode;

    /*
     * Last 'normal' error during an app-level I/O operation, used by
     * SSL_get_error(); used to track data-path errors like SSL_ERROR_WANT_READ
     * and SSL_ERROR_WANT_WRITE.
     */
    int                             last_error;
};

struct quic_conn_st {
    /*
     * ssl_st is a common header for ordinary SSL objects, QUIC connection
     * objects and QUIC stream objects, allowing objects of these different
     * types to be disambiguated at runtime and providing some common fields.
     *
     * Note: This must come first in the QUIC_CONNECTION structure.
     */
    struct ssl_st                   ssl;

    SSL                             *tls;

    /*
     * The QUIC channel providing the core QUIC connection implementation. Note
     * that this is not instantiated until we actually start trying to do the
     * handshake. This is to allow us to gather information like whether we are
     * going to be in client or server mode before committing to instantiating
     * the channel, since we want to determine the channel arguments based on
     * that.
     *
     * The channel remains available after connection termination until the SSL
     * object is freed, thus (ch != NULL) iff (started == 1).
     */
    QUIC_CHANNEL                    *ch;

    /*
     * The mutex used to synchronise access to the QUIC_CHANNEL. We own this but
     * provide it to the channel.
     */
    CRYPTO_MUTEX                    *mutex;

    /*
     * If we have a default stream attached, this is the internal XSO
     * object. If there is no default stream, this is NULL.
     */
    QUIC_XSO                        *default_xso;

    /* The network read and write BIOs. */
    BIO                             *net_rbio, *net_wbio;

    /* Initial peer L4 address. */
    BIO_ADDR                        init_peer_addr;

#  ifndef OPENSSL_NO_QUIC_THREAD_ASSIST
    /* Manages thread for QUIC thread assisted mode. */
    QUIC_THREAD_ASSIST              thread_assist;
#  endif

    /* If non-NULL, used instead of ossl_time_now(). Used for testing. */
    OSSL_TIME                       (*override_now_cb)(void *arg);
    void                            *override_now_cb_arg;

    /* Number of XSOs allocated. Includes the default XSO, if any. */
    size_t                          num_xso;

    /* Have we started? */
    unsigned int                    started                 : 1;

    /* Can the read and write network BIOs support blocking? */
    unsigned int                    can_poll_net_rbio       : 1;
    unsigned int                    can_poll_net_wbio       : 1;

    /*
     * This is 1 if we were instantiated using a QUIC server method
     * (for future use).
     */
    unsigned int                    as_server               : 1;

    /*
     * Has the application called SSL_set_accept_state? We require this to be
     * congruent with the value of as_server.
     */
    unsigned int                    as_server_state         : 1;

    /* Are we using thread assisted mode? Never changes after init. */
    unsigned int                    is_thread_assisted      : 1;

    /* Do connection-level operations (e.g. handshakes) run in blocking mode? */
    unsigned int                    blocking                : 1;

    /* Do newly created streams start in blocking mode? Inherited by new XSOs. */
    unsigned int                    default_blocking        : 1;

    /* Have we created a default XSO yet? */
    unsigned int                    default_xso_created     : 1;

    /* Default stream type. Defaults to SSL_DEFAULT_STREAM_MODE_AUTO_BIDI. */
    uint32_t                        default_stream_mode;

    /* SSL_set_mode. This is not used directly but inherited by new XSOs. */
    uint32_t                        default_ssl_mode;

    /* SSL_set_incoming_stream_policy. */
    int                             incoming_stream_policy;
    uint64_t                        incoming_stream_aec;

    /*
     * Last 'normal' error during an app-level I/O operation, used by
     * SSL_get_error(); used to track data-path errors like SSL_ERROR_WANT_READ
     * and SSL_ERROR_WANT_WRITE.
     */
    int                             last_error;
};

/* Internal calls to the QUIC CSM which come from various places. */
int ossl_quic_conn_on_handshake_confirmed(QUIC_CONNECTION *qc);

/*
 * To be called when a protocol violation occurs. The connection is torn down
 * with the given error code, which should be a QUIC_ERR_* value. Reason string
 * is optional and copied if provided. frame_type should be 0 if not applicable.
 */
void ossl_quic_conn_raise_protocol_error(QUIC_CONNECTION *qc,
                                         uint64_t error_code,
                                         uint64_t frame_type,
                                         const char *reason);

void ossl_quic_conn_on_remote_conn_close(QUIC_CONNECTION *qc,
                                         OSSL_QUIC_FRAME_CONN_CLOSE *f);

int ossl_quic_trace(int write_p, int version, int content_type,
                    const void *buf, size_t msglen, SSL *ssl, void *arg);

#  define OSSL_QUIC_ANY_VERSION 0xFFFFF

#  define QUIC_CONNECTION_FROM_SSL_int(ssl, c)   \
     ((ssl) == NULL ? NULL                       \
      : ((ssl)->type == SSL_TYPE_QUIC_CONNECTION \
         ? (c QUIC_CONNECTION *)(ssl)            \
         : NULL))

#  define QUIC_XSO_FROM_SSL_int(ssl, c)                             \
    ((ssl) == NULL                                                  \
     ? NULL                                                         \
     : (((ssl)->type == SSL_TYPE_QUIC_XSO                           \
        ? (c QUIC_XSO *)(ssl)                                       \
        : ((ssl)->type == SSL_TYPE_QUIC_CONNECTION                  \
           ? (c QUIC_XSO *)((QUIC_CONNECTION *)(ssl))->default_xso  \
           : NULL))))

#  define SSL_CONNECTION_FROM_QUIC_SSL_int(ssl, c)               \
     ((ssl) == NULL ? NULL                                       \
      : ((ssl)->type == SSL_TYPE_QUIC_CONNECTION                 \
         ? (c SSL_CONNECTION *)((c QUIC_CONNECTION *)(ssl))->tls \
         : NULL))

#  define IS_QUIC(ssl) ((ssl) != NULL                                   \
                        && ((ssl)->type == SSL_TYPE_QUIC_CONNECTION     \
                            || (ssl)->type == SSL_TYPE_QUIC_XSO))
# else
#  define QUIC_CONNECTION_FROM_SSL_int(ssl, c) NULL
#  define QUIC_XSO_FROM_SSL_int(ssl, c) NULL
#  define SSL_CONNECTION_FROM_QUIC_SSL_int(ssl, c) NULL
#  define IS_QUIC(ssl) 0
# endif

# define QUIC_CONNECTION_FROM_SSL(ssl) \
    QUIC_CONNECTION_FROM_SSL_int(ssl, SSL_CONNECTION_NO_CONST)
# define QUIC_CONNECTION_FROM_CONST_SSL(ssl) \
    QUIC_CONNECTION_FROM_SSL_int(ssl, const)
# define QUIC_XSO_FROM_SSL(ssl) \
    QUIC_XSO_FROM_SSL_int(ssl, SSL_CONNECTION_NO_CONST)
# define QUIC_XSO_FROM_CONST_SSL(ssl) \
    QUIC_XSO_FROM_SSL_int(ssl, const)
# define SSL_CONNECTION_FROM_QUIC_SSL(ssl) \
    SSL_CONNECTION_FROM_QUIC_SSL_int(ssl, SSL_CONNECTION_NO_CONST)
# define SSL_CONNECTION_FROM_CONST_QUIC_SSL(ssl) \
    SSL_CONNECTION_FROM_CONST_QUIC_SSL_int(ssl, const)

# define IMPLEMENT_quic_meth_func(version, func_name, q_accept, \
                                 q_connect, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                0, \
                0, \
                ossl_quic_new, \
                ossl_quic_free, \
                ossl_quic_reset, \
                ossl_quic_init, \
                ossl_quic_clear, \
                ossl_quic_deinit, \
                q_accept, \
                q_connect, \
                ossl_quic_read, \
                ossl_quic_peek, \
                ossl_quic_write, \
                ossl_quic_writev, \
                NULL /* shutdown */, \
                NULL /* renegotiate */, \
                ossl_quic_renegotiate_check, \
                NULL /* read_bytes */, \
                NULL /* write_bytes */, \
                NULL /* writev_bytes */, \
                NULL /* dispatch_alert */, \
                ossl_quic_ctrl, \
                ossl_quic_ctx_ctrl, \
                NULL /* get_cipher_by_char */, \
                NULL /* put_cipher_by_char */, \
                ossl_quic_pending, \
                ossl_quic_num_ciphers, \
                ossl_quic_get_cipher, \
                tls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ossl_quic_callback_ctrl, \
                ossl_quic_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }

#endif
