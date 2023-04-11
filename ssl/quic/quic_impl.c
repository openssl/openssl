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
#include <openssl/sslerr.h>
#include <crypto/rand.h>
#include "quic_local.h"
#include "internal/quic_tls.h"
#include "internal/quic_rx_depack.h"
#include "internal/quic_error.h"
#include "internal/time.h"

static void aon_write_finish(QUIC_CONNECTION *qc);
static int ensure_channel(QUIC_CONNECTION *qc);

/*
 * QUIC Front-End I/O API: Common Utilities
 * ========================================
 */

/*
 * Block until a predicate is met.
 *
 * Precondition: Must have a channel.
 * Precondition: Must hold channel lock (unchecked).
 */
QUIC_NEEDS_LOCK
static int block_until_pred(QUIC_CONNECTION *qc,
                            int (*pred)(void *arg), void *pred_arg,
                            uint32_t flags)
{
    QUIC_REACTOR *rtor;

    assert(qc->ch != NULL);

    rtor = ossl_quic_channel_get_reactor(qc->ch);
    return ossl_quic_reactor_block_until_pred(rtor, pred, pred_arg, flags,
                                              qc->mutex);
}

/*
 * Raise a 'normal' error, meaning one that can be reported via SSL_get_error()
 * rather than via ERR.
 */
static int quic_raise_normal_error(QUIC_CONNECTION *qc,
                                   int err)
{
    qc->last_error = err;
    return 0;
}

/*
 * Raise a 'non-normal' error, meaning any error that is not reported via
 * SSL_get_error() and must be reported via ERR.
 */
static int quic_raise_non_normal_error(QUIC_CONNECTION *qc,
                                       const char *file,
                                       int line,
                                       const char *func,
                                       int reason,
                                       const char *fmt,
                                       ...)
{
    va_list args;

    ERR_new();
    ERR_set_debug(file, line, func);

    va_start(args, fmt);
    ERR_vset_error(ERR_LIB_SSL, reason, fmt, args);
    va_end(args);

    qc->last_error = SSL_ERROR_SSL;
    return 0;
}

#define QUIC_RAISE_NORMAL_ERROR(qc, err)                        \
    quic_raise_normal_error((qc), (err))

#define QUIC_RAISE_NON_NORMAL_ERROR(qc, reason, msg)            \
    quic_raise_non_normal_error((qc),                           \
                                OPENSSL_FILE, OPENSSL_LINE,     \
                                OPENSSL_FUNC,                   \
                                (reason),                       \
                                (msg))

/*
 * Should be called at entry of every public function to confirm we have a valid
 * QUIC_CONNECTION.
 */
static ossl_inline int expect_quic_conn(const QUIC_CONNECTION *qc)
{
    if (!ossl_assert(qc != NULL))
        return QUIC_RAISE_NON_NORMAL_ERROR(NULL, ERR_R_INTERNAL_ERROR, NULL);

    return 1;

}

/*
 * Ensures that the channel mutex is held for a method which touches channel
 * state.
 *
 * Precondition: Channel mutex is not held (unchecked)
 */
static void quic_lock(QUIC_CONNECTION *qc)
{
    ossl_crypto_mutex_lock(qc->mutex);
}

/* Precondition: Channel mutex is held (unchecked) */
QUIC_NEEDS_LOCK
static void quic_unlock(QUIC_CONNECTION *qc)
{
    ossl_crypto_mutex_unlock(qc->mutex);
}


/*
 * QUIC Front-End I/O API: Initialization
 * ======================================
 *
 *         SSL_new                  => ossl_quic_new
 *                                     ossl_quic_init
 *         SSL_reset                => ossl_quic_reset
 *         SSL_clear                => ossl_quic_clear
 *                                     ossl_quic_deinit
 *         SSL_free                 => ossl_quic_free
 *
 */

/* SSL_new */
SSL *ossl_quic_new(SSL_CTX *ctx)
{
    QUIC_CONNECTION *qc = NULL;
    SSL *ssl_base = NULL;
    SSL_CONNECTION *sc = NULL;

    qc = OPENSSL_zalloc(sizeof(*qc));
    if (qc == NULL)
        goto err;

    /* Initialise the QUIC_CONNECTION's stub header. */
    ssl_base = &qc->ssl;
    if (!ossl_ssl_init(ssl_base, ctx, ctx->method, SSL_TYPE_QUIC_CONNECTION)) {
        ssl_base = NULL;
        goto err;
    }

    qc->tls = ossl_ssl_connection_new_int(ctx, TLS_method());
    if (qc->tls == NULL || (sc = SSL_CONNECTION_FROM_SSL(qc->tls)) == NULL)
         goto err;

    if ((qc->mutex = ossl_crypto_mutex_new()) == NULL)
        goto err;

    qc->is_thread_assisted
        = (ssl_base->method == OSSL_QUIC_client_thread_method());

    /* Channel is not created yet. */
    qc->ssl_mode   = qc->ssl.ctx->mode;
    qc->last_error = SSL_ERROR_NONE;
    qc->blocking   = 1;

    return ssl_base;

err:
    SSL_free(qc->tls);
    OPENSSL_free(qc);
    return NULL;
}

/* SSL_free */
QUIC_TAKES_LOCK
void ossl_quic_free(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    /* We should never be called on anything but a QUIC_CONNECTION. */
    if (!expect_quic_conn(qc))
        return;

    quic_lock(qc);

    if (qc->is_thread_assisted && qc->started) {
        ossl_quic_thread_assist_wait_stopped(&qc->thread_assist);
        ossl_quic_thread_assist_cleanup(&qc->thread_assist);
    }

    ossl_quic_channel_free(qc->ch);

    BIO_free(qc->net_rbio);
    BIO_free(qc->net_wbio);

    /* Note: SSL_free calls OPENSSL_free(qc) for us */

    SSL_free(qc->tls);
    ossl_crypto_mutex_free(&qc->mutex); /* freed while still locked */
}

/* SSL method init */
int ossl_quic_init(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    /* Same op as SSL_clear, forward the call. */
    return ossl_quic_clear(s);
}

/* SSL method deinit */
void ossl_quic_deinit(SSL *s)
{
    /* No-op. */
}

/* SSL_reset */
int ossl_quic_reset(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    /* TODO(QUIC); Currently a no-op. */
    return 1;
}

/* SSL_clear */
int ossl_quic_clear(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    /* TODO(QUIC): Currently a no-op. */
    return 1;
}

void ossl_quic_conn_set_override_now_cb(SSL *s,
                                        OSSL_TIME (*now_cb)(void *arg),
                                        void *now_cb_arg)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    qc->override_now_cb     = now_cb;
    qc->override_now_cb_arg = now_cb_arg;
}

void ossl_quic_conn_force_assist_thread_wake(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (qc->is_thread_assisted && qc->started)
        ossl_quic_thread_assist_notify_deadline_changed(&qc->thread_assist);
}

/*
 * QUIC Front-End I/O API: Network BIO Configuration
 * =================================================
 *
 * Handling the different BIOs is difficult:
 *
 *   - It is more or less a requirement that we use non-blocking network I/O;
 *     we need to be able to have timeouts on recv() calls, and make best effort
 *     (non blocking) send() and recv() calls.
 *
 *     The only sensible way to do this is to configure the socket into
 *     non-blocking mode. We could try to do select() before calling send() or
 *     recv() to get a guarantee that the call will not block, but this will
 *     probably run into issues with buggy OSes which generate spurious socket
 *     readiness events. In any case, relying on this to work reliably does not
 *     seem sane.
 *
 *     Timeouts could be handled via setsockopt() socket timeout options, but
 *     this depends on OS support and adds another syscall to every network I/O
 *     operation. It also has obvious thread safety concerns if we want to move
 *     to concurrent use of a single socket at some later date.
 *
 *     Some OSes support a MSG_DONTWAIT flag which allows a single I/O option to
 *     be made non-blocking. However some OSes (e.g. Windows) do not support
 *     this, so we cannot rely on this.
 *
 *     As such, we need to configure any FD in non-blocking mode. This may
 *     confound users who pass a blocking socket to libssl. However, in practice
 *     it would be extremely strange for a user of QUIC to pass an FD to us,
 *     then also try and send receive traffic on the same socket(!). Thus the
 *     impact of this should be limited, and can be documented.
 *
 *   - We support both blocking and non-blocking operation in terms of the API
 *     presented to the user. One prospect is to set the blocking mode based on
 *     whether the socket passed to us was already in blocking mode. However,
 *     Windows has no API for determining if a socket is in blocking mode (!),
 *     therefore this cannot be done portably. Currently therefore we expose an
 *     explicit API call to set this, and default to blocking mode.
 *
 *   - We need to determine our initial destination UDP address. The "natural"
 *     way for a user to do this is to set the peer variable on a BIO_dgram.
 *     However, this has problems because BIO_dgram's peer variable is used for
 *     both transmission and reception. This means it can be constantly being
 *     changed to a malicious value (e.g. if some random unrelated entity on the
 *     network starts sending traffic to us) on every read call. This is not a
 *     direct issue because we use the 'stateless' BIO_sendmmsg and BIO_recvmmsg
 *     calls only, which do not use this variable. However, we do need to let
 *     the user specify the peer in a 'normal' manner. The compromise here is
 *     that we grab the current peer value set at the time the write BIO is set
 *     and do not read the value again.
 *
 *   - We also need to support memory BIOs (e.g. BIO_dgram_pair) or custom BIOs.
 *     Currently we do this by only supporting non-blocking mode.
 *
 */

/*
 * Determines what initial destination UDP address we should use, if possible.
 * If this fails the client must set the destination address manually, or use a
 * BIO which does not need a destination address.
 */
static int csm_analyse_init_peer_addr(BIO *net_wbio, BIO_ADDR *peer)
{
    if (BIO_dgram_get_peer(net_wbio, peer) <= 0)
        return 0;

    return 1;
}

void ossl_quic_conn_set0_net_rbio(QUIC_CONNECTION *qc, BIO *net_rbio)
{
    if (qc->net_rbio == net_rbio)
        return;

    if (qc->ch != NULL && !ossl_quic_channel_set_net_rbio(qc->ch, net_rbio))
        return;

    BIO_free(qc->net_rbio);
    qc->net_rbio = net_rbio;

    /*
     * If what we have is not pollable (e.g. a BIO_dgram_pair) disable blocking
     * mode as we do not support it for non-pollable BIOs.
     */
    if (net_rbio != NULL) {
        BIO_POLL_DESCRIPTOR d = {0};

        if (!BIO_get_rpoll_descriptor(net_rbio, &d)
            || d.type != BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD) {
            qc->blocking = 0;
            qc->can_poll_net_rbio = 0;
        } else {
            qc->can_poll_net_rbio = 1;
        }
    }
}

void ossl_quic_conn_set0_net_wbio(QUIC_CONNECTION *qc, BIO *net_wbio)
{
    if (qc->net_wbio == net_wbio)
        return;

    if (qc->ch != NULL && !ossl_quic_channel_set_net_wbio(qc->ch, net_wbio))
        return;

    BIO_free(qc->net_wbio);
    qc->net_wbio = net_wbio;

    if (net_wbio != NULL) {
        BIO_POLL_DESCRIPTOR d = {0};

        if (!BIO_get_wpoll_descriptor(net_wbio, &d)
            || d.type != BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD) {
            qc->blocking = 0;
            qc->can_poll_net_wbio = 0;
        } else {
            qc->can_poll_net_wbio = 1;
        }

        /*
         * If we do not have a peer address yet, and we have not started trying
         * to connect yet, try to autodetect one.
         */
        if (BIO_ADDR_family(&qc->init_peer_addr) == AF_UNSPEC
            && !qc->started) {
            if (!csm_analyse_init_peer_addr(net_wbio, &qc->init_peer_addr))
                /* best effort */
                BIO_ADDR_clear(&qc->init_peer_addr);

            if (qc->ch != NULL)
                ossl_quic_channel_set_peer_addr(qc->ch, &qc->init_peer_addr);
        }
    }
}

BIO *ossl_quic_conn_get_net_rbio(const QUIC_CONNECTION *qc)
{
    return qc->net_rbio;
}

BIO *ossl_quic_conn_get_net_wbio(const QUIC_CONNECTION *qc)
{
    return qc->net_wbio;
}

int ossl_quic_conn_get_blocking_mode(const QUIC_CONNECTION *qc)
{
    return qc->blocking;
}

int ossl_quic_conn_set_blocking_mode(QUIC_CONNECTION *qc, int blocking)
{
    /* Cannot enable blocking mode if we do not have pollable FDs. */
    if (blocking != 0 &&
        (!qc->can_poll_net_rbio || !qc->can_poll_net_wbio))
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_UNSUPPORTED, NULL);

    qc->blocking = (blocking != 0);
    return 1;
}

int ossl_quic_conn_set_initial_peer_addr(QUIC_CONNECTION *qc,
                                         const BIO_ADDR *peer_addr)
{
    if (qc->started)
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
                                           NULL);

    if (peer_addr == NULL) {
        BIO_ADDR_clear(&qc->init_peer_addr);
        return 1;
    }

    qc->init_peer_addr = *peer_addr;
    return 1;
}

/*
 * QUIC Front-End I/O API: Asynchronous I/O Management
 * ===================================================
 *
 *   (BIO/)SSL_tick                 => ossl_quic_tick
 *   (BIO/)SSL_get_tick_timeout     => ossl_quic_get_tick_timeout
 *   (BIO/)SSL_get_poll_fd          => ossl_quic_get_poll_fd
 *
 */

/* Returns 1 if the connection is being used in blocking mode. */
static int blocking_mode(const QUIC_CONNECTION *qc)
{
    return qc->blocking;
}

/* SSL_tick; ticks the reactor. */
QUIC_TAKES_LOCK
int ossl_quic_tick(QUIC_CONNECTION *qc)
{
    quic_lock(qc);

    if (qc->ch == NULL) {
        quic_unlock(qc);
        return 1;
    }

    ossl_quic_reactor_tick(ossl_quic_channel_get_reactor(qc->ch), 0);
    quic_unlock(qc);
    return 1;
}

/*
 * SSL_get_tick_timeout. Get the time in milliseconds until the SSL object
 * should be ticked by the application by calling SSL_tick(). tv is set to 0 if
 * the object should be ticked immediately and tv->tv_sec is set to -1 if no
 * timeout is currently active.
 */
QUIC_TAKES_LOCK
int ossl_quic_get_tick_timeout(QUIC_CONNECTION *qc, struct timeval *tv)
{
    OSSL_TIME deadline = ossl_time_infinite();

    quic_lock(qc);

    if (qc->ch != NULL)
        deadline
            = ossl_quic_reactor_get_tick_deadline(ossl_quic_channel_get_reactor(qc->ch));

    if (ossl_time_is_infinite(deadline)) {
        tv->tv_sec  = -1;
        tv->tv_usec = 0;
        quic_unlock(qc);
        return 1;
    }

    *tv = ossl_time_to_timeval(ossl_time_subtract(deadline, ossl_time_now()));
    quic_unlock(qc);
    return 1;
}

/* SSL_get_rpoll_descriptor */
int ossl_quic_get_rpoll_descriptor(QUIC_CONNECTION *qc, BIO_POLL_DESCRIPTOR *desc)
{
    if (desc == NULL || qc->net_rbio == NULL)
        return 0;

    return BIO_get_rpoll_descriptor(qc->net_rbio, desc);
}

/* SSL_get_wpoll_descriptor */
int ossl_quic_get_wpoll_descriptor(QUIC_CONNECTION *qc, BIO_POLL_DESCRIPTOR *desc)
{
    if (desc == NULL || qc->net_wbio == NULL)
        return 0;

    return BIO_get_wpoll_descriptor(qc->net_wbio, desc);
}

/* SSL_net_read_desired */
QUIC_TAKES_LOCK
int ossl_quic_get_net_read_desired(QUIC_CONNECTION *qc)
{
    int ret;

    quic_lock(qc);

    if (qc->ch == NULL) {
        quic_unlock(qc);
        return 0;
    }

    ret = ossl_quic_reactor_net_read_desired(ossl_quic_channel_get_reactor(qc->ch));
    quic_unlock(qc);
    return ret;
}

/* SSL_net_write_desired */
QUIC_TAKES_LOCK
int ossl_quic_get_net_write_desired(QUIC_CONNECTION *qc)
{
    int ret;

    quic_lock(qc);

    if (qc->ch == NULL) {
        quic_unlock(qc);
        return 0;
    }

    ret = ossl_quic_reactor_net_write_desired(ossl_quic_channel_get_reactor(qc->ch));
    quic_unlock(qc);
    return ret;
}

/*
 * QUIC Front-End I/O API: Connection Lifecycle Operations
 * =======================================================
 *
 *         SSL_do_handshake         => ossl_quic_do_handshake
 *         SSL_set_connect_state    => ossl_quic_set_connect_state
 *         SSL_set_accept_state     => ossl_quic_set_accept_state
 *         SSL_shutdown             => ossl_quic_shutdown
 *         SSL_ctrl                 => ossl_quic_ctrl
 *   (BIO/)SSL_connect              => ossl_quic_connect
 *   (BIO/)SSL_accept               => ossl_quic_accept
 *
 */

/* SSL_shutdown */
static int quic_shutdown_wait(void *arg)
{
    QUIC_CONNECTION *qc = arg;

    return qc->ch == NULL || ossl_quic_channel_is_terminated(qc->ch);
}

QUIC_TAKES_LOCK
int ossl_quic_conn_shutdown(QUIC_CONNECTION *qc, uint64_t flags,
                            const SSL_SHUTDOWN_EX_ARGS *args,
                            size_t args_len)
{
    int ret;

    quic_lock(qc);

    if (!ensure_channel(qc)) {
        quic_unlock(qc);
        return -1;
    }

    ossl_quic_channel_local_close(qc->ch,
                                  args != NULL ? args->quic_error_code : 0);

    /* TODO(QUIC): !SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH */

    if (ossl_quic_channel_is_terminated(qc->ch)) {
        quic_unlock(qc);
        return 1;
    }

    if (blocking_mode(qc) && (flags & SSL_SHUTDOWN_FLAG_RAPID) == 0)
        block_until_pred(qc, quic_shutdown_wait, qc, 0);
    else
        ossl_quic_reactor_tick(ossl_quic_channel_get_reactor(qc->ch), 0);

    ret = ossl_quic_channel_is_terminated(qc->ch);
    quic_unlock(qc);
    return ret;
}

/* SSL_ctrl */
long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    switch (cmd) {
    case SSL_CTRL_MODE:
        /* Cannot enable EPW while AON write in progress. */
        if (qc->aon_write_in_progress)
            larg &= ~SSL_MODE_ENABLE_PARTIAL_WRITE;

        qc->ssl_mode |= (uint32_t)larg;
        return qc->ssl_mode;
    case SSL_CTRL_CLEAR_MODE:
        qc->ssl_mode &= ~(uint32_t)larg;
        return qc->ssl_mode;
    default:
        /* Probably a TLS related ctrl. Defer to our internal SSL object */
        return SSL_ctrl(qc->tls, cmd, larg, parg);
    }
}

/* SSL_set_connect_state */
void ossl_quic_set_connect_state(QUIC_CONNECTION *qc)
{
    /* Cannot be changed after handshake started */
    if (qc->started)
        return;

    qc->as_server = 0;
}

/* SSL_set_accept_state */
void ossl_quic_set_accept_state(QUIC_CONNECTION *qc)
{
    /* Cannot be changed after handshake started */
    if (qc->started)
        return;

    qc->as_server = 1;
}

/* SSL_do_handshake */
struct quic_handshake_wait_args {
    QUIC_CONNECTION     *qc;
};

static int quic_handshake_wait(void *arg)
{
    struct quic_handshake_wait_args *args = arg;

    if (!ossl_quic_channel_is_active(args->qc->ch))
        return -1;

    if (ossl_quic_channel_is_handshake_complete(args->qc->ch))
        return 1;

    return 0;
}

static int configure_channel(QUIC_CONNECTION *qc)
{
    assert(qc->ch != NULL);

    if (!ossl_quic_channel_set_net_rbio(qc->ch, qc->net_rbio)
        || !ossl_quic_channel_set_net_wbio(qc->ch, qc->net_wbio)
        || !ossl_quic_channel_set_peer_addr(qc->ch, &qc->init_peer_addr))
        return 0;

    return 1;
}

QUIC_NEEDS_LOCK
static int ensure_channel(QUIC_CONNECTION *qc)
{
    QUIC_CHANNEL_ARGS args = {0};

    if (qc->ch != NULL)
        return 1;

    args.libctx     = qc->ssl.ctx->libctx;
    args.propq      = qc->ssl.ctx->propq;
    args.is_server  = 0;
    args.tls        = qc->tls;
    args.mutex      = qc->mutex;
    args.now_cb     = qc->override_now_cb;
    args.now_cb_arg = qc->override_now_cb_arg;

    qc->ch = ossl_quic_channel_new(&args);
    if (qc->ch == NULL)
        return 0;

    return 1;
}

/*
 * Creates a channel and configures it with the information we have accumulated
 * via calls made to us from the application prior to starting a handshake
 * attempt.
 */
QUIC_NEEDS_LOCK
static int ensure_channel_and_start(QUIC_CONNECTION *qc)
{
    if (!qc->started) {
        if (!ensure_channel(qc))
            return 0;

        if (!configure_channel(qc)
            || !ossl_quic_channel_start(qc->ch))
            goto err;

        qc->stream0 = ossl_quic_channel_get_stream_by_id(qc->ch, 0);
        if (qc->stream0 == NULL)
            goto err;

        if (qc->is_thread_assisted)
            if (!ossl_quic_thread_assist_init_start(&qc->thread_assist, qc->ch))
                goto err;
    }

    qc->started = 1;
    return 1;

err:
    ossl_quic_channel_free(qc->ch);
    qc->ch = NULL;
    return 0;
}

QUIC_NEEDS_LOCK
static int quic_do_handshake(QUIC_CONNECTION *qc)
{
    int ret;

    if (qc->ch != NULL && ossl_quic_channel_is_handshake_complete(qc->ch))
        /* Handshake already completed. */
        return 1;

    if (qc->ch != NULL && ossl_quic_channel_is_term_any(qc->ch))
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);

    if (BIO_ADDR_family(&qc->init_peer_addr) == AF_UNSPEC) {
        /* Peer address must have been set. */
        QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_REMOTE_PEER_ADDRESS_NOT_SET, NULL);
        return -1; /* Non-protocol error */
    }

    if (qc->as_server) {
        /* TODO(QUIC): Server mode not currently supported */
        QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_PASSED_INVALID_ARGUMENT, NULL);
        return -1; /* Non-protocol error */
    }

    if (qc->net_rbio == NULL || qc->net_wbio == NULL) {
        /* Need read and write BIOs. */
        QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_BIO_NOT_SET, NULL);
        return -1; /* Non-protocol error */
    }

    /*
     * Start connection process. Note we may come here multiple times in
     * non-blocking mode, which is fine.
     */
    if (!ensure_channel_and_start(qc)) {
        QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
        return -1; /* Non-protocol error */
    }

    if (ossl_quic_channel_is_handshake_complete(qc->ch))
        /* The handshake is now done. */
        return 1;

    if (blocking_mode(qc)) {
        /* In blocking mode, wait for the handshake to complete. */
        struct quic_handshake_wait_args args;

        args.qc     = qc;

        ret = block_until_pred(qc, quic_handshake_wait, &args, 0);
        if (!ossl_quic_channel_is_active(qc->ch)) {
            QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);
            return 0; /* Shutdown before completion */
        } else if (ret <= 0) {
            QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
            return -1; /* Non-protocol error */
        }

        assert(ossl_quic_channel_is_handshake_complete(qc->ch));
        return 1;
    } else {
        /* Try to advance the reactor. */
        ossl_quic_reactor_tick(ossl_quic_channel_get_reactor(qc->ch), 0);

        if (ossl_quic_channel_is_handshake_complete(qc->ch))
            /* The handshake is now done. */
            return 1;

        /* Otherwise, indicate that the handshake isn't done yet. */
        QUIC_RAISE_NORMAL_ERROR(qc, SSL_ERROR_WANT_READ);
        return -1; /* Non-protocol error */
    }
}

QUIC_TAKES_LOCK
int ossl_quic_do_handshake(QUIC_CONNECTION *qc)
{
    int ret;

    quic_lock(qc);

    ret = quic_do_handshake(qc);
    quic_unlock(qc);
    return ret;
}

/* SSL_connect */
int ossl_quic_connect(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    /* Ensure we are in connect state (no-op if non-idle). */
    ossl_quic_set_connect_state(qc);

    /* Begin or continue the handshake */
    return ossl_quic_do_handshake(qc);
}

/* SSL_accept */
int ossl_quic_accept(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    /* Ensure we are in accept state (no-op if non-idle). */
    ossl_quic_set_accept_state(qc);

    /* Begin or continue the handshake */
    return ossl_quic_do_handshake(qc);
}

/*
 * QUIC Front-End I/O API: Steady-State Operations
 * ===============================================
 *
 * Here we dispatch calls to the steady-state front-end I/O API functions; that
 * is, the functions used during the established phase of a QUIC connection
 * (e.g. SSL_read, SSL_write).
 *
 * Each function must handle both blocking and non-blocking modes. As discussed
 * above, all QUIC I/O is implemented using non-blocking mode internally.
 *
 *         SSL_get_error        => partially implemented by ossl_quic_get_error
 *   (BIO/)SSL_read             => ossl_quic_read
 *   (BIO/)SSL_write            => ossl_quic_write
 *         SSL_pending          => ossl_quic_pending
 *         SSL_stream_conclude  => ossl_quic_conn_stream_conclude
 */

/* SSL_get_error */
int ossl_quic_get_error(const QUIC_CONNECTION *qc, int i)
{
    return qc->last_error;
}

/*
 * SSL_write
 * ---------
 *
 * The set of functions below provide the implementation of the public SSL_write
 * function. We must handle:
 *
 *   - both blocking and non-blocking operation at the application level,
 *     depending on how we are configured;
 *
 *   - SSL_MODE_ENABLE_PARTIAL_WRITE being on or off;
 *
 *   - SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER.
 *
 */
QUIC_NEEDS_LOCK
static void quic_post_write(QUIC_CONNECTION *qc, int did_append, int do_tick)
{
    /*
     * We have appended at least one byte to the stream.
     * Potentially mark stream as active, depending on FC.
     */
    if (did_append)
        ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(qc->ch),
                                          qc->stream0);

    /*
     * Try and send.
     *
     * TODO(QUIC): It is probably inefficient to try and do this immediately,
     * plus we should eventually consider Nagle's algorithm.
     */
    if (do_tick)
        ossl_quic_reactor_tick(ossl_quic_channel_get_reactor(qc->ch), 0);
}

struct quic_write_again_args {
    QUIC_CONNECTION     *qc;
    const unsigned char *buf;
    size_t              len;
    size_t              total_written;
};

QUIC_NEEDS_LOCK
static int quic_write_again(void *arg)
{
    struct quic_write_again_args *args = arg;
    size_t actual_written = 0;

    if (!ossl_quic_channel_is_active(args->qc->ch))
        /* If connection is torn down due to an error while blocking, stop. */
        return -2;

    if (!ossl_quic_sstream_append(args->qc->stream0->sstream,
                                  args->buf, args->len, &actual_written))
        return -2;

    quic_post_write(args->qc, actual_written > 0, 0);

    args->buf           += actual_written;
    args->len           -= actual_written;
    args->total_written += actual_written;

    if (args->len == 0)
        /* Written everything, done. */
        return 1;

    /* Not written everything yet, keep trying. */
    return 0;
}

QUIC_NEEDS_LOCK
static int quic_write_blocking(QUIC_CONNECTION *qc, const void *buf, size_t len,
                               size_t *written)
{
    int res;
    struct quic_write_again_args args;
    size_t actual_written = 0;

    /* First make a best effort to append as much of the data as possible. */
    if (!ossl_quic_sstream_append(qc->stream0->sstream, buf, len,
                                  &actual_written)) {
        /* Stream already finished or allocation error. */
        *written = 0;
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
    }

    quic_post_write(qc, actual_written > 0, 1);

    if (actual_written == len) {
        /* Managed to append everything on the first try. */
        *written = actual_written;
        return 1;
    }

    /*
     * We did not manage to append all of the data immediately, so the stream
     * buffer has probably filled up. This means we need to block until some of
     * it is freed up.
     */
    args.qc             = qc;
    args.buf            = (const unsigned char *)buf + actual_written;
    args.len            = len - actual_written;
    args.total_written  = 0;

    res = block_until_pred(qc, quic_write_again, &args, 0);
    if (res <= 0) {
        if (!ossl_quic_channel_is_active(qc->ch))
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);
        else
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
    }

    *written = args.total_written;
    return 1;
}

/*
 * Functions to manage All-or-Nothing (AON) (that is, non-ENABLE_PARTIAL_WRITE)
 * write semantics.
 */
static void aon_write_begin(QUIC_CONNECTION *qc, const unsigned char *buf,
                            size_t buf_len, size_t already_sent)
{
    assert(!qc->aon_write_in_progress);

    qc->aon_write_in_progress = 1;
    qc->aon_buf_base          = buf;
    qc->aon_buf_pos           = already_sent;
    qc->aon_buf_len           = buf_len;
}

static void aon_write_finish(QUIC_CONNECTION *qc)
{
    qc->aon_write_in_progress   = 0;
    qc->aon_buf_base            = NULL;
    qc->aon_buf_pos             = 0;
    qc->aon_buf_len             = 0;
}

QUIC_NEEDS_LOCK
static int quic_write_nonblocking_aon(QUIC_CONNECTION *qc, const void *buf,
                                      size_t len, size_t *written)
{
    const void *actual_buf;
    size_t actual_len, actual_written = 0;
    int accept_moving_buffer
        = ((qc->ssl_mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) != 0);

    if (qc->aon_write_in_progress) {
        /*
         * We are in the middle of an AON write (i.e., a previous write did not
         * manage to append all data to the SSTREAM and we have Enable Partial
         * Write (EPW) mode disabled.)
         */
        if ((!accept_moving_buffer && qc->aon_buf_base != buf)
            || len != qc->aon_buf_len)
            /*
             * Pointer must not have changed if we are not in accept moving
             * buffer mode. Length must never change.
             */
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_BAD_WRITE_RETRY, NULL);

        actual_buf = (unsigned char *)buf + qc->aon_buf_pos;
        actual_len = len - qc->aon_buf_pos;
        assert(actual_len > 0);
    } else {
        actual_buf = buf;
        actual_len = len;
    }

    /* First make a best effort to append as much of the data as possible. */
    if (!ossl_quic_sstream_append(qc->stream0->sstream, actual_buf, actual_len,
                                  &actual_written)) {
        /* Stream already finished or allocation error. */
        *written = 0;
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
    }

    quic_post_write(qc, actual_written > 0, 1);

    if (actual_written == actual_len) {
        /* We have sent everything. */
        if (qc->aon_write_in_progress) {
            /*
             * We have sent everything, and we were in the middle of an AON
             * write. The output write length is the total length of the AON
             * buffer, not however many bytes we managed to write to the stream
             * in this call.
             */
            *written = qc->aon_buf_len;
            aon_write_finish(qc);
        } else {
            *written = actual_written;
        }

        return 1;
    }

    if (qc->aon_write_in_progress) {
        /*
         * AON write is in progress but we have not written everything yet. We
         * may have managed to send zero bytes, or some number of bytes less
         * than the total remaining which need to be appended during this
         * AON operation.
         */
        qc->aon_buf_pos += actual_written;
        assert(qc->aon_buf_pos < qc->aon_buf_len);
        return QUIC_RAISE_NORMAL_ERROR(qc, SSL_ERROR_WANT_WRITE);
    }

    /*
     * Not in an existing AON operation but partial write is not enabled, so we
     * need to begin a new AON operation. However we needn't bother if we didn't
     * actually append anything.
     */
    if (actual_written > 0)
        aon_write_begin(qc, buf, len, actual_written);

    /*
     * AON - We do not publicly admit to having appended anything until AON
     * completes.
     */
    *written = 0;
    return QUIC_RAISE_NORMAL_ERROR(qc, SSL_ERROR_WANT_WRITE);
}

QUIC_NEEDS_LOCK
static int quic_write_nonblocking_epw(QUIC_CONNECTION *qc, const void *buf, size_t len,
                                      size_t *written)
{
    /* Simple best effort operation. */
    if (!ossl_quic_sstream_append(qc->stream0->sstream, buf, len, written)) {
        /* Stream already finished or allocation error. */
        *written = 0;
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
    }

    quic_post_write(qc, *written > 0, 1);
    return 1;
}

QUIC_TAKES_LOCK
int ossl_quic_write(SSL *s, const void *buf, size_t len, size_t *written)
{
    int ret;
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);
    int partial_write = ((qc->ssl_mode & SSL_MODE_ENABLE_PARTIAL_WRITE) != 0);

    *written = 0;

    if (!expect_quic_conn(qc))
        return 0;

    quic_lock(qc);

    if (qc->ch != NULL && ossl_quic_channel_is_term_any(qc->ch)) {
        ret = QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);
        goto out;
    }

    /*
     * If we haven't finished the handshake, try to advance it.
     * We don't accept writes until the handshake is completed.
     */
    if (quic_do_handshake(qc) < 1) {
        ret = 0;
        goto out;
    }

    if (qc->stream0 == NULL || qc->stream0->sstream == NULL) {
        ret = QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
        goto out;
    }

    if (blocking_mode(qc))
        ret = quic_write_blocking(qc, buf, len, written);
    else if (partial_write)
        ret = quic_write_nonblocking_epw(qc, buf, len, written);
    else
        ret = quic_write_nonblocking_aon(qc, buf, len, written);

out:
    quic_unlock(qc);
    return ret;
}

/*
 * SSL_read
 * --------
 */
struct quic_read_again_args {
    QUIC_CONNECTION *qc;
    QUIC_STREAM     *stream;
    void            *buf;
    size_t          len;
    size_t          *bytes_read;
    int             peek;
};

QUIC_NEEDS_LOCK
static int quic_read_actual(QUIC_CONNECTION *qc,
                            QUIC_STREAM *stream,
                            void *buf, size_t buf_len,
                            size_t *bytes_read,
                            int peek)
{
    int is_fin = 0;

    /* If the receive part of the stream is over, issue EOF. */
    if (stream->recv_fin_retired)
        return QUIC_RAISE_NORMAL_ERROR(qc, SSL_ERROR_ZERO_RETURN);

    if (stream->rstream == NULL)
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);

    if (peek) {
        if (!ossl_quic_rstream_peek(stream->rstream, buf, buf_len,
                                    bytes_read, &is_fin))
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);

    } else {
        if (!ossl_quic_rstream_read(stream->rstream, buf, buf_len,
                                    bytes_read, &is_fin))
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
    }

    if (!peek) {
        if (*bytes_read > 0) {
            /*
             * We have read at least one byte from the stream. Inform stream-level
             * RXFC of the retirement of controlled bytes. Update the active stream
             * status (the RXFC may now want to emit a frame granting more credit to
             * the peer).
             */
            OSSL_RTT_INFO rtt_info;

            ossl_statm_get_rtt_info(ossl_quic_channel_get_statm(qc->ch), &rtt_info);

            if (!ossl_quic_rxfc_on_retire(&qc->stream0->rxfc, *bytes_read,
                                          rtt_info.smoothed_rtt))
                return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
        }

        if (is_fin)
            stream->recv_fin_retired = 1;

        if (*bytes_read > 0)
            ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(qc->ch),
                                              qc->stream0);
    }

    return 1;
}

QUIC_NEEDS_LOCK
static int quic_read_again(void *arg)
{
    struct quic_read_again_args *args = arg;

    if (!ossl_quic_channel_is_active(args->qc->ch)) {
        /* If connection is torn down due to an error while blocking, stop. */
        QUIC_RAISE_NON_NORMAL_ERROR(args->qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);
        return -1;
    }

    if (!quic_read_actual(args->qc, args->stream,
                          args->buf, args->len, args->bytes_read,
                          args->peek))
        return -1;

    if (*args->bytes_read > 0)
        /* got at least one byte, the SSL_read op can finish now */
        return 1;

    return 0; /* did not read anything, keep trying */
}

QUIC_TAKES_LOCK
static int quic_read(SSL *s, void *buf, size_t len, size_t *bytes_read, int peek)
{
    int ret, res;
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);
    struct quic_read_again_args args;

    *bytes_read = 0;

    if (!expect_quic_conn(qc))
        return 0;

    quic_lock(qc);

    if (qc->ch != NULL && ossl_quic_channel_is_term_any(qc->ch)) {
        ret = QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);
        goto out;
    }

    /* If we haven't finished the handshake, try to advance it. */
    if (quic_do_handshake(qc) < 1) {
        ret = 0; /* ossl_quic_do_handshake raised error here */
        goto out;
    }

    if (qc->stream0 == NULL) {
        ret = QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
        goto out;
    }

    if (!quic_read_actual(qc, qc->stream0, buf, len, bytes_read, peek)) {
        ret = 0; /* quic_read_actual raised error here */
        goto out;
    }

    if (*bytes_read > 0) {
        /*
         * Even though we succeeded, tick the reactor here to ensure we are
         * handling other aspects of the QUIC connection.
         */
        ossl_quic_reactor_tick(ossl_quic_channel_get_reactor(qc->ch), 0);
        ret = 1;
    } else if (blocking_mode(qc)) {
        /*
         * We were not able to read anything immediately, so our stream
         * buffer is empty. This means we need to block until we get
         * at least one byte.
         */
        args.qc         = qc;
        args.stream     = qc->stream0;
        args.buf        = buf;
        args.len        = len;
        args.bytes_read = bytes_read;
        args.peek       = peek;

        res = block_until_pred(qc, quic_read_again, &args, 0);
        if (res == 0) {
            ret = QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
            goto out;
        } else if (res < 0) {
            ret = 0; /* quic_read_again raised error here */
            goto out;
        }

        ret = 1;
    } else {
        /* We did not get any bytes and are not in blocking mode. */
        ret = QUIC_RAISE_NORMAL_ERROR(qc, SSL_ERROR_WANT_READ);
    }

out:
    quic_unlock(qc);
    return ret;
}

int ossl_quic_read(SSL *s, void *buf, size_t len, size_t *bytes_read)
{
    return quic_read(s, buf, len, bytes_read, 0);
}

int ossl_quic_peek(SSL *s, void *buf, size_t len, size_t *bytes_read)
{
    return quic_read(s, buf, len, bytes_read, 1);
}

/*
 * SSL_pending
 * -----------
 */
QUIC_TAKES_LOCK
static size_t ossl_quic_pending_int(const QUIC_CONNECTION *qc)
{
    size_t avail = 0;
    int fin = 0;

    if (!expect_quic_conn(qc))
        return 0;

    quic_lock((QUIC_CONNECTION *)qc);

    if (qc->stream0 == NULL || qc->stream0->rstream == NULL)
        /* Cannot raise errors here because we are const, just fail. */
        goto out;

    if (!ossl_quic_rstream_available(qc->stream0->rstream, &avail, &fin))
        avail = 0;

out:
    quic_unlock((QUIC_CONNECTION *)qc);
    return avail;
}

size_t ossl_quic_pending(const SSL *s)
{
    const QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_CONST_SSL(s);

    return ossl_quic_pending_int(qc);
}

int ossl_quic_has_pending(const QUIC_CONNECTION *qc)
{
    return ossl_quic_pending_int(qc) > 0;
}

/*
 * SSL_stream_conclude
 * -------------------
 */
QUIC_TAKES_LOCK
int ossl_quic_conn_stream_conclude(QUIC_CONNECTION *qc)
{
    QUIC_STREAM *qs = qc->stream0;

    quic_lock(qc);

    if (qs == NULL || qs->sstream == NULL) {
        quic_unlock(qc);
        return 0;
    }

    if (!ossl_quic_channel_is_active(qc->ch)
        || ossl_quic_sstream_get_final_size(qs->sstream, NULL)) {
        quic_unlock(qc);
        return 1;
    }

    ossl_quic_sstream_fin(qs->sstream);
    quic_post_write(qc, 1, 1);
    quic_unlock(qc);
    return 1;
}

/*
 * SSL_inject_net_dgram
 * --------------------
 */
QUIC_TAKES_LOCK
int SSL_inject_net_dgram(SSL *s, const unsigned char *buf,
                         size_t buf_len,
                         const BIO_ADDR *peer,
                         const BIO_ADDR *local)
{
    int ret;
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);
    QUIC_DEMUX *demux;

    if (!expect_quic_conn(qc))
        return 0;

    quic_lock(qc);

    if (qc->ch == NULL) {
        ret = QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
                                          NULL);
        goto err;
    }

    demux = ossl_quic_channel_get0_demux(qc->ch);
    ret = ossl_quic_demux_inject(demux, buf, buf_len, peer, local);

err:
    quic_unlock(qc);
    return ret;
}

/*
 * QUIC Front-End I/O API: SSL_CTX Management
 * ==========================================
 */

long ossl_quic_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    switch (cmd) {
    default:
        return ssl3_ctx_ctrl(ctx, cmd, larg, parg);
    }
}

long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void))
{
    return ssl3_callback_ctrl(s, cmd, fp);
}

long ossl_quic_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
{
    return ssl3_ctx_callback_ctrl(ctx, cmd, fp);
}

int ossl_quic_renegotiate_check(SSL *ssl, int initok)
{
    /* We never do renegotiation. */
    return 0;
}

/*
 * These functions define the TLSv1.2 (and below) ciphers that are supported by
 * the SSL_METHOD. Since QUIC only supports TLSv1.3 we don't support any.
 */

int ossl_quic_num_ciphers(void)
{
    return 0;
}

const SSL_CIPHER *ossl_quic_get_cipher(unsigned int u)
{
    return NULL;
}
