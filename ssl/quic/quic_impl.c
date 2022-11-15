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
#include "internal/quic_dummy_handshake.h"
#include "internal/quic_rx_depack.h"
#include "internal/quic_error.h"
#include "internal/time.h"

#define INIT_DCID_LEN           8
#define INIT_CRYPTO_BUF_LEN     8192
#define INIT_APP_BUF_LEN        8192

#define QUIC_RAISE_NORMAL_ERROR(qc, err)                        \
    quic_raise_normal_error((qc), (err))

#define QUIC_RAISE_NON_NORMAL_ERROR(qc, reason, msg)            \
    quic_raise_non_normal_error((qc),                           \
                                OPENSSL_FILE, OPENSSL_LINE,     \
                                OPENSSL_FUNC,                   \
                                (reason),                       \
                                (msg))

static int quic_raise_normal_error(QUIC_CONNECTION *qc,
                                   int err);

static int quic_raise_non_normal_error(QUIC_CONNECTION *qc,
                                       const char *file,
                                       int line,
                                       const char *func,
                                       int reason,
                                       const char *fmt,
                                       ...);

static void csm_tick(QUIC_TICK_RESULT *res, void *arg);
static OSSL_TIME csm_determine_next_tick_deadline(QUIC_CONNECTION *qc);

static int csm_on_crypto_send(const unsigned char *buf, size_t buf_len,
                              size_t *consumed, void *arg);
static int csm_on_crypto_recv(unsigned char *buf, size_t buf_len,
                              size_t *bytes_read, void *arg);
static int csm_on_handshake_yield_secret(uint32_t enc_level, int direction,
                                         uint32_t suite_id, EVP_MD *md,
                                         const unsigned char *secret,
                                         size_t secret_len,
                                         void *arg);
static int csm_on_handshake_complete(void *arg);
static int csm_on_handshake_alert(void *arg, unsigned char alert_code);
static int csm_generate_transport_params(QUIC_CONNECTION *qc,
                                         unsigned char **buf_p,
                                         size_t *buf_len_p);
static int csm_discard_el(QUIC_CONNECTION *qc, uint32_t enc_level);
static int csm_on_transport_params(const unsigned char *params,
                                   size_t params_len,
                                   void *arg);
static void csm_on_terminating_timeout(QUIC_CONNECTION *qc);
static void csm_update_idle(QUIC_CONNECTION *qc);
static void csm_on_idle_timeout(QUIC_CONNECTION *qc);
static void aon_write_finish(QUIC_CONNECTION *qc);

static ossl_inline int expect_quic_conn(const QUIC_CONNECTION *qc)
{
    if (!ossl_assert(qc != NULL))
        return QUIC_RAISE_NON_NORMAL_ERROR(NULL, ERR_R_INTERNAL_ERROR, NULL);

    return 1;
}

/*
 * Core I/O Reactor Framework
 * ==========================
 *
 * Manages use of async network I/O which the QUIC stack is built on. The core
 * mechanic looks like this:
 *
 *   - There is a pollable FD for both the read and write side respectively.
 *     Readability and writeability of these FDs respectively determines when
 *     network I/O is available.
 *
 *   - The reactor can export these FDs to the user, as well as flags indicating
 *     whether the user should listen for readability, writeability, or neither.
 *
 *   - The reactor can export a timeout indication to the user, indicating when
 *     the reactor should be called (via libssl APIs) regardless of whether
 *     the network socket has become ready.
 *
 * The reactor is based around a tick callback which is essentially the mutator
 * function. The mutator attempts to do whatever it can, attempting to perform
 * network I/O to the extent currently feasible. When done, the mutator returns
 * information to the reactor indicating when it should be woken up again:
 *
 *   - Should it be woken up when network RX is possible?
 *   - Should it be woken up when network TX is possible?
 *   - Should it be woken up no later than some deadline X?
 *
 * The intention is that ALL I/O-related SSL_* functions with side effects (e.g.
 * SSL_read/SSL_write) consist of three phases:
 *
 *   - Optionally mutate the QUIC machine's state.
 *   - Optionally tick the QUIC reactor.
 *   - Optionally mutate the QUIC machine's state.
 *
 * For example, SSL_write is a mutation (appending to a stream buffer) followed
 * by an optional tick (generally expected as we may want to send the data
 * immediately, though not strictly needed if transmission is being deferred due
 * to Nagle's algorithm, etc.).
 *
 * SSL_read is also a mutation and in principle does not need to tick the
 * reactor, but it generally will anyway to ensure that the reactor is regularly
 * ticked by an application which is only reading and not writing.
 *
 * If the SSL object is being used in blocking mode, SSL_read may need to block
 * if no data is available yet, and SSL_write may need to block if buffers
 * are full.
 *
 * The internals of the QUIC I/O engine always use asynchronous I/O. If the
 * application desires blocking semantics, we handle this by adding a blocking
 * adaptation layer on top of our internal asynchronous I/O API as exposed by
 * the reactor interface.
 */
static void reactor_init(QUIC_REACTOR *rtor,
                         void (*tick_cb)(QUIC_TICK_RESULT *res, void *arg),
                         void *tick_cb_arg,
                         OSSL_TIME initial_tick_deadline)
{
    rtor->poll_r.type       = BIO_POLL_DESCRIPTOR_TYPE_NONE;
    rtor->poll_w.type       = BIO_POLL_DESCRIPTOR_TYPE_NONE;
    rtor->want_net_read     = 0;
    rtor->want_net_write    = 0;
    rtor->tick_deadline     = initial_tick_deadline;

    rtor->tick_cb           = tick_cb;
    rtor->tick_cb_arg       = tick_cb_arg;
}

static void reactor_set_poll_r(QUIC_REACTOR *rtor, const BIO_POLL_DESCRIPTOR *r)
{
    rtor->poll_r = *r;
}

static void reactor_set_poll_w(QUIC_REACTOR *rtor, const BIO_POLL_DESCRIPTOR *w)
{
    rtor->poll_w = *w;
}

static const BIO_POLL_DESCRIPTOR *reactor_get_poll_r(QUIC_REACTOR *rtor)
{
    return &rtor->poll_r;
}

static const BIO_POLL_DESCRIPTOR *reactor_get_poll_w(QUIC_REACTOR *rtor)
{
    return &rtor->poll_w;
}

static int reactor_want_net_read(QUIC_REACTOR *rtor)
{
    return rtor->want_net_read;
}

static int reactor_want_net_write(QUIC_REACTOR *rtor)
{
    return rtor->want_net_write;
}

static OSSL_TIME reactor_get_tick_deadline(QUIC_REACTOR *rtor)
{
    return rtor->tick_deadline;
}

/*
 * Do whatever work can be done, and as much work as can be done. This involves
 * e.g. seeing if we can read anything from the network (if we want to), seeing
 * if we can write anything to the network (if we want to), etc.
 */
static int reactor_tick(QUIC_REACTOR *rtor)
{
    QUIC_TICK_RESULT res = {0};

    /*
     * Note that the tick callback cannot fail; this is intentional. Arguably it
     * does not make that much sense for ticking to 'fail' (in the sense of an
     * explicit error indicated to the user) because ticking is by its nature
     * best effort. If something fatal happens with a connection we can report
     * it on the next actual application I/O call.
     */
    rtor->tick_cb(&res, rtor->tick_cb_arg);

    rtor->want_net_read     = res.want_net_read;
    rtor->want_net_write    = res.want_net_write;
    rtor->tick_deadline     = res.tick_deadline;
    return 1;
}

/*
 * Blocking I/O Adaptation Layer
 * =============================
 *
 * The blocking I/O adaptation layer implements blocking I/O on top of our
 * asynchronous core.
 *
 * The core mechanism is reactor_block_until_pred(), which does not return until
 * pred() returns a value other than 0. The blocker uses OS I/O synchronisation
 * primitives (e.g. poll(2)) and ticks the reactor until the predicate is
 * satisfied. The blocker is not required to call pred() more than once between
 * tick calls.
 *
 * When pred returns a non-zero value, that value is returned by this function.
 * This can be used to allow pred() to indicate error conditions and short
 * circuit the blocking process.
 *
 * A return value of -1 is reserved for network polling errors. Therefore this
 * return value should not be used by pred() if ambiguity is not desired. Note
 * that the predicate function can always arrange its own output mechanism, for
 * example by passing a structure of its own as the argument.
 *
 * If the SKIP_FIRST_TICK flag is set, the first call to reactor_tick() before
 * the first call to pred() is skipped. This is useful if it is known that
 * ticking the reactor again will not be useful (e.g. because it has already
 * been done).
 */
#define SKIP_FIRST_TICK     (1U << 0)

/*
 * Utility which can be used to poll on up to two FDs. This is designed to
 * support use of split FDs (e.g. with SSL_set_rfd and SSL_set_wfd where
 * different FDs are used for read and write).
 *
 * Generally use of poll(2) is preferred where available. Windows, however,
 * hasn't traditionally offered poll(2), only select(2). WSAPoll() was
 * introduced in Vista but has seemingly been buggy until relatively recent
 * versions of Windows 10. Moreover we support XP so this is not a suitable
 * target anyway. However, the traditional issues with select(2) turn out not to
 * be an issue on Windows; whereas traditional *NIX select(2) uses a bitmap of
 * FDs (and thus is limited in the magnitude of the FDs expressible), Windows
 * select(2) is very different. In Windows, socket handles are not allocated
 * contiguously from zero and thus this bitmap approach was infeasible. Thus in
 * adapting the Berkeley sockets API to Windows a different approach was taken
 * whereby the fd_set contains a fixed length array of socket handles and an
 * integer indicating how many entries are valid; thus Windows select()
 * ironically is actually much more like *NIX poll(2) than *NIX select(2). In
 * any case, this means that the relevant limit for Windows select() is the
 * number of FDs being polled, not the magnitude of those FDs. Since we only
 * poll for two FDs here, this limit does not concern us.
 *
 * Usage: rfd and wfd may be the same or different. Either or both may also be
 * -1. If rfd_want_read is 1, rfd is polled for readability, and if
 * wfd_want_write is 1, wfd is polled for writability. Note that since any
 * passed FD is always polled for error conditions, setting rfd_want_read=0 and
 * wfd_want_write=0 is not the same as passing -1 for both FDs.
 *
 * deadline is a timestamp to return at. If it is ossl_time_infinite(), the call
 * never times out.
 *
 * Returns 0 on error and 1 on success. Timeout expiry is considered a success
 * condition. We don't elaborate our return values here because the way we are
 * actually using this doesn't currently care.
 */
static int poll_two_fds(int rfd, int rfd_want_read,
                        int wfd, int wfd_want_write,
                        OSSL_TIME deadline)
{
#if defined(OSSL_SYS_WINDOWS) || !defined(POLLIN)
    fd_set rfd_set, wfd_set, efd_set;
    OSSL_TIME now, timeout;
    struct timeval tv, *ptv;
    int maxfd, pres;

#ifndef OSSL_SYS_WINDOWS
    /*
     * On Windows there is no relevant limit to the magnitude of a fd value (see
     * above). On *NIX the fd_set uses a bitmap and we must check the limit.
     */
    if (rfd >= FD_SETSIZE || wfd >= FD_SETSIZE)
        return 0;
#endif

    FD_ZERO(&rfd_set);
    FD_ZERO(&wfd_set);
    FD_ZERO(&efd_set);

    if (rfd != -1 && rfd_want_read)
        openssl_fdset(rfd, &rfd_set);
    if (wfd != -1 && wfd_want_write)
        openssl_fdset(wfd, &wfd_set);

    /* Always check for error conditions. */
    if (rfd != -1)
        openssl_fdset(rfd, &efd_set);
    if (wfd != -1)
        openssl_fdset(wfd, &efd_set);

    maxfd = rfd;
    if (wfd > maxfd)
        maxfd = wfd;

    if (rfd == -1 && wfd == -1 && ossl_time_is_infinite(deadline))
        /* Do not block forever; should not happen. */
        return 0;

    do {
        /*
         * select expects a timeout, not a deadline, so do the conversion.
         * Update for each call to ensure the correct value is used if we repeat
         * due to EINTR.
         */
        if (ossl_time_is_infinite(deadline)) {
            ptv = NULL;
        } else {
            now = ossl_time_now();
            /*
             * ossl_time_subtract saturates to zero so we don't need to check if
             * now > deadline.
             */
            timeout = ossl_time_subtract(deadline, now);
            tv      = ossl_time_to_timeval(timeout);
            ptv     = &tv;
        }

        pres = select(maxfd + 1, &rfd_set, &wfd_set, &efd_set, ptv);
    } while (pres == -1 && get_last_socket_error_is_eintr());

    return pres < 0 ? 0 : 1;
#else
    int pres, timeout_ms;
    OSSL_TIME now, timeout;
    struct pollfd pfds[2] = {0};
    size_t npfd = 0;

    if (rfd == wfd) {
        pfds[npfd].fd = rfd;
        pfds[npfd].events = (rfd_want_read  ? POLLIN  : 0)
                          | (wfd_want_write ? POLLOUT : 0);
        if (rfd >= 0 && pfds[npfd].events != 0)
            ++npfd;
    } else {
        pfds[npfd].fd     = rfd;
        pfds[npfd].events = (rfd_want_read ? POLLIN : 0);
        if (rfd >= 0 && pfds[npfd].events != 0)
            ++npfd;

        pfds[npfd].fd     = wfd;
        pfds[npfd].events = (wfd_want_write ? POLLOUT : 0);
        if (wfd >= 0 && pfds[npfd].events != 0)
            ++npfd;
    }

    if (npfd == 0 && ossl_time_is_infinite(deadline))
        /* Do not block forever; should not happen. */
        return 0;

    do {
        if (ossl_time_is_infinite(deadline)) {
            timeout_ms = -1;
        } else {
            now         = ossl_time_now();
            timeout     = ossl_time_subtract(deadline, now);
            timeout_ms  = ossl_time2ms(timeout);
        }

        pres = poll(pfds, npfd, timeout_ms);
    } while (pres == -1 && errno == EINTR);

    return pres < 0 ? 0 : 1;
#endif
}

static int poll_descriptor_to_fd(const BIO_POLL_DESCRIPTOR *d, int *fd)
{
    if (d == NULL || d->type == BIO_POLL_DESCRIPTOR_TYPE_NONE) {
        *fd = -1;
        return 1;
    }

    if (d->type != BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD || d->value.fd < 0)
        return 0;

    *fd = d->value.fd;
    return 1;
}

/*
 * Poll up to two abstract poll descriptors. Currently we only support
 * poll descriptors which represent FDs.
 */
static int poll_two_descriptors(const BIO_POLL_DESCRIPTOR *r, int r_want_read,
                                const BIO_POLL_DESCRIPTOR *w, int w_want_write,
                                OSSL_TIME deadline)
{
    int rfd, wfd;

    if (!poll_descriptor_to_fd(r, &rfd)
        || !poll_descriptor_to_fd(w, &wfd))
        return 0;

    return poll_two_fds(rfd, r_want_read, wfd, w_want_write, deadline);
}

/* Must only be called if we are in blocking mode. */
static int reactor_block_until_pred(QUIC_REACTOR *rtor,
                                    int (*pred)(void *arg), void *pred_arg,
                                    uint32_t flags)
{
    int res;

    for (;;) {
        if ((flags & SKIP_FIRST_TICK) != 0)
            flags &= ~SKIP_FIRST_TICK;
        else
            reactor_tick(rtor); /* best effort */

        if ((res = pred(pred_arg)) != 0)
            return res;

        if (!poll_two_descriptors(reactor_get_poll_r(rtor),
                                  reactor_want_net_read(rtor),
                                  reactor_get_poll_w(rtor),
                                  reactor_want_net_write(rtor),
                                  reactor_get_tick_deadline(rtor)))
            /*
             * We don't actually care why the call succeeded (timeout, FD
             * readiness), we just call reactor_tick and start trying to do I/O
             * things again. If poll_two_fds returns 0, this is some other
             * non-timeout failure and we should stop here.
             *
             * TODO(QUIC): In the future we could avoid unnecessary syscalls by
             * not retrying network I/O that isn't ready based on the result of
             * the poll call. However this might be difficult because it
             * requires we do the call to poll(2) or equivalent syscall
             * ourselves, whereas in the general case the application does the
             * polling and just calls SSL_tick(). Implementing this optimisation
             * in the future will probably therefore require API changes.
             */
            return 0;
    }
}

/*
 * QUIC Connection State Machine: Initialization
 * =============================================
 */

static OSSL_TIME get_time(void *arg)
{
    return ossl_time_now();
}

static uint64_t get_stream_limit(int uni, void *arg)
{
    QUIC_CONNECTION *qc = arg;

    return uni ? qc->max_local_streams_uni : qc->max_local_streams_bidi;
}

static int is_active(const QUIC_CONNECTION *qc)
{
    return qc->state == QUIC_CONN_STATE_ACTIVE;
}

/* True if the connection is terminating. */
static int is_terminating(const QUIC_CONNECTION *qc)
{
    return qc->state == QUIC_CONN_STATE_TERMINATING_CLOSING
        || qc->state == QUIC_CONN_STATE_TERMINATING_DRAINING;
}

static int is_terminated(const QUIC_CONNECTION *qc)
{
    return qc->state == QUIC_CONN_STATE_TERMINATED;
}

/* True if the connection is terminating or terminated. */
static int is_term_any(const QUIC_CONNECTION *qc)
{
    return is_terminating(qc) || is_terminated(qc);
}

/*
 * gen_rand_conn_id
 * ----------------
 */
static int gen_rand_conn_id(OSSL_LIB_CTX *libctx, size_t len, QUIC_CONN_ID *cid)
{
    if (len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    cid->id_len = (unsigned char)len;

    if (RAND_bytes_ex(libctx, cid->id, len, len * 8) != 1) {
        cid->id_len = 0;
        return 0;
    }

    return 1;
}

/*
 * csm_cleanup
 * -----------
 */
static void csm_cleanup(QUIC_CONNECTION *qc)
{
    uint32_t pn_space;

    if (qc->ackm != NULL)
        for (pn_space = QUIC_PN_SPACE_INITIAL;
             pn_space < QUIC_PN_SPACE_NUM;
             ++pn_space)
            ossl_ackm_on_pkt_space_discarded(qc->ackm, pn_space);

    ossl_quic_tx_packetiser_free(qc->txp);
    ossl_quic_txpim_free(qc->txpim);
    ossl_quic_cfq_free(qc->cfq);
    ossl_qtx_free(qc->qtx);
    if (qc->cc_data != NULL)
        qc->cc_method->free(qc->cc_data);
    if (qc->have_statm)
        ossl_statm_destroy(&qc->statm);
    ossl_ackm_free(qc->ackm);

    if (qc->stream0 != NULL) {
        assert(qc->have_qsm);
        ossl_quic_stream_map_release(&qc->qsm, qc->stream0); /* frees sstream */
    }

    if (qc->have_qsm)
        ossl_quic_stream_map_cleanup(&qc->qsm);

    for (pn_space = QUIC_PN_SPACE_INITIAL; pn_space < QUIC_PN_SPACE_NUM; ++pn_space) {
        ossl_quic_sstream_free(qc->crypto_send[pn_space]);
        ossl_quic_rstream_free(qc->crypto_recv[pn_space]);
    }

    ossl_qrx_pkt_release(qc->qrx_pkt);
    qc->qrx_pkt = NULL;

    ossl_quic_dhs_free(qc->dhs);
    ossl_qrx_free(qc->qrx);
    ossl_quic_demux_free(qc->demux);
    OPENSSL_free(qc->client_transport_params);
    BIO_free(qc->net_rbio);
    BIO_free(qc->net_wbio);
}

/*
 * csm_init
 * --------
 */
static int csm_init(QUIC_CONNECTION *qc)
{
    OSSL_QUIC_TX_PACKETISER_ARGS txp_args = {0};
    OSSL_QTX_ARGS qtx_args = {0};
    OSSL_QRX_ARGS qrx_args = {0};
    QUIC_DHS_ARGS dhs_args = {0};
    uint32_t pn_space;

    qc->blocking = 1;

    if (!gen_rand_conn_id(qc->ssl.ctx->libctx, INIT_DCID_LEN, &qc->init_dcid)) {
        csm_cleanup(qc);
        return 0;
    }

    /* We plug in a network write BIO to the QTX later when we get one. */
    qtx_args.mdpl = QUIC_MIN_INITIAL_DGRAM_LEN;
    qc->rx_max_udp_payload_size = qtx_args.mdpl;

    qc->qtx = ossl_qtx_new(&qtx_args);
    if (qc->qtx == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    qc->txpim = ossl_quic_txpim_new();
    if (qc->txpim == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    qc->cfq = ossl_quic_cfq_new();
    if (qc->cfq == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    if (!ossl_quic_txfc_init(&qc->conn_txfc, NULL)) {
        csm_cleanup(qc);
        return 0;
    }

    if (!ossl_quic_rxfc_init(&qc->conn_rxfc, NULL,
                             2  * 1024 * 1024,
                             10 * 1024 * 1024,
                             get_time, NULL)) {
        csm_cleanup(qc);
        return 0;
    }

    if (!ossl_statm_init(&qc->statm)) {
        csm_cleanup(qc);
        return 0;
    }

    qc->have_statm = 1;
    qc->cc_method = &ossl_cc_dummy_method;
    if ((qc->cc_data = qc->cc_method->new(NULL, NULL, NULL)) == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    if ((qc->ackm = ossl_ackm_new(get_time, NULL, &qc->statm,
                                  qc->cc_method, qc->cc_data)) == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    if (!ossl_quic_stream_map_init(&qc->qsm, get_stream_limit, qc)) {
        csm_cleanup(qc);
        return 0;
    }

    qc->have_qsm = 1;

    /* We use a zero-length SCID. */
    txp_args.cur_dcid           = qc->init_dcid;
    txp_args.ack_delay_exponent = 3;
    txp_args.qtx                = qc->qtx;
    txp_args.txpim              = qc->txpim;
    txp_args.cfq                = qc->cfq;
    txp_args.ackm               = qc->ackm;
    txp_args.qsm                = &qc->qsm;
    txp_args.conn_txfc          = &qc->conn_txfc;
    txp_args.conn_rxfc          = &qc->conn_rxfc;
    txp_args.cc_method          = qc->cc_method;
    txp_args.cc_data            = qc->cc_data;
    txp_args.now                = get_time;
    for (pn_space = QUIC_PN_SPACE_INITIAL; pn_space < QUIC_PN_SPACE_NUM; ++pn_space) {
        qc->crypto_send[pn_space] = ossl_quic_sstream_new(INIT_CRYPTO_BUF_LEN);
        if (qc->crypto_send[pn_space] == NULL) {
            csm_cleanup(qc);
            return 0;
        }

        txp_args.crypto[pn_space] = qc->crypto_send[pn_space];
    }

    qc->txp = ossl_quic_tx_packetiser_new(&txp_args);
    if (qc->txp == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    if ((qc->demux = ossl_quic_demux_new(/*BIO=*/NULL, /*Short CID Len=*/0,
                                         1200, get_time, NULL)) == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    qrx_args.demux              = qc->demux;
    qrx_args.short_conn_id_len  = 0; /* We use a zero-length SCID. */
    qrx_args.max_deferred       = 32;

    if ((qc->qrx = ossl_qrx_new(&qrx_args)) == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    if (!ossl_qrx_add_dst_conn_id(qc->qrx, &txp_args.cur_scid)) {
        csm_cleanup(qc);
        return 0;
    }

    for (pn_space = QUIC_PN_SPACE_INITIAL; pn_space < QUIC_PN_SPACE_NUM; ++pn_space) {
        qc->crypto_recv[pn_space] = ossl_quic_rstream_new(NULL, NULL);
        if (qc->crypto_recv[pn_space] == NULL) {
            csm_cleanup(qc);
            return 0;
        }
    }

    if ((qc->stream0 = ossl_quic_stream_map_alloc(&qc->qsm, 0,
                                                  QUIC_STREAM_INITIATOR_CLIENT
                                                  | QUIC_STREAM_DIR_BIDI)) == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    if ((qc->stream0->sstream = ossl_quic_sstream_new(INIT_APP_BUF_LEN)) == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    if ((qc->stream0->rstream = ossl_quic_rstream_new(NULL, NULL)) == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    if (!ossl_quic_txfc_init(&qc->stream0->txfc, &qc->conn_txfc)) {
        csm_cleanup(qc);
        return 0;
    }

    if (!ossl_quic_rxfc_init(&qc->stream0->rxfc, &qc->conn_rxfc,
                             1 * 1024 * 1024,
                             5 * 1024 * 1024,
                             get_time, NULL)) {
        csm_cleanup(qc);
        return 0;
    }

    /*
     * Determine the QUIC Transport Parameters and serialize the transport
     * parameters block.
     */
    if (!csm_generate_transport_params(qc, &qc->client_transport_params,
                                       &dhs_args.transport_params_len)) {
        csm_cleanup(qc);
        return 0;
    }

    /* Plug in the dummy handshake layer. */
    dhs_args.transport_params           = qc->client_transport_params;
    dhs_args.crypto_send_cb             = csm_on_crypto_send;
    dhs_args.crypto_send_cb_arg         = qc;
    dhs_args.crypto_recv_cb             = csm_on_crypto_recv;
    dhs_args.crypto_recv_cb_arg         = qc;
    dhs_args.yield_secret_cb            = csm_on_handshake_yield_secret;
    dhs_args.yield_secret_cb_arg        = qc;
    dhs_args.got_transport_params_cb    = csm_on_transport_params;
    dhs_args.got_transport_params_cb_arg= qc;
    dhs_args.handshake_complete_cb      = csm_on_handshake_complete;
    dhs_args.handshake_complete_cb_arg  = qc;
    dhs_args.alert_cb                   = csm_on_handshake_alert;
    dhs_args.alert_cb_arg               = qc;

    if ((qc->dhs = ossl_quic_dhs_new(&dhs_args)) == NULL) {
        csm_cleanup(qc);
        return 0;
    }

    qc->rx_max_ack_delay        = QUIC_DEFAULT_MAX_ACK_DELAY;
    qc->rx_ack_delay_exp        = QUIC_DEFAULT_ACK_DELAY_EXP;
    qc->rx_active_conn_id_limit = QUIC_MIN_ACTIVE_CONN_ID_LIMIT;
    qc->max_idle_timeout        = QUIC_DEFAULT_IDLE_TIMEOUT;
    qc->tx_enc_level            = QUIC_ENC_LEVEL_INITIAL;
    csm_update_idle(qc);
    reactor_init(&qc->rtor, csm_tick, qc, csm_determine_next_tick_deadline(qc));

    qc->ssl_mode    = qc->ssl.ctx->mode;
    qc->last_error  = SSL_ERROR_NONE;
    return 1;
}

/*
 * QUIC Connection State Machine: Handshake Layer Event Handling
 * =============================================================
 */
static int csm_on_crypto_send(const unsigned char *buf, size_t buf_len,
                              size_t *consumed, void *arg)
{
    int ret;
    QUIC_CONNECTION *qc = arg;
    uint32_t enc_level = qc->tx_enc_level;
    uint32_t pn_space = ossl_quic_enc_level_to_pn_space(enc_level);
    QUIC_SSTREAM *sstream = qc->crypto_send[pn_space];

    if (!ossl_assert(sstream != NULL))
        return 0;

    ret = ossl_quic_sstream_append(sstream, buf, buf_len, consumed);
    return ret;
}

static int crypto_ensure_empty(QUIC_RSTREAM *rstream)
{
    size_t avail = 0;
    int is_fin = 0;

    if (rstream == NULL)
        return 1;

    if (!ossl_quic_rstream_available(rstream, &avail, &is_fin))
        return 0;

    return avail == 0;
}

static int csm_on_crypto_recv(unsigned char *buf, size_t buf_len,
                              size_t *bytes_read, void *arg)
{
    QUIC_CONNECTION *qc = arg;
    QUIC_RSTREAM *rstream;
    int is_fin = 0; /* crypto stream is never finished, so we don't use this */
    uint32_t i;

    /*
     * After we move to a later EL we must not allow our peer to send any new
     * bytes in the crypto stream on a previous EL. Retransmissions of old bytes
     * are allowed.
     *
     * In practice we will only move to a new EL when we have consumed all bytes
     * which should be sent on the crypto stream at a previous EL. For example,
     * the Handshake EL should not be provisioned until we have completely
     * consumed a TLS 1.3 ServerHello. Thus when we provision an EL the output
     * of ossl_quic_rstream_available() should be 0 for all lower ELs. Thus if a
     * given EL is available we simply ensure we have not received any further
     * bytes at a lower EL.
     */
    for (i = QUIC_ENC_LEVEL_INITIAL; i < qc->tx_enc_level; ++i)
        if (i != QUIC_ENC_LEVEL_0RTT &&
            !crypto_ensure_empty(qc->crypto_recv[ossl_quic_enc_level_to_pn_space(i)])) {
            /* Protocol violation (RFC 9001 s. 4.1.3) */
            ossl_quic_conn_raise_protocol_error(qc, QUIC_ERR_PROTOCOL_VIOLATION,
                                                OSSL_QUIC_FRAME_TYPE_CRYPTO,
                                                "crypto stream data in wrong EL");
            return 0;
        }

    rstream = qc->crypto_recv[ossl_quic_enc_level_to_pn_space(qc->tx_enc_level)];
    if (rstream == NULL)
        return 0;

    return ossl_quic_rstream_read(rstream, buf, buf_len, bytes_read,
                                  &is_fin);
}

static int csm_on_handshake_yield_secret(uint32_t enc_level, int direction,
                                         uint32_t suite_id, EVP_MD *md,
                                         const unsigned char *secret,
                                         size_t secret_len,
                                         void *arg)
{
    QUIC_CONNECTION *qc = arg;
    uint32_t i;

    if (enc_level < QUIC_ENC_LEVEL_HANDSHAKE || enc_level >= QUIC_ENC_LEVEL_NUM)
        /* Invalid EL. */
        return 0;

    if (enc_level <= qc->tx_enc_level)
        /*
         * Does not make sense for us to try and provision an EL we have already
         * attained.
         */
        return 0;

    /*
     * Ensure all crypto streams for previous ELs are now empty of available
     * data.
     */
    for (i = QUIC_ENC_LEVEL_INITIAL; i < enc_level; ++i)
        if (!crypto_ensure_empty(qc->crypto_recv[i])) {
            /* Protocol violation (RFC 9001 s. 4.1.3) */
            ossl_quic_conn_raise_protocol_error(qc, QUIC_ERR_PROTOCOL_VIOLATION,
                                                OSSL_QUIC_FRAME_TYPE_CRYPTO,
                                                "crypto stream data in wrong EL");
            return 0;
        }

    if (direction) {
        /* TX */
        if (!ossl_qtx_provide_secret(qc->qtx, enc_level,
                                     suite_id, md,
                                     secret, secret_len))
            return 0;

        qc->tx_enc_level = enc_level;
    } else {
        /* RX */
        if (!ossl_qrx_provide_secret(qc->qrx, enc_level,
                                     suite_id, md,
                                     secret, secret_len))
            return 0;
    }

    return 1;
}

static int csm_on_handshake_complete(void *arg)
{
    QUIC_CONNECTION *qc = arg;

    if (qc->handshake_complete)
        return 0; /* this should not happen twice */

    if (!ossl_assert(qc->tx_enc_level == QUIC_ENC_LEVEL_1RTT))
        return 0;

    if (!qc->got_transport_params)
        /*
         * Was not a valid QUIC handshake if we did not get valid transport
         * params.
         */
        return 0;

    /* Don't need transport parameters anymore. */
    OPENSSL_free(qc->client_transport_params);
    qc->client_transport_params = NULL;

    /* Tell TXP the handshake is complete. */
    ossl_quic_tx_packetiser_notify_handshake_complete(qc->txp);

    qc->handshake_complete = 1;
    return 1;
}

static int csm_on_handshake_alert(void *arg, unsigned char alert_code)
{
    QUIC_CONNECTION *qc = arg;

    ossl_quic_conn_raise_protocol_error(qc, QUIC_ERR_CRYPTO_ERR_BEGIN + alert_code,
                                        0, "handshake alert");
    return 1;
}

/* QUIC Connection State Machine: Transport Parameters
 * ===================================================
 */
static int csm_generate_transport_params(QUIC_CONNECTION *qc,
                                         unsigned char **buf_p,
                                         size_t *buf_len_p)
{
    int ok = 0;
    BUF_MEM *buf_mem = NULL;
    WPACKET wpkt;
    int wpkt_valid = 0;

    if ((buf_mem = BUF_MEM_new()) == NULL)
        goto err;

    if (!WPACKET_init(&wpkt, buf_mem))
        goto err;

    wpkt_valid = 1;

    if (ossl_quic_wire_encode_transport_param_bytes(&wpkt, QUIC_TPARAM_DISABLE_ACTIVE_MIGRATION,
                                                    NULL, 0) == NULL)
        goto err;

    if (ossl_quic_wire_encode_transport_param_bytes(&wpkt, QUIC_TPARAM_INITIAL_SCID,
                                                    NULL, 0) == NULL)
        goto err;

    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_MAX_IDLE_TIMEOUT,
                                                   qc->max_idle_timeout))
        goto err;

    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_MAX_UDP_PAYLOAD_SIZE,
                                                   QUIC_MIN_INITIAL_DGRAM_LEN))
        goto err;

    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_ACTIVE_CONN_ID_LIMIT,
                                                   4))
        goto err;

    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_INITIAL_MAX_DATA,
                                                   ossl_quic_rxfc_get_cwm(&qc->conn_rxfc)))
        goto err;

    /*
     * We actually want the default CWM for a new RXFC, but here we just use
     * stream0 as a representative specimen. TODO(QUIC): revisit this when we
     * support multiple streams.
     */
    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                                   ossl_quic_rxfc_get_cwm(&qc->stream0->rxfc)))
        goto err;

    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                                                   ossl_quic_rxfc_get_cwm(&qc->stream0->rxfc)))
        goto err;

    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_INITIAL_MAX_STREAM_DATA_UNI,
                                                   ossl_quic_rxfc_get_cwm(&qc->stream0->rxfc)))
        goto err;

    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_INITIAL_MAX_STREAMS_BIDI,
                                                   0))
        goto err;

    if (!ossl_quic_wire_encode_transport_param_int(&wpkt, QUIC_TPARAM_INITIAL_MAX_STREAMS_UNI,
                                                   0))
        goto err;

    if (!WPACKET_get_total_written(&wpkt, buf_len_p))
        goto err;

    *buf_p = (unsigned char *)buf_mem->data;
    buf_mem->data = NULL;

    if (!WPACKET_finish(&wpkt))
        goto err;

    wpkt_valid = 0;
    ok = 1;
err:
    if (wpkt_valid)
        WPACKET_cleanup(&wpkt);
    BUF_MEM_free(buf_mem);
    return ok;
}

static int tparam_to_cid(PACKET *pkt, QUIC_CONN_ID *cid)
{
    const unsigned char *body;
    size_t len = 0;
    uint64_t id;

    body = ossl_quic_wire_decode_transport_param_bytes(pkt, &id, &len);
    if (body == NULL || len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    cid->id_len = (unsigned char)len;
    memcpy(cid->id, body, cid->id_len);
    return 1;
}

/*
 * Called by handshake layer when we receive QUIC Transport Parameters from the
 * peer. Note that these are not authenticated until the handshake is marked
 * as complete.
 */
static int csm_on_transport_params(const unsigned char *params,
                                   size_t params_len,
                                   void *arg)
{
    QUIC_CONNECTION *qc = arg;
    PACKET pkt;
    uint64_t id, v;
    size_t len;
    const unsigned char *body;
    int got_orig_dcid = 0;
    int got_initial_scid = 0;
    int got_retry_scid = 0;
    int got_initial_max_data = 0;
    int got_initial_max_stream_data_bidi_local = 0;
    int got_initial_max_stream_data_bidi_remote = 0;
    int got_initial_max_stream_data_uni = 0;
    int got_initial_max_streams_bidi = 0;
    int got_initial_max_streams_uni = 0;
    int got_ack_delay_exp = 0;
    int got_max_ack_delay = 0;
    int got_max_udp_payload_size = 0;
    int got_max_idle_timeout = 0;
    int got_active_conn_id_limit = 0;
    QUIC_CONN_ID cid;

    if (qc->got_transport_params)
        goto malformed;

    if (!PACKET_buf_init(&pkt, params, params_len))
        return 0;

    while (PACKET_remaining(&pkt) > 0) {
        if (!ossl_quic_wire_peek_transport_param(&pkt, &id))
            goto malformed;

        switch (id) {
            case QUIC_TPARAM_ORIG_DCID:
                if (got_orig_dcid)
                    /* must not appear more than once */
                    goto malformed;

                if (!tparam_to_cid(&pkt, &cid))
                    goto malformed;

                /* Must match our initial DCID. */
                if (!ossl_quic_conn_id_eq(&qc->init_dcid, &cid))
                    goto malformed;

                got_orig_dcid = 1;
                break;

            case QUIC_TPARAM_RETRY_SCID:
                if (got_retry_scid || !qc->doing_retry)
                    /* must not appear more than once or if retry not done */
                    goto malformed;

                if (!tparam_to_cid(&pkt, &cid))
                    goto malformed;

                /* Must match Retry packet SCID. */
                if (!ossl_quic_conn_id_eq(&qc->retry_scid, &cid))
                    goto malformed;

                got_retry_scid = 1;
                break;

            case QUIC_TPARAM_INITIAL_SCID:
                if (got_initial_scid)
                    /* must not appear more than once */
                    goto malformed;

                if (!tparam_to_cid(&pkt, &cid))
                    goto malformed;

                /* Must match SCID of first Initial packet from server. */
                if (!ossl_quic_conn_id_eq(&qc->init_scid, &cid))
                    goto malformed;

                got_initial_scid = 1;
                break;

            case QUIC_TPARAM_INITIAL_MAX_DATA:
                if (got_initial_max_data)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v))
                    goto malformed;

                ossl_quic_txfc_bump_cwm(&qc->conn_txfc, v);
                got_initial_max_data = 1;
                break;

            case QUIC_TPARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                if (got_initial_max_stream_data_bidi_local)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v))
                    goto malformed;

                /*
                 * This is correct; the BIDI_LOCAL TP governs streams created by
                 * the endpoint which sends the TP, i.e., our peer.
                 */
                qc->init_max_stream_data_bidi_remote = v;
                got_initial_max_stream_data_bidi_local = 1;
                break;

            case QUIC_TPARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                if (got_initial_max_stream_data_bidi_remote)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v))
                    goto malformed;

                /*
                 * This is correct; the BIDI_REMOTE TP governs streams created
                 * by the endpoint which receives the TP, i.e., us.
                 */
                qc->init_max_stream_data_bidi_local = v;

                /* Apply to stream 0. */
                ossl_quic_txfc_bump_cwm(&qc->stream0->txfc, v);
                got_initial_max_stream_data_bidi_remote = 1;
                break;

            case QUIC_TPARAM_INITIAL_MAX_STREAM_DATA_UNI:
                if (got_initial_max_stream_data_uni)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v))
                    goto malformed;

                qc->init_max_stream_data_uni_remote = v;
                got_initial_max_stream_data_uni = 1;
                break;

            case QUIC_TPARAM_ACK_DELAY_EXP:
                if (got_ack_delay_exp)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v)
                    || v > QUIC_MAX_ACK_DELAY_EXP)
                    goto malformed;

                qc->rx_ack_delay_exp = (unsigned char)v;
                got_ack_delay_exp = 1;
                break;

            case QUIC_TPARAM_MAX_ACK_DELAY:
                if (got_max_ack_delay)
                    /* must not appear more than once */
                    return 0;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v)
                    || v >= (((uint64_t)1) << 14))
                    goto malformed;

                qc->rx_max_ack_delay = v;
                got_max_ack_delay = 1;
                break;

            case QUIC_TPARAM_INITIAL_MAX_STREAMS_BIDI:
                if (got_initial_max_streams_bidi)
                    /* must not appear more than once */
                    return 0;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v)
                    || v > (((uint64_t)1) << 60))
                    goto malformed;

                assert(qc->max_local_streams_bidi == 0);
                qc->max_local_streams_bidi = v;
                got_initial_max_streams_bidi = 1;
                break;

            case QUIC_TPARAM_INITIAL_MAX_STREAMS_UNI:
                if (got_initial_max_streams_uni)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v)
                    || v > (((uint64_t)1) << 60))
                    goto malformed;

                assert(qc->max_local_streams_uni == 0);
                qc->max_local_streams_uni = v;
                got_initial_max_streams_uni = 1;
                break;

            case QUIC_TPARAM_MAX_IDLE_TIMEOUT:
                if (got_max_idle_timeout)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v))
                    goto malformed;

                if (v < qc->max_idle_timeout)
                    qc->max_idle_timeout = v;

                csm_update_idle(qc);
                got_max_idle_timeout = 1;
                break;

            case QUIC_TPARAM_MAX_UDP_PAYLOAD_SIZE:
                if (got_max_udp_payload_size)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v)
                    || v < QUIC_MIN_INITIAL_DGRAM_LEN)
                    goto malformed;

                qc->rx_max_udp_payload_size = v;
                got_max_udp_payload_size    = 1;
                break;

            case QUIC_TPARAM_ACTIVE_CONN_ID_LIMIT:
                if (got_active_conn_id_limit)
                    /* must not appear more than once */
                    goto malformed;

                if (!ossl_quic_wire_decode_transport_param_int(&pkt, &id, &v)
                    || v < QUIC_MIN_ACTIVE_CONN_ID_LIMIT)
                    goto malformed;

                qc->rx_active_conn_id_limit = v;
                got_active_conn_id_limit = 1;
                break;

            /*
             * TODO(QUIC): Handle:
             *   QUIC_TPARAM_STATELESS_RESET_TOKEN
             *   QUIC_TPARAM_PREFERRED_ADDR
             */

            case QUIC_TPARAM_DISABLE_ACTIVE_MIGRATION:
                /* We do not currently handle migration, so nothing to do. */
            default:
                /* Skip over and ignore. */
                body = ossl_quic_wire_decode_transport_param_bytes(&pkt, &id,
                                                                   &len);
                if (body == NULL)
                    goto malformed;

                break;
        }
    }

    if (!got_orig_dcid || !got_initial_scid || got_retry_scid != qc->doing_retry)
        /* Transport parameters were not valid. */
        goto malformed;

    qc->got_transport_params = 1;

    if (got_initial_max_data || got_initial_max_stream_data_bidi_remote
        || got_initial_max_streams_bidi || got_initial_max_streams_uni)
        /* If FC credit was bumped, we may now be able to send. */
        ossl_quic_stream_map_update_state(&qc->qsm, qc->stream0);

    return 1;

malformed:
    ossl_quic_conn_raise_protocol_error(qc, QUIC_ERR_TRANSPORT_PARAMETER_ERROR,
                                        0, "bad transport parameter");
    return 0;
}

/*
 * QUIC Connection State Machine: Ticker-Mutator
 * =============================================
 */
static int csm_rx(QUIC_CONNECTION *qc);
static int csm_tx(QUIC_CONNECTION *qc);

/*
 * The central ticker function called by the reactor. This does everything, or
 * at least everything network I/O related. Best effort - not allowed to fail
 * "loudly".
 */
static void csm_tick(QUIC_TICK_RESULT *res, void *arg)
{
    OSSL_TIME now, deadline;
    QUIC_CONNECTION *qc = arg;

    /*
     * When we tick the QUIC connection, we do everything we need to do
     * periodically. In order, we:
     *
     *   - handle any incoming data from the network;
     *   - handle any timer events which are due to fire (ACKM, etc.)
     *   - write any data to the network due to be sent, to the extent
     *     possible;
     *   - determine the time at which we should next be ticked.
     */

    /* If we are in the TERMINATED state, there is nothing to do. */
    if (is_terminated(qc)) {
        res->want_net_read  = 0;
        res->want_net_write = 0;
        res->tick_deadline  = ossl_time_infinite();
        return;
    }

    /*
     * If we are in the TERMINATING state, check if the terminating timer has
     * expired.
     */
    if (is_terminating(qc)) {
        now = ossl_time_now();

        if (ossl_time_compare(now, qc->terminate_deadline) >= 0) {
            csm_on_terminating_timeout(qc);
            res->want_net_read  = 0;
            res->want_net_write = 0;
            res->tick_deadline  = ossl_time_infinite();
            return; /* abort normal processing, nothing to do */
        }
    }

    /* Handle any incoming data from the network. */
    csm_rx(qc);

    /*
     * Allow the handshake layer to check for any new incoming data and generate
     * new outgoing data.
     */
    ossl_quic_dhs_tick(qc->dhs);

    /*
     * Handle any timer events which are due to fire; namely, the loss detection
     * deadline and the idle timeout.
     *
     * ACKM ACK generation deadline is polled by TXP, so we don't need to handle
     * it here.
     */
    now = ossl_time_now();
    if (ossl_time_compare(now, qc->idle_deadline) >= 0) {
        /*
         * Idle timeout differs from normal protocol violation because we do not
         * send a CONN_CLOSE frame; go straight to TERMINATED.
         */
        csm_on_idle_timeout(qc);
        res->want_net_read  = 0;
        res->want_net_write = 0;
        res->tick_deadline  = ossl_time_infinite();
        return;
    }

    deadline = ossl_ackm_get_loss_detection_deadline(qc->ackm);
    if (!ossl_time_is_zero(deadline) && ossl_time_compare(now, deadline) >= 0)
        ossl_ackm_on_timeout(qc->ackm);

    /* Write any data to the network due to be sent. */
    csm_tx(qc);

    /* Determine the time at which we should next be ticked. */
    res->tick_deadline = csm_determine_next_tick_deadline(qc);

    /* Always process network input. */
    res->want_net_read = 1;

    /* We want to write to the network if we have any in our queue. */
    res->want_net_write = (ossl_qtx_get_queue_len_datagrams(qc->qtx) > 0);
}

/* Process incoming packets and handle frames, if any. */
static void csm_rx_handle_packet(QUIC_CONNECTION *qc);
static int csm_retry(QUIC_CONNECTION *qc,
                     const unsigned char *retry_token,
                     size_t retry_token_len,
                     const QUIC_CONN_ID *retry_scid);

static int csm_rx(QUIC_CONNECTION *qc)
{
    int handled_any = 0;

    if (!qc->have_sent_any_pkt)
        /*
         * We have not sent anything yet, therefore there is no need to check
         * for incoming data.
         */
        return 1;

    /*
     * Get DEMUX to BIO_recvmmsg from the network and queue incoming datagrams
     * to the appropriate QRX instance.
     */
    ossl_quic_demux_pump(qc->demux); /* best effort */

    for (;;) {
        assert(qc->qrx_pkt == NULL);

        if (!ossl_qrx_read_pkt(qc->qrx, &qc->qrx_pkt))
            break;

        if (!handled_any)
            csm_update_idle(qc);

        csm_rx_handle_packet(qc); /* best effort */

        /*
         * Regardless of the outcome of frame handling, unref the packet.
         * This will free the packet unless something added another
         * reference to it during frame processing.
         */
        ossl_qrx_pkt_release(qc->qrx_pkt);
        qc->qrx_pkt = NULL;

        handled_any = 1;
    }

    /*
     * When in TERMINATING - CLOSING, generate a CONN_CLOSE frame whenever we
     * process one or more incoming packets.
     */
    if (handled_any && qc->state == QUIC_CONN_STATE_TERMINATING_CLOSING)
        qc->conn_close_queued = 1;

    return 1;
}

/* Handles the packet currently in qc->qrx_pkt->hdr. */
static void csm_rx_handle_packet(QUIC_CONNECTION *qc)
{
    uint32_t enc_level;

    assert(qc->qrx_pkt != NULL);

    if (ossl_quic_pkt_type_is_encrypted(qc->qrx_pkt->hdr->type)) {
        if (!qc->have_received_enc_pkt) {
            qc->init_scid = qc->qrx_pkt->hdr->src_conn_id;
            qc->have_received_enc_pkt = 1;

            /*
             * We change to using the SCID in the first Initial packet as the
             * DCID.
             */
            ossl_quic_tx_packetiser_set_cur_dcid(qc->txp, &qc->init_scid);
        }

        enc_level = ossl_quic_pkt_type_to_enc_level(qc->qrx_pkt->hdr->type);
        if ((qc->el_discarded & (1U << enc_level)) != 0)
            /* Do not process packets from ELs we have already discarded. */
            return;
    }

    /* Handle incoming packet. */
    switch (qc->qrx_pkt->hdr->type) {
        case QUIC_PKT_TYPE_RETRY:
            if (qc->doing_retry)
                /* It is not allowed to ask a client to do a retry more than
                 * once. */
                return;

            if (qc->qrx_pkt->hdr->len <= QUIC_RETRY_INTEGRITY_TAG_LEN)
                /* Packets with zero-length Retry Tokens are invalid. */
                return;

            /*
             * TODO(QUIC): Theoretically this should probably be in the QRX.
             * However because validation is dependent on context (namely the
             * client's initial DCID) we can't do this cleanly. In the future we
             * should probably add a callback to the QRX to let it call us (via
             * the DEMUX) and ask us about the correct original DCID, rather
             * than allow the QRX to emit a potentially malformed packet to the
             * upper layers. However, special casing this will do for now.
             */
            if (!ossl_quic_validate_retry_integrity_tag(qc->ssl.ctx->libctx,
                                                        qc->ssl.ctx->propq,
                                                        qc->qrx_pkt->hdr,
                                                        &qc->init_dcid))
                /* Malformed retry packet, ignore. */
                return;

            csm_retry(qc, qc->qrx_pkt->hdr->data,
                      qc->qrx_pkt->hdr->len - QUIC_RETRY_INTEGRITY_TAG_LEN,
                      &qc->qrx_pkt->hdr->src_conn_id);
            break;

        case QUIC_PKT_TYPE_VERSION_NEG:
            /* TODO(QUIC): Implement version negotiation */
            break;

        default:
            if (qc->qrx_pkt->hdr->type == QUIC_PKT_TYPE_HANDSHAKE)
                /*
                 * We automatically drop INITIAL EL keys when first successfully
                 * decrypting a HANDSHAKE packet, as per the RFC.
                 */
                csm_discard_el(qc, QUIC_ENC_LEVEL_INITIAL);

            /* This packet contains frames, pass to the RXDP. */
            ossl_quic_handle_frames(qc, qc->qrx_pkt); /* best effort */
            break;
    }
}

/* Try to generate packets and if possible, flush them to the network. */
static int csm_tx(QUIC_CONNECTION *qc)
{
    if (qc->state == QUIC_CONN_STATE_TERMINATING_CLOSING) {
        /*
         * While closing, only send CONN_CLOSE if we've received more traffic
         * from the peer. Once we tell the TXP to generate CONN_CLOSE, all
         * future calls to it generate CONN_CLOSE frames, so otherwise we would
         * just constantly generate CONN_CLOSE frames.
         */
        if (!qc->conn_close_queued)
            return 0;

        qc->conn_close_queued = 0;
    }

    /*
     * Send a packet, if we need to. Best effort. The TXP consults the CC and
     * applies any limitations imposed by it, so we don't need to do it here.
     *
     * Best effort. In particular if TXP fails for some reason we should still
     * flush any queued packets which we already generated.
     */
    if (ossl_quic_tx_packetiser_generate(qc->txp,
                                         TX_PACKETISER_ARCHETYPE_NORMAL)
        == TX_PACKETISER_RES_SENT_PKT)
        qc->have_sent_any_pkt = 1;

    ossl_qtx_flush_net(qc->qtx); /* best effort */
    return 1;
}

/* Determine next tick deadline. */
static OSSL_TIME csm_determine_next_tick_deadline(QUIC_CONNECTION *qc)
{
    OSSL_TIME deadline;
    uint32_t pn_space;

    deadline = ossl_ackm_get_loss_detection_deadline(qc->ackm);
    if (ossl_time_is_zero(deadline))
        deadline = ossl_time_infinite();

    for (pn_space = QUIC_PN_SPACE_INITIAL; pn_space < QUIC_PN_SPACE_NUM; ++pn_space)
        deadline = ossl_time_min(deadline,
                                 ossl_ackm_get_ack_deadline(qc->ackm, pn_space));

    /* When will CC let us send more? */
    if (ossl_quic_tx_packetiser_has_pending(qc->txp, TX_PACKETISER_ARCHETYPE_NORMAL,
                                            TX_PACKETISER_BYPASS_CC))
        deadline = ossl_time_min(deadline,
                                 qc->cc_method->get_next_credit_time(qc->cc_data));

    /* Is the terminating timer armed? */
    if (is_terminating(qc))
        deadline = ossl_time_min(deadline,
                                 qc->terminate_deadline);
    else if (!ossl_time_is_infinite(qc->idle_deadline))
        deadline = ossl_time_min(deadline,
                                 qc->idle_deadline);

    return deadline;
}

/*
 * QUIC Connection State Machine: Lifecycle Transitions
 * ====================================================
 */

/*
 * csm_connect
 * -----------
 */
static int csm_connect(QUIC_CONNECTION *qc)
{
    if (qc->state != QUIC_CONN_STATE_IDLE)
        /* Calls to connect are idempotent */
        return 1;

    /* Inform QTX of peer address. */
    if (!ossl_quic_tx_packetiser_set_peer(qc->txp, &qc->init_peer_addr))
        return 0;

    /* Plug in secrets for the Initial EL. */
    if (!ossl_quic_provide_initial_secret(qc->ssl.ctx->libctx,
                                          qc->ssl.ctx->propq,
                                          &qc->init_dcid,
                                          /*is_server=*/0,
                                          qc->qrx, qc->qtx))
        return 0;

    /* Change state. */
    qc->state                   = QUIC_CONN_STATE_ACTIVE;
    qc->doing_proactive_ver_neg = 0; /* not currently supported */

    /* Handshake layer: start (e.g. send CH). */
    if (!ossl_quic_dhs_tick(qc->dhs))
        return 0;

    reactor_tick(&qc->rtor); /* best effort */
    return 1;
}

/*
 * csm_retry
 * ---------
 *
 * Called when a server asks us to do a retry.
 */
static void free_token(const unsigned char *buf, size_t buf_len, void *arg)
{
    OPENSSL_free((unsigned char *)buf);
}

static int csm_retry(QUIC_CONNECTION *qc,
                     const unsigned char *retry_token,
                     size_t retry_token_len,
                     const QUIC_CONN_ID *retry_scid)
{
    void *buf;

    /* We change to using the SCID in the Retry packet as the DCID. */
    if (!ossl_quic_tx_packetiser_set_cur_dcid(qc->txp, retry_scid))
        return 0;

    /*
     * Now we retry. We will release the Retry packet immediately, so copy
     * the token.
     */
    if ((buf = OPENSSL_malloc(retry_token_len)) == NULL)
        return 0;

    memcpy(buf, retry_token, retry_token_len);

    ossl_quic_tx_packetiser_set_initial_token(qc->txp, buf, retry_token_len,
                                              free_token, NULL);

    qc->retry_scid  = *retry_scid;
    qc->doing_retry = 1;

    /*
     * We need to stimulate the Initial EL to generate the first CRYPTO frame
     * again. We can do this most cleanly by simply forcing the ACKM to consider
     * the first Initial packet as lost, which it effectively was as the server
     * hasn't processed it. This also maintains the desired behaviour with e.g.
     * PNs not resetting and so on.
     *
     * The PN we used initially is always zero, because QUIC does not allow
     * repeated retries.
     */
    if (!ossl_ackm_mark_packet_pseudo_lost(qc->ackm, QUIC_PN_SPACE_INITIAL,
                                      /*PN=*/0))
        return 0;

    /*
     * Plug in new secrets for the Initial EL. This is the only time we change
     * the secrets for an EL after we already provisioned it.
     */
    if (!ossl_quic_provide_initial_secret(qc->ssl.ctx->libctx,
                                          qc->ssl.ctx->propq,
                                          &qc->retry_scid,
                                          /*is_server=*/0,
                                          qc->qrx, qc->qtx))
        return 0;

    return 1;
}

/*
 * csm_discard_el
 * --------------
 */
static int csm_discard_el(QUIC_CONNECTION *qc,
                          uint32_t enc_level)
{
    if (!ossl_assert(enc_level < QUIC_ENC_LEVEL_1RTT))
        return 0;

    if ((qc->el_discarded & (1U << enc_level)) != 0)
        /* Already done. */
        return 1;

    /* Best effort for all of these. */
    ossl_quic_tx_packetiser_discard_enc_level(qc->txp, enc_level);
    ossl_qrx_discard_enc_level(qc->qrx, enc_level);
    ossl_qtx_discard_enc_level(qc->qtx, enc_level);

    if (enc_level != QUIC_ENC_LEVEL_0RTT) {
        uint32_t pn_space = ossl_quic_enc_level_to_pn_space(enc_level);

        ossl_ackm_on_pkt_space_discarded(qc->ackm, pn_space);

        /* We should still have crypto streams at this point. */
        assert(qc->crypto_send[pn_space] != NULL);
        assert(qc->crypto_recv[pn_space] != NULL);

        /* Get rid of the crypto stream state for the EL. */
        ossl_quic_sstream_free(qc->crypto_send[pn_space]);
        qc->crypto_send[pn_space] = NULL;

        ossl_quic_rstream_free(qc->crypto_recv[pn_space]);
        qc->crypto_recv[pn_space] = NULL;
    }

    qc->el_discarded |= (1U << enc_level);
    return 1;
}

/*
 * ossl_quic_conn_on_handshake_confirmed
 * -------------------------------------
 * Called by the RXDP.
 */
int ossl_quic_conn_on_handshake_confirmed(QUIC_CONNECTION *qc)
{
    if (qc->handshake_confirmed)
        return 1;

    if (!qc->handshake_complete) {
        /*
         * Does not make sense for handshake to be confirmed before it is
         * completed.
         */
        ossl_quic_conn_raise_protocol_error(qc, QUIC_ERR_PROTOCOL_VIOLATION,
                                            OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE,
                                            "handshake cannot be confirmed "
                                            "before it is completed");
        return 0;
    }

    csm_discard_el(qc, QUIC_ENC_LEVEL_HANDSHAKE);
    qc->handshake_confirmed = 1;
    return 1;
}

/*
 * csm_terminate
 * -------------
 *
 * Master function used when we want to start tearing down a connection:
 *
 *   - If the connection is still IDLE we can go straight to TERMINATED;
 *
 *   - If we are already TERMINATED this is a no-op.
 *
 *   - If we are TERMINATING - CLOSING and we have now got a CONNECTION_CLOSE
 *     from the peer (tcause->remote == 1), we move to TERMINATING - CLOSING.
 *
 *   - If we are TERMINATING - DRAINING, we remain here until the terminating
 *     timer expires.
 *
 *   - Otherwise, we are in ACTIVE and move to TERMINATING - CLOSING.
 *     if we caused the termination (e.g. we have sent a CONNECTION_CLOSE). Note
 *     that we are considered to have caused a termination if we sent the first
 *     CONNECTION_CLOSE frame, even if it is caused by a peer protocol
 *     violation. If the peer sent the first CONNECTION_CLOSE frame, we move to
 *     TERMINATING - DRAINING.
 *
 * We record the termination cause structure passed on the first call only.
 * Any successive calls have their termination cause data discarded;
 * once we start sending a CONNECTION_CLOSE frame, we don't change the details
 * in it.
 */
static void csm_start_terminating(QUIC_CONNECTION *qc,
                                  const QUIC_TERMINATE_CAUSE *tcause)
{
    switch (qc->state) {
        default:
        case QUIC_CONN_STATE_IDLE:
            qc->terminate_cause = *tcause;
            csm_on_terminating_timeout(qc);
            break;

        case QUIC_CONN_STATE_ACTIVE:
            qc->state = tcause->remote ? QUIC_CONN_STATE_TERMINATING_DRAINING
                                       : QUIC_CONN_STATE_TERMINATING_CLOSING;
            qc->terminate_cause = *tcause;
            qc->terminate_deadline
                = ossl_time_add(ossl_time_now(),
                                ossl_time_multiply(ossl_ackm_get_pto_duration(qc->ackm),
                                                   3));

            if (!tcause->remote) {
                OSSL_QUIC_FRAME_CONN_CLOSE f = {0};

                /* best effort */
                f.error_code = qc->terminate_cause.error_code;
                f.frame_type = qc->terminate_cause.frame_type;
                f.is_app     = qc->terminate_cause.app;
                ossl_quic_tx_packetiser_schedule_conn_close(qc->txp, &f);
                qc->conn_close_queued = 1;
            }
            break;

        case QUIC_CONN_STATE_TERMINATING_CLOSING:
            if (tcause->remote)
                qc->state = QUIC_CONN_STATE_TERMINATING_DRAINING;

            break;

        case QUIC_CONN_STATE_TERMINATING_DRAINING:
            /* We remain here until the timout expires. */
            break;

        case QUIC_CONN_STATE_TERMINATED:
            /* No-op. */
            break;
    }
}

/*
 * ossl_quic_conn_on_remote_conn_close
 * -----------------------------------
 */
void ossl_quic_conn_on_remote_conn_close(QUIC_CONNECTION *qc,
                                         OSSL_QUIC_FRAME_CONN_CLOSE *f)
{
    QUIC_TERMINATE_CAUSE tcause = {0};

    if (!is_active(qc))
        return;

    tcause.remote     = 1;
    tcause.app        = f->is_app;
    tcause.error_code = f->error_code;
    tcause.frame_type = f->frame_type;

    csm_start_terminating(qc, &tcause);
}

/*
 * ossl_quic_conn_raise_protocol_error
 * -----------------------------------
 *
 * This function is the master function which should be called in the event of a
 * protocol error detected by us. We specify a QUIC transport-scope error code
 * and optional frame type which was responsible. The reason string is not
 * currently handled. If the connection has already terminated due to a previous
 * protocol error, this is a no-op; first error wins.
 */
void ossl_quic_conn_raise_protocol_error(QUIC_CONNECTION *qc,
                                         uint64_t error_code,
                                         uint64_t frame_type,
                                         const char *reason)
{
    QUIC_TERMINATE_CAUSE tcause = {0};

    tcause.error_code = error_code;
    tcause.frame_type = frame_type;

    csm_start_terminating(qc, &tcause);
}

/*
 * csm_on_terminating_timeout
 * --------------------------
 *
 * Called once the terminating timer expires, meaning we move from TERMINATING
 * to TERMINATED.
 */
static void csm_on_terminating_timeout(QUIC_CONNECTION *qc)
{
    qc->state = QUIC_CONN_STATE_TERMINATED;
}

/*
 * csm_update_idle
 * ---------------
 */
static void csm_update_idle(QUIC_CONNECTION *qc)
{
    if (qc->max_idle_timeout == 0)
        qc->idle_deadline = ossl_time_infinite();
    else
        qc->idle_deadline = ossl_time_add(ossl_time_now(),
            ossl_ms2time(qc->max_idle_timeout));
}

/*
 * csm_on_idle_timeout
 * -------------------
 */
static void csm_on_idle_timeout(QUIC_CONNECTION *qc)
{
    /*
     * Idle timeout does not have an error code associated with it because a
     * CONN_CLOSE is never sent for it. We shouldn't use this data once we reach
     * TERMINATED anyway.
     */
    qc->terminate_cause.app         = 0;
    qc->terminate_cause.error_code  = UINT64_MAX;
    qc->terminate_cause.frame_type  = 0;

    qc->state = QUIC_CONN_STATE_TERMINATED;
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

/*
 * SSL_new
 * -------
 */
SSL *ossl_quic_new(SSL_CTX *ctx)
{
    QUIC_CONNECTION *qc = NULL;
    SSL *ssl_base = NULL;

    qc = OPENSSL_zalloc(sizeof(*qc));
    if (qc == NULL)
        goto err;

    /* Initialise the QUIC_CONNECTION's stub header. */
    ssl_base = &qc->ssl;
    if (!ossl_ssl_init(ssl_base, ctx, SSL_TYPE_QUIC_CONNECTION)) {
        ssl_base = NULL;
        goto err;
    }

    if (!csm_init(qc))
        /* csm_init does its own teardown on error */
        goto err;

    return ssl_base;

err:
    OPENSSL_free(qc);
    return NULL;
}

/*
 * SSL_free
 * --------
 */
void ossl_quic_free(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    /* We should never be called on anything but a QUIC_CONNECTION. */
    if (!expect_quic_conn(qc))
        return;

    csm_cleanup(qc);
    /* Note: SSL_free calls OPENSSL_free(qc) for us */
}

/*
 * ossl_quic_init
 * --------------
 */
int ossl_quic_init(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    /* Same op as SSL_clear, forward the call. */
    return ossl_quic_clear(s);
}

/*
 * ossl_quic_deinit
 * ----------------
 */
void ossl_quic_deinit(SSL *s)
{
    /* No-op. */
}

/*
 * SSL_reset
 * ---------
 */
int ossl_quic_reset(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    /* Currently a no-op. */
    return 1;
}

/*
 * SSL_clear
 * ---------
 */
int ossl_quic_clear(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    /* Currently a no-op. */
    return 1;
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
 * csm_analyse_init_peer_addr
 * --------------------------
 *
 * Determines what initial destination UDP address we should use, if possible.
 * If this fails the client must set the destination address manually, or use a
 * BIO which does not need a destination address.
 */
static int csm_analyse_init_peer_addr(BIO *net_wbio, BIO_ADDR *peer)
{
    if (!BIO_dgram_get_peer(net_wbio, peer))
        return 0;

    return 1;
}

/*
 * validate_poll_descriptor
 * ------------------------
 * Determines whether we can support a given poll descriptor.
 */
static int validate_poll_descriptor(const BIO_POLL_DESCRIPTOR *d)
{
    return d->type == BIO_POLL_DESCRIPTOR_TYPE_NONE
        || (d->type == BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD && d->value.fd >= 0);
}

/*
 * ossl_quic_conn_set0_net_rbio
 * ----------------------------
 */
void ossl_quic_conn_set0_net_rbio(QUIC_CONNECTION *qc, BIO *net_rbio)
{
    BIO_POLL_DESCRIPTOR d = {0};

    if (qc->net_rbio == net_rbio)
        return;

    if (net_rbio != NULL) {
        if (!BIO_get_rpoll_descriptor(net_rbio, &d))
            /* Non-pollable BIO */
            d.type = BIO_POLL_DESCRIPTOR_TYPE_NONE;

        if (!validate_poll_descriptor(&d))
            return;
    }

    reactor_set_poll_r(&qc->rtor, &d);
    BIO_free(qc->net_rbio);
    ossl_quic_demux_set_bio(qc->demux, net_rbio);
    qc->net_rbio = net_rbio;

    /*
     * If what we have is not pollable (e.g. a BIO_dgram_pair) disable blocking
     * mode as we do not support it for now.
     */
    if (net_rbio != NULL && d.type == BIO_POLL_DESCRIPTOR_TYPE_NONE)
        qc->blocking = 0;
}

/*
 * ossl_quic_conn_set0_net_wbio
 * ----------------------------
 */
void ossl_quic_conn_set0_net_wbio(QUIC_CONNECTION *qc, BIO *net_wbio)
{
    BIO_POLL_DESCRIPTOR d = {0};

    if (qc->net_wbio == net_wbio)
        return;

    if (net_wbio != NULL) {
        if (!BIO_get_wpoll_descriptor(net_wbio, &d))
            /* Non-pollable BIO */
            d.type = BIO_POLL_DESCRIPTOR_TYPE_NONE;

        if (!validate_poll_descriptor(&d))
            return;

        /*
         * If we do not have a peer address yet, and we have not started trying
         * to connect yet, try to autodetect one.
         */
        if (BIO_ADDR_family(&qc->init_peer_addr) == AF_UNSPEC
            && qc->state == QUIC_CONN_STATE_IDLE
            && !csm_analyse_init_peer_addr(net_wbio, &qc->init_peer_addr))
            /* best effort */
            BIO_ADDR_clear(&qc->init_peer_addr);
    }

    reactor_set_poll_w(&qc->rtor, &d);
    BIO_free(qc->net_wbio);
    ossl_qtx_set_bio(qc->qtx, net_wbio);
    qc->net_wbio = net_wbio;

    /*
     * If what we have is not pollable (e.g. a BIO_dgram_pair) disable blocking
     * mode as we do not support it for now.
     */
    if (net_wbio != NULL && d.type == BIO_POLL_DESCRIPTOR_TYPE_NONE)
        qc->blocking = 0;
}

/*
 * ossl_quic_conn_get_net_rbio
 * ---------------------------
 */
BIO *ossl_quic_conn_get_net_rbio(const QUIC_CONNECTION *qc)
{
    return qc->net_rbio;
}

/*
 * ossl_quic_conn_get_net_wbio
 * ---------------------------
 */
BIO *ossl_quic_conn_get_net_wbio(const QUIC_CONNECTION *qc)
{
    return qc->net_wbio;
}

/* ossl_quic_conn_get_blocking_mode
 * --------------------------------
 */
int ossl_quic_conn_get_blocking_mode(const QUIC_CONNECTION *qc)
{
    return qc->blocking;
}

/*
 * ossl_quic_conn_set_blocking_mode
 * --------------------------------
 */
int ossl_quic_conn_set_blocking_mode(QUIC_CONNECTION *qc, int blocking)
{
    /* Cannot enable blocking mode if we do not have pollable FDs. */
    if (blocking != 0 &&
        (reactor_get_poll_r(&qc->rtor)->type == BIO_POLL_DESCRIPTOR_TYPE_NONE
         || reactor_get_poll_w(&qc->rtor)->type == BIO_POLL_DESCRIPTOR_TYPE_NONE))
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_UNSUPPORTED, NULL);

    qc->blocking = (blocking != 0);
    return 1;
}

/*
 * ossl_quic_set_initial_peer_addr
 * -------------------------------
 */
int ossl_quic_conn_set_initial_peer_addr(QUIC_CONNECTION *qc,
                                         const BIO_ADDR *peer_addr)
{
    if (qc->state != QUIC_CONN_STATE_IDLE)
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

/*
 * SSL_tick
 * --------
 *
 * Ticks the reactor.
 */
int ossl_quic_tick(QUIC_CONNECTION *qc)
{
    reactor_tick(&qc->rtor);
    return 1;
}

/*
 * SSL_get_tick_timeout
 * --------------------
 *
 * Get the time in milliseconds until the SSL object should be ticked by the
 * application by calling SSL_tick(). tv is set to 0 if the object should be
 * ticked immediately and tv->tv_sec is set to -1 if no timeout is currently
 * active.
 */
int ossl_quic_get_tick_timeout(QUIC_CONNECTION *qc, struct timeval *tv)
{
    OSSL_TIME now, deadline;

    deadline = reactor_get_tick_deadline(&qc->rtor);
    if (ossl_time_is_infinite(deadline)) {
        tv->tv_sec  = -1;
        tv->tv_usec = 0;
        return 1;
    }

    now = ossl_time_now();
    if (ossl_time_compare(now, deadline) >= 0) {
        tv->tv_sec  = 0;
        tv->tv_usec = 0;
        return 1;
    }

    *tv = ossl_time_to_timeval(ossl_time_subtract(deadline, now));
    return 1;
}

/*
 * SSL_get_rpoll_descriptor
 * ------------------------
 */
int ossl_quic_get_rpoll_descriptor(QUIC_CONNECTION *qc, BIO_POLL_DESCRIPTOR *desc)
{
    if (desc == NULL)
        return 0;

    *desc = *reactor_get_poll_r(&qc->rtor);
    return 1;
}

/*
 * SSL_get_wpoll_descriptor
 * ------------------------
 */
int ossl_quic_get_wpoll_descriptor(QUIC_CONNECTION *qc, BIO_POLL_DESCRIPTOR *desc)
{
    if (desc == NULL)
        return 0;

    *desc = *reactor_get_poll_w(&qc->rtor);
    return 1;
}

/*
 * SSL_want_net_read
 * -----------------
 */
int ossl_quic_get_want_net_read(QUIC_CONNECTION *qc)
{
    return reactor_want_net_read(&qc->rtor);
}

/*
 * SSL_want_net_write
 * ------------------
 */
int ossl_quic_get_want_net_write(QUIC_CONNECTION *qc)
{
    return reactor_want_net_write(&qc->rtor);
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

/*
 * SSL_shutdown
 * ------------
 */
int ossl_quic_shutdown(SSL *s)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);
    QUIC_TERMINATE_CAUSE tcause = {0};

    if (!expect_quic_conn(qc))
        return 0;

    /* Already terminating? */
    if (!is_term_any(qc))
        return 1;

    tcause.app = 1;
    csm_start_terminating(qc, &tcause);
    return 1;
}

/* SSL_ctrl
 * --------
 */
static void fixup_mode_change(QUIC_CONNECTION *qc)
{
    /* If enabling EPW mode, cancel any AON write */
    if ((qc->ssl_mode & SSL_MODE_ENABLE_PARTIAL_WRITE) != 0)
        aon_write_finish(qc);
}

long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);

    if (!expect_quic_conn(qc))
        return 0;

    switch (cmd) {
    case SSL_CTRL_MODE:
        qc->ssl_mode |= (uint32_t)larg;
        fixup_mode_change(qc);
        return qc->ssl_mode;
    case SSL_CTRL_CLEAR_MODE:
        qc->ssl_mode &= ~(uint32_t)larg;
        fixup_mode_change(qc);
        return qc->ssl_mode;
    default:
        return 0;
    }
}

/* SSL_set_connect_state
 * ---------------------
 */
void ossl_quic_set_connect_state(QUIC_CONNECTION *qc)
{
    /* Cannot be changed after handshake started */
    if (qc->state != QUIC_CONN_STATE_IDLE)
        return;

    qc->as_server = 0;
}

/* SSL_set_accept_state
 * --------------------
 */
void ossl_quic_set_accept_state(QUIC_CONNECTION *qc)
{
    /* Cannot be changed after handshake started */
    if (qc->state != QUIC_CONN_STATE_IDLE)
        return;

    qc->as_server = 1;
}

/* SSL_do_handshake
 * ----------------
 */
struct quic_handshake_wait_args {
    QUIC_CONNECTION     *qc;
};

static int quic_handshake_wait(void *arg)
{
    struct quic_handshake_wait_args *args = arg;

    if (args->qc->state != QUIC_CONN_STATE_ACTIVE)
        return -1;

    if (args->qc->handshake_complete)
        return 1;

    return 0;
}

int ossl_quic_do_handshake(QUIC_CONNECTION *qc)
{
    int ret;

    if (is_term_any(qc))
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);

    if (BIO_ADDR_family(&qc->init_peer_addr) == AF_UNSPEC)
        /* Peer address must have been set. */
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_PASSED_INVALID_ARGUMENT, NULL);

    if (qc->as_server)
        /* TODO(QUIC): Server mode not currently supported */
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_PASSED_INVALID_ARGUMENT, NULL);

    /*
     * Start connection process. Note we may come here multiple times in
     * non-blocking mode, which is fine.
     */
    if (!csm_connect(qc))
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);

    if (qc->handshake_complete)
        /* The handshake is now done. */
        return 1;

    if (blocking_mode(qc)) {
        /* In blocking mode, wait for the handshake to complete. */
        struct quic_handshake_wait_args args;

        args.qc     = qc;

        ret = reactor_block_until_pred(&qc->rtor, quic_handshake_wait, &args, 0);
        if (qc->state != QUIC_CONN_STATE_ACTIVE)
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);
        else if (ret <= 0)
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);

        assert(qc->handshake_complete);
        return 1;
    } else {
        /* Otherwise, indicate that the handshake isn't done yet. */
        return QUIC_RAISE_NORMAL_ERROR(qc, SSL_ERROR_WANT_READ);
    }
}

/* SSL_connect
 * -----------
 */
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

/* SSL_accept
 * ----------
 */
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
 */

/*
 * SSL_get_error
 * -------------
 */
int ossl_quic_get_error(const QUIC_CONNECTION *qc, int i)
{
    return qc->last_error;
}

static int quic_raise_normal_error(QUIC_CONNECTION *qc,
                                   int err)
{
    qc->last_error = err;
    return 0;
}

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
    ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC);

    va_start(args, fmt);
    ERR_vset_error(ERR_LIB_SSL, reason, fmt, args);
    va_end(args);

    qc->last_error = SSL_ERROR_SSL;
    return 0;
}

/*
 * SSL_write
 * ---------
 *
 * This function provides the implementation of the public SSL_write function.
 * It must handle:
 *
 *   - both blocking and non-blocking operation at the application level,
 *     depending on how we are configured;
 *
 *   - SSL_MODE_ENABLE_PARTIAL_WRITE being on or off;
 *
 *   - SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER.
 *
 */
static void quic_post_write(QUIC_CONNECTION *qc, int did_append, int do_tick)
{
    /*
     * We have appended at least one byte to the stream.
     * Potentially mark stream as active, depending on FC.
     */
    if (did_append)
        ossl_quic_stream_map_update_state(&qc->qsm, qc->stream0);

    /*
     * Try and send.
     *
     * TODO(QUIC): It is probably inefficient to try and do this immediately,
     * plus we should eventually consider Nagle's algorithm.
     */
    if (do_tick)
        reactor_tick(&qc->rtor);
}

struct quic_write_again_args {
    QUIC_CONNECTION     *qc;
    const unsigned char *buf;
    size_t              len;
    size_t              total_written;
};

static int quic_write_again(void *arg)
{
    struct quic_write_again_args *args = arg;
    size_t actual_written = 0;

    if (args->qc->state != QUIC_CONN_STATE_ACTIVE)
        /* If connection is torn down due to an error while blocking, stop. */
        return -2;

    if (!ossl_quic_sstream_append(args->qc->stream0->sstream,
                                  args->buf, args->len, &actual_written))
        return -2;

    quic_post_write(args->qc, actual_written > 0, 0);

    args->buf           += actual_written;
    args->len           -= actual_written;
    args->total_written += actual_written;

    if (actual_written == 0)
        /* Written everything, done. */
        return 1;

    /* Not written everything yet, keep trying. */
    return 0;
}

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

    res = reactor_block_until_pred(&qc->rtor, quic_write_again, &args, 0);
    if (res <= 0) {
        if (qc->state != QUIC_CONN_STATE_ACTIVE)
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);
        else
            return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
    }

    *written = args.total_written;
    return 1;
}

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
         * manage to append all data to the SSTREAM and we have EPW mode
         * disabled.)
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

int ossl_quic_write(SSL *s, const void *buf, size_t len, size_t *written)
{
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);
    int partial_write = ((qc->ssl_mode & SSL_MODE_ENABLE_PARTIAL_WRITE) != 0);

    *written = 0;

    if (!expect_quic_conn(qc))
        return 0;

    if (!is_active(qc))
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);

    if (qc->stream0 == NULL || qc->stream0->sstream == NULL)
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);

    if (blocking_mode(qc))
        return quic_write_blocking(qc, buf, len, written);
    else if (partial_write)
        return quic_write_nonblocking_epw(qc, buf, len, written);
    else
        return quic_write_nonblocking_aon(qc, buf, len, written);
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

static int quic_read_actual(QUIC_CONNECTION *qc,
                            QUIC_STREAM *stream,
                            void *buf, size_t buf_len,
                            size_t *bytes_read,
                            int peek)
{
    int is_fin = 0;

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
            ossl_statm_get_rtt_info(&qc->statm, &rtt_info);

            if (!ossl_quic_rxfc_on_retire(&qc->stream0->rxfc, *bytes_read,
                                          rtt_info.smoothed_rtt))
                return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
        }

        if (is_fin)
            stream->recv_fin_retired = 1;

        if (*bytes_read > 0)
            ossl_quic_stream_map_update_state(&qc->qsm, qc->stream0);
    }

    return 1;
}

static int quic_read_again(void *arg)
{
    struct quic_read_again_args *args = arg;

    if (!is_active(args->qc))
        /* If connection is torn down due to an error while blocking, stop. */
        return -2;

    if (!quic_read_actual(args->qc, args->stream,
                          args->buf, args->len, args->bytes_read,
                          args->peek))
        return -1;

    if (*args->bytes_read > 0)
        /* got at least one byte, the SSL_read op can finish now */
        return 1;

    return 0; /* did not write anything, keep trying */
}

static int quic_read(SSL *s, void *buf, size_t len, size_t *bytes_read, int peek)
{
    int res;
    QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_SSL(s);
    struct quic_read_again_args args;

    *bytes_read = 0;

    if (!expect_quic_conn(qc))
        return 0;

    if (!is_active(qc))
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);

    if (qc->stream0 == NULL)
        return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);

    if (!quic_read_actual(qc, qc->stream0, buf, len, bytes_read, peek))
        return 0;

    if (*bytes_read > 0) {
        /*
         * Even though we succeeded, tick the reactor here to ensure we are
         * handling other aspects of the QUIC connection.
         */
        reactor_tick(&qc->rtor);
        return 1;
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

        res = reactor_block_until_pred(&qc->rtor, quic_read_again, &args, 0);
        if (res <= 0) {
            if (qc->state != QUIC_CONN_STATE_ACTIVE)
                return QUIC_RAISE_NON_NORMAL_ERROR(qc, SSL_R_PROTOCOL_IS_SHUTDOWN, NULL);
            else
                return QUIC_RAISE_NON_NORMAL_ERROR(qc, ERR_R_INTERNAL_ERROR, NULL);
        }
    }

    return 1;
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
size_t ossl_quic_pending(const SSL *s)
{
    const QUIC_CONNECTION *qc = QUIC_CONNECTION_FROM_CONST_SSL(s);
    size_t avail = 0;
    int fin = 0;

    if (!expect_quic_conn(qc))
        return 0;

    if (qc->stream0 == NULL || qc->stream0->rstream == NULL)
        /* Cannot raise errors here because we are const, just fail. */
        return 0;

    if (!ossl_quic_rstream_available(qc->stream0->rstream, &avail, &fin))
        return 0;

    return avail;
}

/*
 * QUIC Front-End I/O API: SSL_CTX Management
 * ==========================================
 */

long ossl_quic_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    switch (cmd) {
    default:
        return 0;
    }
}

long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void))
{
    return 0;
}

long ossl_quic_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
{
    return 0;
}

QUIC_CONNECTION *ossl_quic_conn_from_ssl(SSL *ssl)
{
    return QUIC_CONNECTION_FROM_SSL(ssl);
}

int ossl_quic_renegotiate_check(SSL *ssl, int initok)
{
    /* We never do renegotiation. */
    return 0;
}

/*
 * This is the subset of TLS1.3 ciphers which can be used with QUIC and which we
 * actually support.
 */
static SSL_CIPHER tls13_quic_ciphers[] = {
    {
        1,
        TLS1_3_RFC_AES_128_GCM_SHA256,
        TLS1_3_RFC_AES_128_GCM_SHA256,
        TLS1_3_CK_AES_128_GCM_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128GCM,
        SSL_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    }, {
        1,
        TLS1_3_RFC_AES_256_GCM_SHA384,
        TLS1_3_RFC_AES_256_GCM_SHA384,
        TLS1_3_CK_AES_256_GCM_SHA384,
        SSL_kANY,
        SSL_aANY,
        SSL_AES256GCM,
        SSL_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA384,
        256,
        256,
    },
    {
        1,
        TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        TLS1_3_CK_CHACHA20_POLY1305_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_CHACHA20POLY1305,
        SSL_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        256,
        256,
    }
};

int ossl_quic_num_ciphers(void)
{
    return OSSL_NELEM(tls13_quic_ciphers);
}

const SSL_CIPHER *ossl_quic_get_cipher(unsigned int u)
{
    if (u >= OSSL_NELEM(tls13_quic_ciphers))
        return NULL;

    return &tls13_quic_ciphers[u];
}
