/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/lhash.h>
#include "internal/quic_tserver.h"
#include "internal/quic_ssl.h"
#include "testutil.h"
#if defined(OPENSSL_THREADS)
# include "internal/thread_arch.h"
#endif

static const char *certfile, *keyfile;

#if defined(OPENSSL_THREADS)
struct child_thread_args {
    struct helper *h;
    const struct script_op *script;
    int thread_idx;

    CRYPTO_THREAD *t;
    CRYPTO_MUTEX *m;
    int testresult;
    int done;
};
#endif

typedef struct stream_info {
    const char      *name;
    SSL             *c_stream;
    uint64_t        s_stream_id;
} STREAM_INFO;

DEFINE_LHASH_OF_EX(STREAM_INFO);

struct helper {
    int                     s_fd;
    BIO                     *s_net_bio, *s_net_bio_own;
    BIO_ADDR                *s_net_bio_addr;
    QUIC_TSERVER            *s;
    LHASH_OF(STREAM_INFO)   *s_streams;

    int                     c_fd;
    BIO                     *c_net_bio, *c_net_bio_own;
    SSL_CTX                 *c_ctx;
    SSL                     *c_conn;
    LHASH_OF(STREAM_INFO)   *c_streams;

#if defined(OPENSSL_THREADS)
    struct child_thread_args    *threads;
    size_t                      num_threads;
#endif

    OSSL_TIME       start_time;

    /*
     * This is a duration recording the amount of time we have skipped forwards
     * for testing purposes relative to the real ossl_time_now() clock. We add
     * a quantity of time to this every time we skip some time.
     */
    CRYPTO_RWLOCK   *time_lock;
    OSSL_TIME       time_slip; /* protected by time_lock */

    int             init, blocking, check_spin_again;
    int             free_order;
};

struct helper_local {
    struct helper           *h;
    LHASH_OF(STREAM_INFO)   *c_streams;
    int                     thread_idx;
};

struct script_op {
    uint32_t        op;
    const void      *arg0;
    size_t          arg1;
    int             (*check_func)(struct helper *h, const struct script_op *op);
    const char      *stream_name;
    uint64_t        arg2;
};

#define OPK_END                                     0
#define OPK_CHECK                                   1
#define OPK_C_SET_ALPN                              2
#define OPK_C_CONNECT_WAIT                          3
#define OPK_C_WRITE                                 4
#define OPK_S_WRITE                                 5
#define OPK_C_READ_EXPECT                           6
#define OPK_S_READ_EXPECT                           7
#define OPK_C_EXPECT_FIN                            8
#define OPK_S_EXPECT_FIN                            9
#define OPK_C_CONCLUDE                              10
#define OPK_S_CONCLUDE                              11
#define OPK_C_DETACH                                12
#define OPK_C_ATTACH                                13
#define OPK_C_NEW_STREAM                            14
#define OPK_S_NEW_STREAM                            15
#define OPK_C_ACCEPT_STREAM_WAIT                    16
#define OPK_C_ACCEPT_STREAM_NONE                    17
#define OPK_C_FREE_STREAM                           18
#define OPK_C_SET_DEFAULT_STREAM_MODE               19
#define OPK_C_SET_INCOMING_STREAM_POLICY            20
#define OPK_C_SHUTDOWN                              21
#define OPK_C_EXPECT_CONN_CLOSE_INFO                22
#define OPK_S_EXPECT_CONN_CLOSE_INFO                23
#define OPK_S_BIND_STREAM_ID                        24
#define OPK_C_WAIT_FOR_DATA                         25
#define OPK_C_WRITE_FAIL                            26
#define OPK_S_WRITE_FAIL                            27
#define OPK_C_READ_FAIL                             28
#define OPK_C_STREAM_RESET                          29
#define OPK_S_ACCEPT_STREAM_WAIT                    30
#define OPK_NEW_THREAD                              31
#define OPK_BEGIN_REPEAT                            32
#define OPK_END_REPEAT                              33
#define OPK_S_UNBIND_STREAM_ID                      34

#define EXPECT_CONN_CLOSE_APP       (1U << 0)
#define EXPECT_CONN_CLOSE_REMOTE    (1U << 1)

#define C_BIDI_ID(ordinal) \
    (((ordinal) << 2) | QUIC_STREAM_INITIATOR_CLIENT | QUIC_STREAM_DIR_BIDI)
#define S_BIDI_ID(ordinal) \
    (((ordinal) << 2) | QUIC_STREAM_INITIATOR_SERVER | QUIC_STREAM_DIR_BIDI)
#define C_UNI_ID(ordinal) \
    (((ordinal) << 2) | QUIC_STREAM_INITIATOR_CLIENT | QUIC_STREAM_DIR_UNI)
#define S_UNI_ID(ordinal) \
    (((ordinal) << 2) | QUIC_STREAM_INITIATOR_SERVER | QUIC_STREAM_DIR_UNI)

#define ANY_ID UINT64_MAX

#define OP_END  \
    {OPK_END}
#define OP_CHECK(func, arg2)  \
    {OPK_CHECK, NULL, 0, (func), NULL, (arg2)},
#define OP_C_SET_ALPN(alpn) \
    {OPK_C_SET_ALPN, (alpn), 0, NULL, NULL},
#define OP_C_CONNECT_WAIT() \
    {OPK_C_CONNECT_WAIT, NULL, 0, NULL, NULL},
#define OP_C_WRITE(stream_name, buf, buf_len)   \
    {OPK_C_WRITE, (buf), (buf_len), NULL, #stream_name},
#define OP_S_WRITE(stream_name, buf, buf_len)   \
    {OPK_S_WRITE, (buf), (buf_len), NULL, #stream_name},
#define OP_C_READ_EXPECT(stream_name, buf, buf_len)   \
    {OPK_C_READ_EXPECT, (buf), (buf_len), NULL, #stream_name},
#define OP_S_READ_EXPECT(stream_name, buf, buf_len)   \
    {OPK_S_READ_EXPECT, (buf), (buf_len), NULL, #stream_name},
#define OP_C_EXPECT_FIN(stream_name) \
    {OPK_C_EXPECT_FIN, NULL, 0, NULL, #stream_name},
#define OP_S_EXPECT_FIN(stream_name) \
    {OPK_S_EXPECT_FIN, NULL, 0, NULL, #stream_name},
#define OP_C_CONCLUDE(stream_name) \
    {OPK_C_CONCLUDE, NULL, 0, NULL, #stream_name},
#define OP_S_CONCLUDE(stream_name) \
    {OPK_S_CONCLUDE, NULL, 0, NULL, #stream_name},
#define OP_C_DETACH(stream_name) \
    {OPK_C_DETACH, NULL, 0, NULL, #stream_name},
#define OP_C_ATTACH(stream_name) \
    {OPK_C_ATTACH, NULL, 0, NULL, #stream_name},
#define OP_C_NEW_STREAM_BIDI(stream_name, expect_id) \
    {OPK_C_NEW_STREAM, NULL, 0, NULL, #stream_name, (expect_id)},
#define OP_C_NEW_STREAM_UNI(stream_name, expect_id) \
    {OPK_C_NEW_STREAM, NULL, 1, NULL, #stream_name, (expect_id)},
#define OP_S_NEW_STREAM_BIDI(stream_name, expect_id) \
    {OPK_S_NEW_STREAM, NULL, 0, NULL, #stream_name, (expect_id)},
#define OP_S_NEW_STREAM_UNI(stream_name, expect_id) \
    {OPK_S_NEW_STREAM, NULL, 1, NULL, #stream_name, (expect_id)},
#define OP_C_ACCEPT_STREAM_WAIT(stream_name) \
    {OPK_C_ACCEPT_STREAM_WAIT, NULL, 0, NULL, #stream_name},
#define OP_C_ACCEPT_STREAM_NONE() \
    {OPK_C_ACCEPT_STREAM_NONE, NULL, 0, NULL, NULL},
#define OP_C_FREE_STREAM(stream_name) \
    {OPK_C_FREE_STREAM, NULL, 0, NULL, #stream_name},
#define OP_C_SET_DEFAULT_STREAM_MODE(mode) \
    {OPK_C_SET_DEFAULT_STREAM_MODE, NULL, (mode), NULL, NULL},
#define OP_C_SET_INCOMING_STREAM_POLICY(policy) \
    {OPK_C_SET_INCOMING_STREAM_POLICY, NULL, (policy), NULL, NULL},
#define OP_C_SHUTDOWN() \
    {OPK_C_SHUTDOWN, NULL, 0, NULL, NULL},
#define OP_C_EXPECT_CONN_CLOSE_INFO(ec, app, remote)                \
    {OPK_C_EXPECT_CONN_CLOSE_INFO, NULL,                            \
        ((app) ? EXPECT_CONN_CLOSE_APP : 0) |                       \
        ((remote) ? EXPECT_CONN_CLOSE_REMOTE : 0),                  \
        NULL, NULL, (ec)},
#define OP_S_EXPECT_CONN_CLOSE_INFO(ec, app, remote) \
    {OPK_S_EXPECT_CONN_CLOSE_INFO, NULL,            \
        ((app) ? EXPECT_CONN_CLOSE_APP : 0) |       \
        ((remote) ? EXPECT_CONN_CLOSE_REMOTE : 0),  \
        NULL, NULL, (ec)},
#define OP_S_BIND_STREAM_ID(stream_name, stream_id) \
    {OPK_S_BIND_STREAM_ID, NULL, 0, NULL, #stream_name, (stream_id)},
#define OP_C_WAIT_FOR_DATA(stream_name) \
    {OPK_C_WAIT_FOR_DATA, NULL, 0, NULL, #stream_name},
#define OP_C_WRITE_FAIL(stream_name)  \
    {OPK_C_WRITE_FAIL, NULL, 0, NULL, #stream_name},
#define OP_S_WRITE_FAIL(stream_name)  \
    {OPK_S_WRITE_FAIL, NULL, 0, NULL, #stream_name},
#define OP_C_READ_FAIL(stream_name)  \
    {OPK_C_READ_FAIL, NULL, 0, NULL, #stream_name},
#define OP_C_STREAM_RESET(stream_name, aec)  \
    {OPK_C_STREAM_RESET, NULL, 0, NULL, #stream_name, (aec)},
#define OP_S_ACCEPT_STREAM_WAIT(stream_name)  \
    {OPK_S_ACCEPT_STREAM_WAIT, NULL, 0, NULL, #stream_name},
#define OP_NEW_THREAD(num_threads, script) \
    {OPK_NEW_THREAD, (script), (num_threads), NULL, NULL, 0 },
#define OP_BEGIN_REPEAT(n)  \
    {OPK_BEGIN_REPEAT, NULL, (n)},
#define OP_END_REPEAT() \
    {OPK_END_REPEAT},
#define OP_S_UNBIND_STREAM_ID(stream_name) \
    {OPK_S_UNBIND_STREAM_ID, NULL, 0, NULL, #stream_name},

static OSSL_TIME get_time(void *arg)
{
    struct helper *h = arg;
    OSSL_TIME t;

    if (!TEST_true(CRYPTO_THREAD_read_lock(h->time_lock)))
        return ossl_time_zero();

    t = ossl_time_add(ossl_time_now(), h->time_slip);

    CRYPTO_THREAD_unlock(h->time_lock);
    return t;
}

static int skip_time_ms(struct helper *h, const struct script_op *op)
{
    if (!TEST_true(CRYPTO_THREAD_write_lock(h->time_lock)))
        return 0;

    h->time_slip = ossl_time_add(h->time_slip, ossl_ms2time(op->arg2));

    CRYPTO_THREAD_unlock(h->time_lock);
    return 1;
}

static int check_rejected(struct helper *h, const struct script_op *op)
{
    uint64_t stream_id = op->arg2;

    if (!ossl_quic_tserver_stream_has_peer_stop_sending(h->s, stream_id, NULL)
        || !ossl_quic_tserver_stream_has_peer_reset_stream(h->s, stream_id, NULL)) {
        h->check_spin_again = 1;
        return 0;
    }

    return 1;
}

static int check_stream_reset(struct helper *h, const struct script_op *op)
{
    uint64_t stream_id = op->arg2, aec = 0;

    if (!ossl_quic_tserver_stream_has_peer_reset_stream(h->s, stream_id, &aec)) {
        h->check_spin_again = 1;
        return 0;
    }

    return TEST_uint64_t_eq(aec, 42);
}

static int check_stream_stopped(struct helper *h, const struct script_op *op)
{
    uint64_t stream_id = op->arg2;

    if (!ossl_quic_tserver_stream_has_peer_stop_sending(h->s, stream_id, NULL)) {
        h->check_spin_again = 1;
        return 0;
    }

    return 1;
}

static int override_key_update(struct helper *h, const struct script_op *op)
{
    QUIC_CHANNEL *ch = ossl_quic_conn_get_channel(h->c_conn);

    ossl_quic_channel_set_txku_threshold_override(ch, op->arg2);
    return 1;
}

static int trigger_key_update(struct helper *h, const struct script_op *op)
{
    if (!TEST_true(SSL_key_update(h->c_conn, SSL_KEY_UPDATE_REQUESTED)))
        return 0;

    return 1;
}

static int check_key_update_ge(struct helper *h, const struct script_op *op)
{
    QUIC_CHANNEL *ch = ossl_quic_conn_get_channel(h->c_conn);
    int64_t txke = (int64_t)ossl_quic_channel_get_tx_key_epoch(ch);
    int64_t rxke = (int64_t)ossl_quic_channel_get_rx_key_epoch(ch);
    int64_t diff = txke - rxke;

    /*
     * TXKE must always be equal to or ahead of RXKE.
     * It can be ahead of RXKE by at most 1.
     */
    if (!TEST_int64_t_ge(diff, 0) || !TEST_int64_t_le(diff, 1))
        return 0;

    /* Caller specifies a minimum number of RXKEs which must have happened. */
    if (!TEST_uint64_t_ge((uint64_t)rxke, op->arg2))
        return 0;

    return 1;
}

static int check_key_update_lt(struct helper *h, const struct script_op *op)
{
    QUIC_CHANNEL *ch = ossl_quic_conn_get_channel(h->c_conn);
    uint64_t txke = ossl_quic_channel_get_tx_key_epoch(ch);

    /* Caller specifies a maximum number of TXKEs which must have happened. */
    if (!TEST_uint64_t_lt(txke, op->arg2))
        return 0;

    return 1;
}

static unsigned long stream_info_hash(const STREAM_INFO *info)
{
    return OPENSSL_LH_strhash(info->name);
}

static int stream_info_cmp(const STREAM_INFO *a, const STREAM_INFO *b)
{
    return strcmp(a->name, b->name);
}

static void cleanup_stream(STREAM_INFO *info)
{
    SSL_free(info->c_stream);
    OPENSSL_free(info);
}

static void helper_cleanup_streams(LHASH_OF(STREAM_INFO) **lh)
{
    if (*lh == NULL)
        return;

    lh_STREAM_INFO_doall(*lh, cleanup_stream);
    lh_STREAM_INFO_free(*lh);
    *lh = NULL;
}

#if defined(OPENSSL_THREADS)
static CRYPTO_THREAD_RETVAL run_script_child_thread(void *arg);

static int join_threads(struct child_thread_args *threads, size_t num_threads)
{
    int ok = 1;
    size_t i;
    CRYPTO_THREAD_RETVAL rv;

    for (i = 0; i < num_threads; ++i) {
        if (threads[i].t != NULL) {
            ossl_crypto_thread_native_join(threads[i].t, &rv);

            if (!threads[i].testresult)
                /* Do not log failure here, worker will do it. */
                ok = 0;

            ossl_crypto_thread_native_clean(threads[i].t);
            threads[i].t = NULL;
        }

        ossl_crypto_mutex_free(&threads[i].m);
    }

    return ok;
}
#endif

static void helper_cleanup(struct helper *h)
{
#if defined(OPENSSL_THREADS)
    join_threads(h->threads, h->num_threads);
    OPENSSL_free(h->threads);
    h->threads = NULL;
    h->num_threads = 0;
#endif

    if (h->free_order == 0) {
        /* order 0: streams, then conn */
        helper_cleanup_streams(&h->c_streams);

        SSL_free(h->c_conn);
        h->c_conn = NULL;
    } else {
        /* order 1: conn, then streams */
        SSL_free(h->c_conn);
        h->c_conn = NULL;

        helper_cleanup_streams(&h->c_streams);
    }

    helper_cleanup_streams(&h->s_streams);
    ossl_quic_tserver_free(h->s);
    h->s = NULL;

    BIO_free(h->s_net_bio_own);
    h->s_net_bio_own = NULL;

    BIO_free(h->c_net_bio_own);
    h->c_net_bio_own = NULL;

    if (h->s_fd >= 0) {
        BIO_closesocket(h->s_fd);
        h->s_fd = -1;
    }

    if (h->c_fd >= 0) {
        BIO_closesocket(h->c_fd);
        h->c_fd = -1;
    }

    BIO_ADDR_free(h->s_net_bio_addr);
    h->s_net_bio_addr = NULL;

    SSL_CTX_free(h->c_ctx);
    h->c_ctx = NULL;

    CRYPTO_THREAD_lock_free(h->time_lock);
    h->time_lock = NULL;
}

static int helper_init(struct helper *h, int free_order)
{
    short port = 8186;
    struct in_addr ina = {0};
    QUIC_TSERVER_ARGS s_args = {0};

    memset(h, 0, sizeof(*h));
    h->c_fd = -1;
    h->s_fd = -1;
    h->free_order = free_order;
    h->time_slip = ossl_time_zero();

    if (!TEST_ptr(h->time_lock = CRYPTO_THREAD_lock_new()))
        goto err;

    if (!TEST_ptr(h->s_streams = lh_STREAM_INFO_new(stream_info_hash,
                                                    stream_info_cmp)))
        goto err;

    if (!TEST_ptr(h->c_streams = lh_STREAM_INFO_new(stream_info_hash,
                                                    stream_info_cmp)))
        goto err;

    ina.s_addr = htonl(0x7f000001UL);

    h->s_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(h->s_fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(h->s_fd, 1)))
        goto err;

    if (!TEST_ptr(h->s_net_bio_addr = BIO_ADDR_new()))
        goto err;

    if (!TEST_true(BIO_ADDR_rawmake(h->s_net_bio_addr, AF_INET, &ina, sizeof(ina),
                                    htons(port))))
        goto err;

    if (!TEST_true(BIO_bind(h->s_fd, h->s_net_bio_addr, 0)))
        goto err;

    if (!TEST_int_gt(BIO_ADDR_rawport(h->s_net_bio_addr), 0))
        goto err;

    if  (!TEST_ptr(h->s_net_bio = h->s_net_bio_own = BIO_new_dgram(h->s_fd, 0)))
        goto err;

    if (!BIO_up_ref(h->s_net_bio))
        goto err;

    s_args.net_rbio     = h->s_net_bio;
    s_args.net_wbio     = h->s_net_bio;
    s_args.now_cb       = get_time;
    s_args.now_cb_arg   = h;

    if (!TEST_ptr(h->s = ossl_quic_tserver_new(&s_args, certfile, keyfile)))
        goto err;

    h->s_net_bio_own = NULL;

    h->c_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(h->c_fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(h->c_fd, 1)))
        goto err;

    if (!TEST_ptr(h->c_net_bio = h->c_net_bio_own = BIO_new_dgram(h->c_fd, 0)))
        goto err;

    if (!TEST_true(BIO_dgram_set_peer(h->c_net_bio, h->s_net_bio_addr)))
        goto err;


    if (!TEST_ptr(h->c_ctx = SSL_CTX_new(OSSL_QUIC_client_method())))
        goto err;

    if (!TEST_ptr(h->c_conn = SSL_new(h->c_ctx)))
        goto err;

    /* Use custom time function for virtual time skip. */
    if (!TEST_true(ossl_quic_conn_set_override_now_cb(h->c_conn, get_time, h)))
        goto err;

    /* Takes ownership of our reference to the BIO. */
    SSL_set0_rbio(h->c_conn, h->c_net_bio);
    h->c_net_bio_own = NULL;

    if (!TEST_true(BIO_up_ref(h->c_net_bio)))
        goto err;

    SSL_set0_wbio(h->c_conn, h->c_net_bio);

    if (!TEST_true(SSL_set_blocking_mode(h->c_conn, 0)))
        goto err;

    h->start_time   = ossl_time_now();
    h->init         = 1;
    return 1;

err:
    helper_cleanup(h);
    return 0;
}

static int helper_local_init(struct helper_local *hl, struct helper *h,
                             int thread_idx)
{
    hl->h           = h;
    hl->c_streams   = NULL;
    hl->thread_idx  = thread_idx;

    if (!TEST_ptr(h))
        return 0;

    if (thread_idx < 0) {
        hl->c_streams = h->c_streams;
    } else {
        if (!TEST_ptr(hl->c_streams = lh_STREAM_INFO_new(stream_info_hash,
                                                         stream_info_cmp)))
            return 0;
    }

    return 1;
}

static void helper_local_cleanup(struct helper_local *hl)
{
    if (hl->h == NULL)
        return;

    if (hl->thread_idx >= 0)
        helper_cleanup_streams(&hl->c_streams);

    hl->h = NULL;
}

static STREAM_INFO *get_stream_info(LHASH_OF(STREAM_INFO) *lh,
                                    const char *stream_name)
{
    STREAM_INFO key, *info;

    if (!TEST_ptr(stream_name))
        return NULL;

    if (!strcmp(stream_name, "DEFAULT"))
        return NULL;

    key.name = stream_name;
    info = lh_STREAM_INFO_retrieve(lh, &key);
    if (info == NULL) {
        info = OPENSSL_zalloc(sizeof(*info));
        if (info == NULL)
            return NULL;

        info->name          = stream_name;
        info->s_stream_id   = UINT64_MAX;
        lh_STREAM_INFO_insert(lh, info);
    }

    return info;
}

static int helper_local_set_c_stream(struct helper_local *hl,
                                     const char *stream_name,
                                     SSL *c_stream)
{
    STREAM_INFO *info = get_stream_info(hl->c_streams, stream_name);

    if (info == NULL)
        return 0;

    info->c_stream      = c_stream;
    info->s_stream_id   = UINT64_MAX;
    return 1;
}

static SSL *helper_local_get_c_stream(struct helper_local *hl,
                                      const char *stream_name)
{
    STREAM_INFO *info;

    if (!strcmp(stream_name, "DEFAULT"))
        return hl->h->c_conn;

    info = get_stream_info(hl->c_streams, stream_name);
    if (info == NULL)
        return NULL;

    return info->c_stream;
}

static int
helper_set_s_stream(struct helper *h, const char *stream_name,
                    uint64_t s_stream_id)
{
    STREAM_INFO *info;

    if (!strcmp(stream_name, "DEFAULT"))
        return 0;

    info = get_stream_info(h->s_streams, stream_name);
    if (info == NULL)
        return 0;

    info->c_stream      = NULL;
    info->s_stream_id   = s_stream_id;
    return 1;
}

static uint64_t helper_get_s_stream(struct helper *h, const char *stream_name)
{
    STREAM_INFO *info;

    if (!strcmp(stream_name, "DEFAULT"))
        return UINT64_MAX;

    info = get_stream_info(h->s_streams, stream_name);
    if (info == NULL)
        return UINT64_MAX;

    return info->s_stream_id;
}

static int is_want(SSL *s, int ret)
{
    int ec = SSL_get_error(s, ret);

    return ec == SSL_ERROR_WANT_READ || ec == SSL_ERROR_WANT_WRITE;
}

static int run_script_worker(struct helper *h, const struct script_op *script,
                             int thread_idx)
{
    int testresult = 0;
    unsigned char *tmp_buf = NULL;
    int connect_started = 0;
    size_t offset = 0;
    size_t op_idx = 0;
    const struct script_op *op = NULL;
    int no_advance = 0, first = 1;
#if defined(OPENSSL_THREADS)
    int end_wait_warning = 0;
#endif
    OSSL_TIME op_start_time = ossl_time_zero(), op_deadline = ossl_time_zero();
    struct helper_local hl;
#define REPEAT_SLOTS 8
    size_t repeat_stack_idx[REPEAT_SLOTS], repeat_stack_done[REPEAT_SLOTS];
    size_t repeat_stack_limit[REPEAT_SLOTS];
    size_t repeat_stack_len = 0;

    if (!TEST_true(helper_local_init(&hl, h, thread_idx)))
        goto out;

#define SPIN_AGAIN() { OSSL_sleep(1); no_advance = 1; continue; }

    for (;;) {
        SSL *c_tgt              = h->c_conn;
        uint64_t s_stream_id    = UINT64_MAX;

        if (no_advance) {
            no_advance = 0;
        } else {
            if (!first)
                ++op_idx;

            first           = 0;
            offset          = 0;
            op_start_time   = ossl_time_now();
            op_deadline     = ossl_time_add(op_start_time, ossl_ms2time(2000));
        }

        if (!TEST_int_le(ossl_time_compare(ossl_time_now(), op_deadline), 0)) {
            TEST_error("op %zu timed out on thread %d", op_idx + 1, thread_idx);
            goto out;
        }

        op = &script[op_idx];

        if (op->stream_name != NULL) {
            c_tgt = helper_local_get_c_stream(&hl, op->stream_name);
            if (thread_idx < 0)
                s_stream_id = helper_get_s_stream(h, op->stream_name);
            else
                s_stream_id = UINT64_MAX;
        }

        if (thread_idx < 0)
            ossl_quic_tserver_tick(h->s);

        if (thread_idx >= 0 || connect_started)
            SSL_handle_events(h->c_conn);

        if (thread_idx >= 0) {
            /* Only allow certain opcodes on child threads. */
            switch (op->op) {
                case OPK_END:
                case OPK_C_ACCEPT_STREAM_WAIT:
                case OPK_C_NEW_STREAM:
                case OPK_C_READ_EXPECT:
                case OPK_C_EXPECT_FIN:
                case OPK_C_WRITE:
                case OPK_C_CONCLUDE:
                case OPK_C_FREE_STREAM:
                case OPK_BEGIN_REPEAT:
                case OPK_END_REPEAT:
                    break;

                default:
                    TEST_error("opcode %d not allowed on child thread", op->op);
                    goto out;
            }
        }

        switch (op->op) {
        case OPK_END:
            if (!TEST_size_t_eq(repeat_stack_len, 0))
                goto out;

#if defined(OPENSSL_THREADS)
            if (thread_idx < 0) {
                int done;
                size_t i;

                for (i = 0; i < h->num_threads; ++i) {
                    if (h->threads[i].m == NULL)
                        continue;

                    ossl_crypto_mutex_lock(h->threads[i].m);
                    done = h->threads[i].done;
                    ossl_crypto_mutex_unlock(h->threads[i].m);

                    if (!done) {
                        if (!end_wait_warning) {
                            TEST_info("still waiting for other threads to finish (%zu)", i);
                            end_wait_warning = 1;
                        }

                        SPIN_AGAIN();
                    }
                }
            }
#endif

            TEST_info("script finished on thread %d", thread_idx);
            testresult = 1;
            goto out;

        case OPK_BEGIN_REPEAT:
            if (!TEST_size_t_lt(repeat_stack_len, OSSL_NELEM(repeat_stack_idx)))
                goto out;

            if (!TEST_size_t_gt(op->arg1, 0))
                goto out;

            repeat_stack_idx[repeat_stack_len] = op_idx + 1;
            repeat_stack_done[repeat_stack_len] = 0;
            repeat_stack_limit[repeat_stack_len] = op->arg1;
            ++repeat_stack_len;
            break;

        case OPK_END_REPEAT:
            if (!TEST_size_t_gt(repeat_stack_len, 0))
                goto out;

            if (++repeat_stack_done[repeat_stack_len - 1]
                == repeat_stack_limit[repeat_stack_len - 1]) {
                --repeat_stack_len;
            } else {
                op_idx = repeat_stack_idx[repeat_stack_len - 1];
                no_advance = 1;
                continue;
            }

            break;

        case OPK_CHECK:
            {
                int ok = op->check_func(h, op);
                if (h->check_spin_again) {
                    h->check_spin_again = 0;
                    SPIN_AGAIN();
                }

                if (!TEST_true(ok))
                    goto out;
            }
            break;

        case OPK_C_SET_ALPN:
            {
                const char *alpn = op->arg0;
                size_t alpn_len = strlen(alpn);

                if (!TEST_size_t_le(alpn_len, UINT8_MAX)
                    || !TEST_ptr(tmp_buf = (unsigned char *)OPENSSL_malloc(alpn_len + 1)))
                    goto out;

                memcpy(tmp_buf + 1, alpn, alpn_len);
                tmp_buf[0] = (unsigned char)alpn_len;

                /* 0 is the success case for SSL_set_alpn_protos(). */
                if (!TEST_false(SSL_set_alpn_protos(h->c_conn, tmp_buf,
                                                    alpn_len + 1)))
                    goto out;

                OPENSSL_free(tmp_buf);
                tmp_buf = NULL;
            }
            break;

        case OPK_C_CONNECT_WAIT:
            {
                int ret;

                connect_started = 1;

                ret = SSL_connect(h->c_conn);
                if (!TEST_true(ret == 1
                               || (!h->blocking && is_want(h->c_conn, ret))))
                    goto out;

                if (!h->blocking && ret != 1)
                    SPIN_AGAIN();
            }
            break;

        case OPK_C_WRITE:
            {
                size_t bytes_written = 0;

                if (!TEST_ptr(c_tgt))
                    goto out;

                if (!TEST_true(SSL_write_ex(c_tgt, op->arg0, op->arg1,
                                            &bytes_written))
                    || !TEST_size_t_eq(bytes_written, op->arg1))
                    goto out;
            }
            break;

        case OPK_S_WRITE:
            {
                size_t bytes_written = 0;

                if (!TEST_uint64_t_ne(s_stream_id, UINT64_MAX))
                    goto out;

                if (!TEST_true(ossl_quic_tserver_write(h->s, s_stream_id,
                                                       op->arg0, op->arg1,
                                                       &bytes_written))
                    || !TEST_size_t_eq(bytes_written, op->arg1))
                    goto out;
            }
            break;

        case OPK_C_CONCLUDE:
            {
                if (!TEST_true(SSL_stream_conclude(c_tgt, 0)))
                    goto out;
            }
            break;

        case OPK_S_CONCLUDE:
            {
                if (!TEST_uint64_t_ne(s_stream_id, UINT64_MAX))
                    goto out;

                ossl_quic_tserver_conclude(h->s, s_stream_id);
            }
            break;

        case OPK_C_WAIT_FOR_DATA:
            {
                char buf[1];
                size_t bytes_read = 0;

                if (!TEST_ptr(c_tgt))
                    goto out;

                if (!SSL_peek_ex(c_tgt, buf, sizeof(buf), &bytes_read)
                    || bytes_read == 0)
                    SPIN_AGAIN();
            }
            break;

        case OPK_C_READ_EXPECT:
            {
                size_t bytes_read = 0;

                if (op->arg1 > 0 && tmp_buf == NULL
                    && !TEST_ptr(tmp_buf = OPENSSL_malloc(op->arg1)))
                    goto out;

                if (!SSL_read_ex(c_tgt, tmp_buf + offset, op->arg1 - offset,
                                 &bytes_read))
                    SPIN_AGAIN();

                if (bytes_read + offset != op->arg1) {
                    offset += bytes_read;
                    SPIN_AGAIN();
                }

                if (op->arg1 > 0
                    && !TEST_mem_eq(tmp_buf, op->arg1, op->arg0, op->arg1))
                    goto out;

                OPENSSL_free(tmp_buf);
                tmp_buf = NULL;
            }
            break;

        case OPK_S_READ_EXPECT:
            {
                size_t bytes_read = 0;

                if (!TEST_uint64_t_ne(s_stream_id, UINT64_MAX))
                    goto out;

                if (op->arg1 > 0 && tmp_buf == NULL
                    && !TEST_ptr(tmp_buf = OPENSSL_malloc(op->arg1)))
                    goto out;

                if (!TEST_true(ossl_quic_tserver_read(h->s, s_stream_id,
                                                      tmp_buf + offset,
                                                      op->arg1 - offset,
                                                      &bytes_read)))
                    goto out;

                if (bytes_read + offset != op->arg1) {
                    offset += bytes_read;
                    SPIN_AGAIN();
                }

                if (op->arg1 > 0
                    && !TEST_mem_eq(tmp_buf, op->arg1, op->arg0, op->arg1))
                    goto out;

                OPENSSL_free(tmp_buf);
                tmp_buf = NULL;
            }
            break;

        case OPK_C_EXPECT_FIN:
            {
                char buf[1];
                size_t bytes_read = 0;

                if (!TEST_false(SSL_read_ex(c_tgt, buf, sizeof(buf),
                                            &bytes_read))
                    || !TEST_size_t_eq(bytes_read, 0))
                    goto out;

                if (is_want(c_tgt, 0))
                    SPIN_AGAIN();

                if (!TEST_int_eq(SSL_get_error(c_tgt, 0),
                                 SSL_ERROR_ZERO_RETURN))
                    goto out;
            }
            break;

        case OPK_S_EXPECT_FIN:
            {
                if (!TEST_uint64_t_ne(s_stream_id, UINT64_MAX))
                    goto out;

                if (!ossl_quic_tserver_has_read_ended(h->s, s_stream_id))
                    SPIN_AGAIN();
            }
            break;

        case OPK_C_DETACH:
            {
                SSL *c_stream;

                if (!TEST_ptr_null(c_tgt))
                    goto out; /* don't overwrite existing stream with same name */

                if (!TEST_ptr(c_stream = ossl_quic_detach_stream(h->c_conn)))
                    goto out;

                if (!TEST_true(helper_local_set_c_stream(&hl, op->stream_name, c_stream)))
                    goto out;
            }
            break;

        case OPK_C_ATTACH:
            {
                if (!TEST_ptr(c_tgt))
                    goto out;

                if (!TEST_true(ossl_quic_attach_stream(h->c_conn, c_tgt)))
                    goto out;

                if (!TEST_true(helper_local_set_c_stream(&hl, op->stream_name, NULL)))
                    goto out;
            }
            break;

        case OPK_C_NEW_STREAM:
            {
                SSL *c_stream;
                uint64_t flags = 0;

                if (!TEST_ptr_null(c_tgt))
                    goto out; /* don't overwrite existing stream with same name */

                if (op->arg1 != 0)
                    flags |= SSL_STREAM_FLAG_UNI;

                if (!TEST_ptr(c_stream = SSL_new_stream(h->c_conn, flags)))
                    goto out;

                if (op->arg2 != UINT64_MAX
                    && !TEST_uint64_t_eq(SSL_get_stream_id(c_stream),
                                         op->arg2))
                    goto out;

                if (!TEST_true(helper_local_set_c_stream(&hl, op->stream_name, c_stream)))
                    goto out;
            }
            break;

        case OPK_S_NEW_STREAM:
            {
                uint64_t stream_id = UINT64_MAX;

                if (!TEST_uint64_t_eq(s_stream_id, UINT64_MAX))
                    goto out; /* don't overwrite existing stream with same name */

                if (!TEST_true(ossl_quic_tserver_stream_new(h->s,
                                                            op->arg1 > 0,
                                                            &stream_id)))
                    goto out;

                if (op->arg2 != UINT64_MAX
                    && !TEST_uint64_t_eq(stream_id, op->arg2))
                    goto out;

                if (!TEST_true(helper_set_s_stream(h, op->stream_name,
                                                   stream_id)))
                    goto out;
            }
            break;

        case OPK_C_ACCEPT_STREAM_WAIT:
            {
                SSL *c_stream;

                if (!TEST_ptr_null(c_tgt))
                    goto out; /* don't overwrite existing stream with same name */

                if ((c_stream = SSL_accept_stream(h->c_conn, 0)) == NULL)
                    SPIN_AGAIN();

                if (!TEST_true(helper_local_set_c_stream(&hl, op->stream_name,
                                                          c_stream)))
                    goto out;
            }
            break;

        case OPK_S_ACCEPT_STREAM_WAIT:
            {
                uint64_t new_stream_id;

                if (!TEST_uint64_t_eq(s_stream_id, UINT64_MAX))
                    goto out;

                new_stream_id = ossl_quic_tserver_pop_incoming_stream(h->s);
                if (new_stream_id == UINT64_MAX)
                    SPIN_AGAIN();

                if (!TEST_true(helper_set_s_stream(h, op->stream_name, new_stream_id)))
                    goto out;
            }
            break;

        case OPK_C_ACCEPT_STREAM_NONE:
            {
                SSL *c_stream;

                if (!TEST_ptr_null(c_stream = SSL_accept_stream(h->c_conn, 0))) {
                    SSL_free(c_stream);
                    goto out;
                }
            }
            break;

        case OPK_C_FREE_STREAM:
            {
                if (!TEST_ptr(c_tgt)
                    || !TEST_true(!SSL_is_connection(c_tgt)))
                    goto out;

                if (!TEST_true(helper_local_set_c_stream(&hl, op->stream_name, NULL)))
                    goto out;

                SSL_free(c_tgt);
                c_tgt = NULL;
            }
            break;

        case OPK_C_SET_DEFAULT_STREAM_MODE:
            {
                if (!TEST_ptr(c_tgt))
                    goto out;

                if (!TEST_true(SSL_set_default_stream_mode(c_tgt, op->arg1)))
                    goto out;
            }
            break;

        case OPK_C_SET_INCOMING_STREAM_POLICY:
            {
                if (!TEST_ptr(c_tgt))
                    goto out;

                if (!TEST_true(SSL_set_incoming_stream_policy(c_tgt,
                                                              op->arg1, 0)))
                    goto out;
            }
            break;

        case OPK_C_SHUTDOWN:
            {
                int ret;

                if (!TEST_ptr(c_tgt))
                    goto out;

                ret = SSL_shutdown_ex(c_tgt, 0, NULL, 0);
                if (!TEST_int_ge(ret, 0))
                    goto out;

            }
            break;

        case OPK_C_EXPECT_CONN_CLOSE_INFO:
            {
                SSL_CONN_CLOSE_INFO cc_info = {0};
                int expect_app = (op->arg1 & EXPECT_CONN_CLOSE_APP) != 0;
                int expect_remote = (op->arg1 & EXPECT_CONN_CLOSE_REMOTE) != 0;
                uint64_t error_code = op->arg2;

                if (!TEST_ptr(c_tgt))
                    goto out;

                if (!SSL_get_conn_close_info(c_tgt, &cc_info, sizeof(cc_info)))
                    SPIN_AGAIN();

                if (!TEST_int_eq(expect_app, !cc_info.is_transport)
                    || !TEST_int_eq(expect_remote, !cc_info.is_local)
                    || !TEST_uint64_t_eq(error_code, cc_info.error_code))
                    goto out;
            }
            break;

        case OPK_S_EXPECT_CONN_CLOSE_INFO:
            {
                const QUIC_TERMINATE_CAUSE *tc;
                int expect_app = (op->arg1 & EXPECT_CONN_CLOSE_APP) != 0;
                int expect_remote = (op->arg1 & EXPECT_CONN_CLOSE_REMOTE) != 0;
                uint64_t error_code = op->arg2;

                if (!ossl_quic_tserver_is_term_any(h->s))
                    SPIN_AGAIN();

                if (!TEST_ptr(tc = ossl_quic_tserver_get_terminate_cause(h->s)))
                    goto out;

                if (!TEST_uint64_t_eq(error_code, tc->error_code)
                    || !TEST_int_eq(expect_app, tc->app)
                    || !TEST_int_eq(expect_remote, tc->remote))
                    goto out;
            }
            break;

        case OPK_S_BIND_STREAM_ID:
            {
                if (!TEST_uint64_t_eq(s_stream_id, UINT64_MAX))
                    goto out;

                if (!TEST_true(helper_set_s_stream(h, op->stream_name, op->arg2)))
                    goto out;
            }
            break;

        case OPK_S_UNBIND_STREAM_ID:
            {
                if (!TEST_uint64_t_ne(s_stream_id, UINT64_MAX))
                    goto out;

                if (!TEST_true(helper_set_s_stream(h, op->stream_name, UINT64_MAX)))
                    goto out;
            }
            break;

        case OPK_C_WRITE_FAIL:
            {
                size_t bytes_written = 0;

                if (!TEST_ptr(c_tgt))
                    goto out;

                if (!TEST_false(SSL_write_ex(c_tgt, "apple", 5, &bytes_written)))
                    goto out;
            }
            break;

        case OPK_S_WRITE_FAIL:
            {
                size_t bytes_written = 0;

                if (!TEST_uint64_t_ne(s_stream_id, UINT64_MAX))
                    goto out;

                if (!TEST_false(ossl_quic_tserver_write(h->s, s_stream_id,
                                                       (const unsigned char *)"apple", 5,
                                                       &bytes_written)))
                    goto out;
            }
            break;

        case OPK_C_READ_FAIL:
            {
                size_t bytes_read = 0;
                char buf[1];

                if (!TEST_ptr(c_tgt))
                    goto out;

                if (!TEST_false(SSL_read_ex(c_tgt, buf, sizeof(buf), &bytes_read)))
                    goto out;
            }
            break;

        case OPK_C_STREAM_RESET:
            {
                SSL_STREAM_RESET_ARGS args = {0};

                if (!TEST_ptr(c_tgt))
                    goto out;

                args.quic_error_code = op->arg2;

                if (!TEST_true(SSL_stream_reset(c_tgt, &args, sizeof(args))))
                    goto out;
            }
            break;

        case OPK_NEW_THREAD:
            {
#if !defined(OPENSSL_THREADS)
                /*
                 * If this test script requires threading and we do not have
                 * support for it, skip the rest of it.
                 */
                TEST_skip("threading not supported, skipping");
                testresult = 1;
                goto out;
#else
                size_t i;

                if (!TEST_ptr_null(h->threads)) {
                    TEST_error("max one NEW_THREAD operation per script");
                    goto out;
                }

                h->threads = OPENSSL_zalloc(op->arg1 * sizeof(struct child_thread_args));
                if (!TEST_ptr(h->threads))
                    goto out;

                h->num_threads = op->arg1;

                for (i = 0; i < op->arg1; ++i) {
                    h->threads[i].h            = h;
                    h->threads[i].script       = op->arg0;
                    h->threads[i].thread_idx   = i;

                    h->threads[i].m = ossl_crypto_mutex_new();
                    if (!TEST_ptr(h->threads[i].m))
                        goto out;

                    h->threads[i].t
                        = ossl_crypto_thread_native_start(run_script_child_thread,
                                                          &h->threads[i], 1);
                    if (!TEST_ptr(h->threads[i].t))
                        goto out;
                }
#endif
            }
            break;

        default:
            TEST_error("unknown op");
            goto out;
        }
    }

out:
    if (!testresult) {
        size_t i;

        TEST_error("failed at script op %zu, thread %d\n",
                   op_idx + 1, thread_idx);

        for (i = 0; i < repeat_stack_len; ++i)
            TEST_info("while repeating, iteration %zu of %zu, starting at script op %zu",
                      repeat_stack_done[i],
                      repeat_stack_limit[i],
                      repeat_stack_idx[i]);
    }

    OPENSSL_free(tmp_buf);
    helper_local_cleanup(&hl);
    return testresult;
}

static int run_script(const struct script_op *script, int free_order)
{
    int testresult = 0;
    struct helper h;

    if (!TEST_true(helper_init(&h, free_order)))
        goto out;

    if (!TEST_true(run_script_worker(&h, script, -1)))
        goto out;

#if defined(OPENSSL_THREADS)
    if (!TEST_true(join_threads(h.threads, h.num_threads)))
        goto out;
#endif

    testresult = 1;
out:
    helper_cleanup(&h);
    return testresult;
}

#if defined(OPENSSL_THREADS)
static CRYPTO_THREAD_RETVAL run_script_child_thread(void *arg)
{
    int testresult;
    struct child_thread_args *args = arg;

    testresult = run_script_worker(args->h, args->script,
                                   args->thread_idx);

    ossl_crypto_mutex_lock(args->m);
    args->testresult    = testresult;
    args->done          = 1;
    ossl_crypto_mutex_unlock(args->m);
    return 1;
}
#endif

/* 1. Simple single-stream test */
static const struct script_op script_1[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()
    OP_C_WRITE              (DEFAULT, "apple", 5)
    OP_C_CONCLUDE           (DEFAULT)
    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "apple", 5)
    OP_S_EXPECT_FIN         (a)
    OP_S_WRITE              (a, "orange", 6)
    OP_S_CONCLUDE           (a)
    OP_C_READ_EXPECT        (DEFAULT, "orange", 6)
    OP_C_EXPECT_FIN         (DEFAULT)
    OP_END
};

/* 2. Multi-stream test */
static const struct script_op script_2[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()
    OP_C_SET_INCOMING_STREAM_POLICY(SSL_INCOMING_STREAM_POLICY_ACCEPT)
    OP_C_WRITE              (DEFAULT,  "apple", 5)
    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "apple", 5)
    OP_S_WRITE              (a, "orange", 6)
    OP_C_READ_EXPECT        (DEFAULT, "orange", 6)

    OP_C_NEW_STREAM_BIDI    (b, C_BIDI_ID(1))
    OP_C_WRITE              (b, "flamingo", 8)
    OP_C_CONCLUDE           (b)
    OP_S_BIND_STREAM_ID     (b, C_BIDI_ID(1))
    OP_S_READ_EXPECT        (b, "flamingo", 8)
    OP_S_EXPECT_FIN         (b)
    OP_S_WRITE              (b, "gargoyle", 8)
    OP_S_CONCLUDE           (b)
    OP_C_READ_EXPECT        (b, "gargoyle", 8)
    OP_C_EXPECT_FIN         (b)

    OP_C_NEW_STREAM_UNI     (c, C_UNI_ID(0))
    OP_C_WRITE              (c, "elephant", 8)
    OP_C_CONCLUDE           (c)
    OP_S_BIND_STREAM_ID     (c, C_UNI_ID(0))
    OP_S_READ_EXPECT        (c, "elephant", 8)
    OP_S_EXPECT_FIN         (c)
    OP_S_WRITE_FAIL         (c)

    OP_C_ACCEPT_STREAM_NONE ()

    OP_S_NEW_STREAM_BIDI    (d, S_BIDI_ID(0))
    OP_S_WRITE              (d, "frog", 4)
    OP_S_CONCLUDE           (d)

    OP_C_ACCEPT_STREAM_WAIT (d)
    OP_C_ACCEPT_STREAM_NONE ()
    OP_C_READ_EXPECT        (d, "frog", 4)
    OP_C_EXPECT_FIN         (d)

    OP_S_NEW_STREAM_BIDI    (e, S_BIDI_ID(1))
    OP_S_WRITE              (e, "mixture", 7)
    OP_S_CONCLUDE           (e)

    OP_C_ACCEPT_STREAM_WAIT (e)
    OP_C_READ_EXPECT        (e, "mixture", 7)
    OP_C_EXPECT_FIN         (e)
    OP_C_WRITE              (e, "ramble", 6)
    OP_S_READ_EXPECT        (e, "ramble", 6)
    OP_C_CONCLUDE           (e)
    OP_S_EXPECT_FIN         (e)

    OP_S_NEW_STREAM_UNI     (f, S_UNI_ID(0))
    OP_S_WRITE              (f, "yonder", 6)
    OP_S_CONCLUDE           (f)

    OP_C_ACCEPT_STREAM_WAIT (f)
    OP_C_ACCEPT_STREAM_NONE ()
    OP_C_READ_EXPECT        (f, "yonder", 6)
    OP_C_EXPECT_FIN         (f)
    OP_C_WRITE_FAIL         (f)

    OP_C_SET_INCOMING_STREAM_POLICY(SSL_INCOMING_STREAM_POLICY_REJECT)
    OP_S_NEW_STREAM_BIDI    (g, S_BIDI_ID(2))
    OP_S_WRITE              (g, "unseen", 6)
    OP_S_CONCLUDE           (g)

    OP_C_ACCEPT_STREAM_NONE ()

    OP_C_SET_INCOMING_STREAM_POLICY(SSL_INCOMING_STREAM_POLICY_AUTO)
    OP_S_NEW_STREAM_BIDI    (h, S_BIDI_ID(3))
    OP_S_WRITE              (h, "UNSEEN", 6)
    OP_S_CONCLUDE           (h)

    OP_C_ACCEPT_STREAM_NONE ()

    /*
     * Streams g, h should have been rejected, so server should have got
     * STOP_SENDING/RESET_STREAM.
     */
    OP_CHECK                (check_rejected, S_BIDI_ID(2))
    OP_CHECK                (check_rejected, S_BIDI_ID(3))

    OP_END
};

/* 3. Default stream detach/reattach test */
static const struct script_op script_3[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_WRITE              (DEFAULT, "apple", 5)
    OP_C_DETACH             (a)             /* DEFAULT becomes stream 'a' */
    OP_C_WRITE_FAIL         (DEFAULT)

    OP_C_WRITE              (a, "by", 2)

    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "appleby", 7)

    OP_S_WRITE              (a, "hello", 5)
    OP_C_READ_EXPECT        (a, "hello", 5)

    OP_C_WRITE_FAIL         (DEFAULT)
    OP_C_ATTACH             (a)
    OP_C_WRITE              (DEFAULT, "is here", 7)
    OP_S_READ_EXPECT        (a, "is here", 7)

    OP_C_DETACH             (a)
    OP_C_CONCLUDE           (a)
    OP_S_EXPECT_FIN         (a)

    OP_END
};

/* 4. Default stream mode test */
static const struct script_op script_4[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)
    OP_C_WRITE_FAIL         (DEFAULT)

    OP_S_NEW_STREAM_BIDI    (a, S_BIDI_ID(0))
    OP_S_WRITE              (a, "apple", 5)

    OP_C_READ_FAIL          (DEFAULT)

    OP_C_ACCEPT_STREAM_WAIT (a)
    OP_C_READ_EXPECT        (a, "apple", 5)

    OP_C_ATTACH             (a)
    OP_C_WRITE              (DEFAULT, "orange", 6)
    OP_S_READ_EXPECT        (a, "orange", 6)

    OP_END
};

/* 5. Test stream reset functionality */
static const struct script_op script_5[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)
    OP_C_NEW_STREAM_BIDI    (a, C_BIDI_ID(0))

    OP_C_WRITE              (a, "apple", 5)
    OP_C_STREAM_RESET       (a, 42)

    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "apple", 5)
    OP_CHECK                (check_stream_reset, C_BIDI_ID(0))

    OP_END
};

/* 6. Test STOP_SENDING functionality */
static const struct script_op script_6[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)
    OP_S_NEW_STREAM_BIDI    (a, S_BIDI_ID(0))
    OP_S_WRITE              (a, "apple", 5)

    OP_C_ACCEPT_STREAM_WAIT (a)
    OP_C_FREE_STREAM        (a)
    OP_C_ACCEPT_STREAM_NONE ()

    OP_CHECK                (check_stream_stopped, S_BIDI_ID(0))

    OP_END
};

/* 7. Unidirectional default stream mode test (client sends first) */
static const struct script_op script_7[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_AUTO_UNI)
    OP_C_WRITE              (DEFAULT, "apple", 5)

    OP_S_BIND_STREAM_ID     (a, C_UNI_ID(0))
    OP_S_READ_EXPECT        (a, "apple", 5)
    OP_S_WRITE_FAIL         (a)

    OP_END
};

/* 8. Unidirectional default stream mode test (server sends first) */
static const struct script_op script_8[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_AUTO_UNI)
    OP_S_NEW_STREAM_UNI     (a, S_UNI_ID(0))
    OP_S_WRITE              (a, "apple", 5)
    OP_C_READ_EXPECT        (DEFAULT, "apple", 5)
    OP_C_WRITE_FAIL         (DEFAULT)

    OP_END
};

/* 9. Unidirectional default stream mode test (server sends first on bidi) */
static const struct script_op script_9[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_AUTO_UNI)
    OP_S_NEW_STREAM_BIDI    (a, S_BIDI_ID(0))
    OP_S_WRITE              (a, "apple", 5)
    OP_C_READ_EXPECT        (DEFAULT, "apple", 5)
    OP_C_WRITE              (DEFAULT, "orange", 6)
    OP_S_READ_EXPECT        (a, "orange", 6)

    OP_END
};

/* 10. Shutdown */
static const struct script_op script_10[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_WRITE              (DEFAULT, "apple", 5)
    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "apple", 5)

    OP_C_SHUTDOWN           ()
    OP_C_EXPECT_CONN_CLOSE_INFO(0, 1, 0)
    OP_S_EXPECT_CONN_CLOSE_INFO(0, 1, 1)

    OP_END
};

/* 11. Many threads accepted on the same client connection */
static const struct script_op script_11_child[] = {
    OP_C_ACCEPT_STREAM_WAIT (a)
    OP_C_READ_EXPECT        (a, "foo", 3)
    OP_C_EXPECT_FIN         (a)

    OP_END
};

static const struct script_op script_11[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()
    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)

    OP_NEW_THREAD           (5, script_11_child)

    OP_S_NEW_STREAM_BIDI    (a, ANY_ID)
    OP_S_WRITE              (a, "foo", 3)
    OP_S_CONCLUDE           (a)

    OP_S_NEW_STREAM_BIDI    (b, ANY_ID)
    OP_S_WRITE              (b, "foo", 3)
    OP_S_CONCLUDE           (b)

    OP_S_NEW_STREAM_BIDI    (c, ANY_ID)
    OP_S_WRITE              (c, "foo", 3)
    OP_S_CONCLUDE           (c)

    OP_S_NEW_STREAM_BIDI    (d, ANY_ID)
    OP_S_WRITE              (d, "foo", 3)
    OP_S_CONCLUDE           (d)

    OP_S_NEW_STREAM_BIDI    (e, ANY_ID)
    OP_S_WRITE              (e, "foo", 3)
    OP_S_CONCLUDE           (e)

    OP_END
};

/* 12. Many threads initiated on the same client connection */
static const struct script_op script_12_child[] = {
    OP_C_NEW_STREAM_BIDI    (a, ANY_ID)
    OP_C_WRITE              (a, "foo", 3)
    OP_C_CONCLUDE           (a)
    OP_C_FREE_STREAM        (a)

    OP_END
};

static const struct script_op script_12[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()
    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)

    OP_NEW_THREAD           (5, script_12_child)

    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "foo", 3)
    OP_S_EXPECT_FIN         (a)
    OP_S_BIND_STREAM_ID     (b, C_BIDI_ID(1))
    OP_S_READ_EXPECT        (b, "foo", 3)
    OP_S_EXPECT_FIN         (b)
    OP_S_BIND_STREAM_ID     (c, C_BIDI_ID(2))
    OP_S_READ_EXPECT        (c, "foo", 3)
    OP_S_EXPECT_FIN         (c)
    OP_S_BIND_STREAM_ID     (d, C_BIDI_ID(3))
    OP_S_READ_EXPECT        (d, "foo", 3)
    OP_S_EXPECT_FIN         (d)
    OP_S_BIND_STREAM_ID     (e, C_BIDI_ID(4))
    OP_S_READ_EXPECT        (e, "foo", 3)
    OP_S_EXPECT_FIN         (e)

    OP_END
};

/* 13. Many threads accepted on the same client connection (stress test) */
static const struct script_op script_13_child[] = {
    OP_BEGIN_REPEAT         (10)

    OP_C_ACCEPT_STREAM_WAIT (a)
    OP_C_READ_EXPECT        (a, "foo", 3)
    OP_C_EXPECT_FIN         (a)
    OP_C_FREE_STREAM        (a)

    OP_END_REPEAT           ()

    OP_END
};

static const struct script_op script_13[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()
    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)

    OP_NEW_THREAD           (5, script_13_child)

    OP_BEGIN_REPEAT         (50)

    OP_S_NEW_STREAM_BIDI    (a, ANY_ID)
    OP_S_WRITE              (a, "foo", 3)
    OP_S_CONCLUDE           (a)
    OP_S_UNBIND_STREAM_ID   (a)

    OP_END_REPEAT           ()

    OP_END
};

/* 14. Many threads initiating on the same client connection (stress test) */
static const struct script_op script_14_child[] = {
    OP_BEGIN_REPEAT         (10)

    OP_C_NEW_STREAM_BIDI    (a, ANY_ID)
    OP_C_WRITE              (a, "foo", 3)
    OP_C_CONCLUDE           (a)
    OP_C_FREE_STREAM        (a)

    OP_END_REPEAT           ()

    OP_END
};

static const struct script_op script_14[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()
    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)

    OP_NEW_THREAD           (5, script_14_child)

    OP_BEGIN_REPEAT         (50)

    OP_S_ACCEPT_STREAM_WAIT (a)
    OP_S_READ_EXPECT        (a, "foo", 3)
    OP_S_EXPECT_FIN         (a)
    OP_S_UNBIND_STREAM_ID   (a)

    OP_END_REPEAT           ()

    OP_END
};

/* 15. Client sending large number of streams, MAX_STREAMS test */
static const struct script_op script_15[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()
    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)

    /*
     * This will cause a protocol violation to be raised by the server if we are
     * not handling the stream limit correctly on the TX side.
     */
    OP_BEGIN_REPEAT         (200)

    OP_C_NEW_STREAM_BIDI    (a, ANY_ID)
    OP_C_WRITE              (a, "foo", 3)
    OP_C_CONCLUDE           (a)
    OP_C_FREE_STREAM        (a)

    OP_END_REPEAT           ()

    /* Prove the connection is still good. */
    OP_S_NEW_STREAM_BIDI    (a, S_BIDI_ID(0))
    OP_S_WRITE              (a, "bar", 3)
    OP_S_CONCLUDE           (a)

    OP_C_ACCEPT_STREAM_WAIT (a)
    OP_C_READ_EXPECT        (a, "bar", 3)
    OP_C_EXPECT_FIN         (a)

    /*
     * Drain the queue of incoming streams. We should be able to get all 200
     * even though only 100 can be initiated at a time.
     */
    OP_BEGIN_REPEAT         (200)

    OP_S_ACCEPT_STREAM_WAIT (b)
    OP_S_READ_EXPECT        (b, "foo", 3)
    OP_S_EXPECT_FIN         (b)
    OP_S_UNBIND_STREAM_ID   (b)

    OP_END_REPEAT           ()

    OP_END
};

/* 16. Server sending large number of streams, MAX_STREAMS test */
static const struct script_op script_16[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()
    OP_C_SET_DEFAULT_STREAM_MODE(SSL_DEFAULT_STREAM_MODE_NONE)

    /*
     * This will cause a protocol violation to be raised by the client if we are
     * not handling the stream limit correctly on the TX side.
     */
    OP_BEGIN_REPEAT         (200)

    OP_S_NEW_STREAM_BIDI    (a, ANY_ID)
    OP_S_WRITE              (a, "foo", 3)
    OP_S_CONCLUDE           (a)
    OP_S_UNBIND_STREAM_ID   (a)

    OP_END_REPEAT           ()

    /* Prove that the connection is still good. */
    OP_C_NEW_STREAM_BIDI    (a, ANY_ID)
    OP_C_WRITE              (a, "bar", 3)
    OP_C_CONCLUDE           (a)

    OP_S_ACCEPT_STREAM_WAIT (b)
    OP_S_READ_EXPECT        (b, "bar", 3)
    OP_S_EXPECT_FIN         (b)

    /* Drain the queue of incoming streams. */
    OP_BEGIN_REPEAT         (200)

    OP_C_ACCEPT_STREAM_WAIT (b)
    OP_C_READ_EXPECT        (b, "foo", 3)
    OP_C_EXPECT_FIN         (b)
    OP_C_FREE_STREAM        (b)

    OP_END_REPEAT           ()

    OP_END
};

/* 17. Key update test - unlimited */
static const struct script_op script_17[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_WRITE              (DEFAULT, "apple", 5)

    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "apple", 5)

    OP_CHECK                (override_key_update, 1)

    OP_BEGIN_REPEAT         (200)

    OP_C_WRITE              (DEFAULT, "apple", 5)
    OP_S_READ_EXPECT        (a, "apple", 5)

    /*
     * TXKU frequency is bounded by RTT because a previous TXKU needs to be
     * acknowledged by the peer first before another one can be begin. By
     * waiting this long, we eliminate any such concern and ensure as many key
     * updates as possible can occur for the purposes of this test.
     */
    OP_CHECK                (skip_time_ms,    100)

    OP_END_REPEAT           ()

    /* At least 5 RXKUs detected */
    OP_CHECK                (check_key_update_ge, 5)

    /*
     * Prove the connection is still healthy by sending something in both
     * directions.
     */
    OP_C_WRITE              (DEFAULT, "xyzzy", 5)
    OP_S_READ_EXPECT        (a, "xyzzy", 5)

    OP_S_WRITE              (a, "plugh", 5)
    OP_C_READ_EXPECT        (DEFAULT, "plugh", 5)

    OP_END
};

/* 18. Key update test - RTT-bounded */
static const struct script_op script_18[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_WRITE              (DEFAULT, "apple", 5)

    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "apple", 5)

    OP_CHECK                (override_key_update, 1)

    OP_BEGIN_REPEAT         (200)

    OP_C_WRITE              (DEFAULT, "apple", 5)
    OP_S_READ_EXPECT        (a, "apple", 5)
    OP_CHECK                (skip_time_ms,    2)

    OP_END_REPEAT           ()

    /*
     * This time we simulate far less time passing between writes, so there are
     * fewer opportunities to initiate TXKUs. Note that we ask for a TXKU every
     * 1 packet above, which is absurd; thus this ensures we only actually
     * generate TXKUs when we are allowed to.
     */
    OP_CHECK                (check_key_update_ge, 4)
    OP_CHECK                (check_key_update_lt, 120)

    /*
     * Prove the connection is still healthy by sending something in both
     * directions.
     */
    OP_C_WRITE              (DEFAULT, "xyzzy", 5)
    OP_S_READ_EXPECT        (a, "xyzzy", 5)

    OP_S_WRITE              (a, "plugh", 5)
    OP_C_READ_EXPECT        (DEFAULT, "plugh", 5)

    OP_END
};

/* 19. Key update test - artificially triggered */
static const struct script_op script_19[] = {
    OP_C_SET_ALPN           ("ossltest")
    OP_C_CONNECT_WAIT       ()

    OP_C_WRITE              (DEFAULT, "apple", 5)

    OP_S_BIND_STREAM_ID     (a, C_BIDI_ID(0))
    OP_S_READ_EXPECT        (a, "apple", 5)

    OP_CHECK                (check_key_update_lt, 1)
    OP_CHECK                (trigger_key_update, 0)

    OP_C_WRITE              (DEFAULT, "orange", 6)
    OP_S_READ_EXPECT        (a, "orange", 6)

    OP_CHECK                (check_key_update_ge, 1)

    OP_END
};

static const struct script_op *const scripts[] = {
    script_1,
    script_2,
    script_3,
    script_4,
    script_5,
    script_6,
    script_7,
    script_8,
    script_9,
    script_10,
    script_11,
    script_12,
    script_13,
    script_14,
    script_15,
    script_16,
    script_17,
    script_18,
    script_19,
};

static int test_script(int idx)
{
    int script_idx = idx >> 1;
    int free_order = idx & 1;

    TEST_info("Running script %d (order=%d)", script_idx + 1, free_order);
    return run_script(scripts[script_idx], free_order);
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certfile = test_get_argument(0))
        || !TEST_ptr(keyfile = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_script, OSSL_NELEM(scripts) * 2);
    return 1;
}
