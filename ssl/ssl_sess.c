/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <opentls/rand.h>
#include <opentls/engine.h>
#include "internal/refcount.h"
#include "internal/cryptlib.h"
#include "tls_local.h"
#include "statem/statem_local.h"

static void tls_SESSION_list_remove(tls_CTX *ctx, tls_SESSION *s);
static void tls_SESSION_list_add(tls_CTX *ctx, tls_SESSION *s);
static int remove_session_lock(tls_CTX *ctx, tls_SESSION *c, int lck);

/*
 * tls_get_session() and tls_get1_session() are problematic in TLS1.3 because,
 * unlike in earlier protocol versions, the session ticket may not have been
 * sent yet even though a handshake has finished. The session ticket data could
 * come in sometime later...or even change if multiple session ticket messages
 * are sent from the server. The preferred way for applications to obtain
 * a resumable session is to use tls_CTX_sess_set_new_cb().
 */

tls_SESSION *tls_get_session(const tls *tls)
/* aka tls_get0_session; gets 0 objects, just returns a copy of the pointer */
{
    return tls->session;
}

tls_SESSION *tls_get1_session(tls *tls)
/* variant of tls_get_session: caller really gets something */
{
    tls_SESSION *sess;
    /*
     * Need to lock this all up rather than just use CRYPTO_add so that
     * somebody doesn't free tls->session between when we check it's non-null
     * and when we up the reference count.
     */
    CRYPTO_THREAD_read_lock(tls->lock);
    sess = tls->session;
    if (sess)
        tls_SESSION_up_ref(sess);
    CRYPTO_THREAD_unlock(tls->lock);
    return sess;
}

int tls_SESSION_set_ex_data(tls_SESSION *s, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&s->ex_data, idx, arg);
}

void *tls_SESSION_get_ex_data(const tls_SESSION *s, int idx)
{
    return CRYPTO_get_ex_data(&s->ex_data, idx);
}

tls_SESSION *tls_SESSION_new(void)
{
    tls_SESSION *ss;

    if (!OPENtls_init_tls(OPENtls_INIT_LOAD_tls_STRINGS, NULL))
        return NULL;

    ss = OPENtls_zalloc(sizeof(*ss));
    if (ss == NULL) {
        tlserr(tls_F_tls_SESSION_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ss->verify_result = 1;      /* avoid 0 (= X509_V_OK) just in case */
    ss->references = 1;
    ss->timeout = 60 * 5 + 4;   /* 5 minute timeout by default */
    ss->time = (unsigned long)time(NULL);
    ss->lock = CRYPTO_THREAD_lock_new();
    if (ss->lock == NULL) {
        tlserr(tls_F_tls_SESSION_NEW, ERR_R_MALLOC_FAILURE);
        OPENtls_free(ss);
        return NULL;
    }

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_tls_SESSION, ss, &ss->ex_data)) {
        CRYPTO_THREAD_lock_free(ss->lock);
        OPENtls_free(ss);
        return NULL;
    }
    return ss;
}

tls_SESSION *tls_SESSION_dup(const tls_SESSION *src)
{
    return tls_session_dup(src, 1);
}

/*
 * Create a new tls_SESSION and duplicate the contents of |src| into it. If
 * ticket == 0 then no ticket information is duplicated, otherwise it is.
 */
tls_SESSION *tls_session_dup(const tls_SESSION *src, int ticket)
{
    tls_SESSION *dest;

    dest = OPENtls_malloc(sizeof(*src));
    if (dest == NULL) {
        goto err;
    }
    memcpy(dest, src, sizeof(*dest));

    /*
     * Set the various pointers to NULL so that we can call tls_SESSION_free in
     * the case of an error whilst halfway through constructing dest
     */
#ifndef OPENtls_NO_PSK
    dest->psk_identity_hint = NULL;
    dest->psk_identity = NULL;
#endif
    dest->ext.hostname = NULL;
    dest->ext.tick = NULL;
    dest->ext.alpn_selected = NULL;
#ifndef OPENtls_NO_SRP
    dest->srp_username = NULL;
#endif
    dest->peer_chain = NULL;
    dest->peer = NULL;
    dest->ticket_appdata = NULL;
    memset(&dest->ex_data, 0, sizeof(dest->ex_data));

    /* We deliberately don't copy the prev and next pointers */
    dest->prev = NULL;
    dest->next = NULL;

    dest->references = 1;

    dest->lock = CRYPTO_THREAD_lock_new();
    if (dest->lock == NULL)
        goto err;

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_tls_SESSION, dest, &dest->ex_data))
        goto err;

    if (src->peer != NULL) {
        if (!X509_up_ref(src->peer))
            goto err;
        dest->peer = src->peer;
    }

    if (src->peer_chain != NULL) {
        dest->peer_chain = X509_chain_up_ref(src->peer_chain);
        if (dest->peer_chain == NULL)
            goto err;
    }
#ifndef OPENtls_NO_PSK
    if (src->psk_identity_hint) {
        dest->psk_identity_hint = OPENtls_strdup(src->psk_identity_hint);
        if (dest->psk_identity_hint == NULL) {
            goto err;
        }
    }
    if (src->psk_identity) {
        dest->psk_identity = OPENtls_strdup(src->psk_identity);
        if (dest->psk_identity == NULL) {
            goto err;
        }
    }
#endif

    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_tls_SESSION,
                            &dest->ex_data, &src->ex_data)) {
        goto err;
    }

    if (src->ext.hostname) {
        dest->ext.hostname = OPENtls_strdup(src->ext.hostname);
        if (dest->ext.hostname == NULL) {
            goto err;
        }
    }

    if (ticket != 0 && src->ext.tick != NULL) {
        dest->ext.tick =
            OPENtls_memdup(src->ext.tick, src->ext.ticklen);
        if (dest->ext.tick == NULL)
            goto err;
    } else {
        dest->ext.tick_lifetime_hint = 0;
        dest->ext.ticklen = 0;
    }

    if (src->ext.alpn_selected != NULL) {
        dest->ext.alpn_selected = OPENtls_memdup(src->ext.alpn_selected,
                                                 src->ext.alpn_selected_len);
        if (dest->ext.alpn_selected == NULL)
            goto err;
    }

#ifndef OPENtls_NO_SRP
    if (src->srp_username) {
        dest->srp_username = OPENtls_strdup(src->srp_username);
        if (dest->srp_username == NULL) {
            goto err;
        }
    }
#endif

    if (src->ticket_appdata != NULL) {
        dest->ticket_appdata =
            OPENtls_memdup(src->ticket_appdata, src->ticket_appdata_len);
        if (dest->ticket_appdata == NULL)
            goto err;
    }

    return dest;
 err:
    tlserr(tls_F_tls_SESSION_DUP, ERR_R_MALLOC_FAILURE);
    tls_SESSION_free(dest);
    return NULL;
}

const unsigned char *tls_SESSION_get_id(const tls_SESSION *s, unsigned int *len)
{
    if (len)
        *len = (unsigned int)s->session_id_length;
    return s->session_id;
}
const unsigned char *tls_SESSION_get0_id_context(const tls_SESSION *s,
                                                unsigned int *len)
{
    if (len != NULL)
        *len = (unsigned int)s->sid_ctx_length;
    return s->sid_ctx;
}

unsigned int tls_SESSION_get_compress_id(const tls_SESSION *s)
{
    return s->compress_meth;
}

/*
 * tlsv3/TLSv1 has 32 bytes (256 bits) of session ID space. As such, filling
 * the ID with random junk repeatedly until we have no conflict is going to
 * complete in one iteration pretty much "most" of the time (btw:
 * understatement). So, if it takes us 10 iterations and we still can't avoid
 * a conflict - well that's a reasonable point to call it quits. Either the
 * RAND code is broken or someone is trying to open roughly very close to
 * 2^256 tls sessions to our server. How you might store that many sessions
 * is perhaps a more interesting question ...
 */

#define MAX_SESS_ID_ATTEMPTS 10
static int def_generate_session_id(tls *tls, unsigned char *id,
                                   unsigned int *id_len)
{
    unsigned int retry = 0;
    do
        if (RAND_bytes(id, *id_len) <= 0)
            return 0;
    while (tls_has_matching_session_id(tls, id, *id_len) &&
           (++retry < MAX_SESS_ID_ATTEMPTS)) ;
    if (retry < MAX_SESS_ID_ATTEMPTS)
        return 1;
    /* else - woops a session_id match */
    /*
     * XXX We should also check the external cache -- but the probability of
     * a collision is negligible, and we could not prevent the concurrent
     * creation of sessions with identical IDs since we currently don't have
     * means to atomically check whether a session ID already exists and make
     * a reservation for it if it does not (this problem applies to the
     * internal cache as well).
     */
    return 0;
}

int tls_generate_session_id(tls *s, tls_SESSION *ss)
{
    unsigned int tmp;
    GEN_SESSION_CB cb = def_generate_session_id;

    switch (s->version) {
    case tls3_VERSION:
    case TLS1_VERSION:
    case TLS1_1_VERSION:
    case TLS1_2_VERSION:
    case TLS1_3_VERSION:
    case DTLS1_BAD_VER:
    case DTLS1_VERSION:
    case DTLS1_2_VERSION:
        ss->session_id_length = tls3_tls_SESSION_ID_LENGTH;
        break;
    default:
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_SESSION_ID,
                 tls_R_UNSUPPORTED_tls_VERSION);
        return 0;
    }

    /*-
     * If RFC5077 ticket, use empty session ID (as server).
     * Note that:
     * (a) tls_get_prev_session() does lookahead into the
     *     ClientHello extensions to find the session ticket.
     *     When tls_get_prev_session() fails, statem_srvr.c calls
     *     tls_get_new_session() in tls_process_client_hello().
     *     At that point, it has not yet parsed the extensions,
     *     however, because of the lookahead, it already knows
     *     whether a ticket is expected or not.
     *
     * (b) statem_clnt.c calls tls_get_new_session() before parsing
     *     ServerHello extensions, and before recording the session
     *     ID received from the server, so this block is a noop.
     */
    if (s->ext.ticket_expected) {
        ss->session_id_length = 0;
        return 1;
    }

    /* Choose which callback will set the session ID */
    CRYPTO_THREAD_read_lock(s->lock);
    CRYPTO_THREAD_read_lock(s->session_ctx->lock);
    if (s->generate_session_id)
        cb = s->generate_session_id;
    else if (s->session_ctx->generate_session_id)
        cb = s->session_ctx->generate_session_id;
    CRYPTO_THREAD_unlock(s->session_ctx->lock);
    CRYPTO_THREAD_unlock(s->lock);
    /* Choose a session ID */
    memset(ss->session_id, 0, ss->session_id_length);
    tmp = (int)ss->session_id_length;
    if (!cb(s, ss->session_id, &tmp)) {
        /* The callback failed */
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_SESSION_ID,
                 tls_R_tls_SESSION_ID_CALLBACK_FAILED);
        return 0;
    }
    /*
     * Don't allow the callback to set the session length to zero. nor
     * set it higher than it was.
     */
    if (tmp == 0 || tmp > ss->session_id_length) {
        /* The callback set an illegal length */
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_SESSION_ID,
                 tls_R_tls_SESSION_ID_HAS_BAD_LENGTH);
        return 0;
    }
    ss->session_id_length = tmp;
    /* Finally, check for a conflict */
    if (tls_has_matching_session_id(s, ss->session_id,
                                    (unsigned int)ss->session_id_length)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_SESSION_ID,
                 tls_R_tls_SESSION_ID_CONFLICT);
        return 0;
    }

    return 1;
}

int tls_get_new_session(tls *s, int session)
{
    /* This gets used by clients and servers. */

    tls_SESSION *ss = NULL;

    if ((ss = tls_SESSION_new()) == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GET_NEW_SESSION,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* If the context has a default timeout, use it */
    if (s->session_ctx->session_timeout == 0)
        ss->timeout = tls_get_default_timeout(s);
    else
        ss->timeout = s->session_ctx->session_timeout;

    tls_SESSION_free(s->session);
    s->session = NULL;

    if (session) {
        if (tls_IS_TLS13(s)) {
            /*
             * We generate the session id while constructing the
             * NewSessionTicket in TLSv1.3.
             */
            ss->session_id_length = 0;
        } else if (!tls_generate_session_id(s, ss)) {
            /* tlsfatal() already called */
            tls_SESSION_free(ss);
            return 0;
        }

    } else {
        ss->session_id_length = 0;
    }

    if (s->sid_ctx_length > sizeof(ss->sid_ctx)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GET_NEW_SESSION,
                 ERR_R_INTERNAL_ERROR);
        tls_SESSION_free(ss);
        return 0;
    }
    memcpy(ss->sid_ctx, s->sid_ctx, s->sid_ctx_length);
    ss->sid_ctx_length = s->sid_ctx_length;
    s->session = ss;
    ss->tls_version = s->version;
    ss->verify_result = X509_V_OK;

    /* If client supports extended master secret set it in session */
    if (s->s3.flags & TLS1_FLAGS_RECEIVED_EXTMS)
        ss->flags |= tls_SESS_FLAG_EXTMS;

    return 1;
}

tls_SESSION *lookup_sess_in_cache(tls *s, const unsigned char *sess_id,
                                  size_t sess_id_len)
{
    tls_SESSION *ret = NULL;

    if ((s->session_ctx->session_cache_mode
         & tls_SESS_CACHE_NO_INTERNAL_LOOKUP) == 0) {
        tls_SESSION data;

        data.tls_version = s->version;
        if (!otls_assert(sess_id_len <= tls_MAX_tls_SESSION_ID_LENGTH))
            return NULL;

        memcpy(data.session_id, sess_id, sess_id_len);
        data.session_id_length = sess_id_len;

        CRYPTO_THREAD_read_lock(s->session_ctx->lock);
        ret = lh_tls_SESSION_retrieve(s->session_ctx->sessions, &data);
        if (ret != NULL) {
            /* don't allow other threads to steal it: */
            tls_SESSION_up_ref(ret);
        }
        CRYPTO_THREAD_unlock(s->session_ctx->lock);
        if (ret == NULL)
            tsan_counter(&s->session_ctx->stats.sess_miss);
    }

    if (ret == NULL && s->session_ctx->get_session_cb != NULL) {
        int copy = 1;

        ret = s->session_ctx->get_session_cb(s, sess_id, sess_id_len, &copy);

        if (ret != NULL) {
            tsan_counter(&s->session_ctx->stats.sess_cb_hit);

            /*
             * Increment reference count now if the session callback asks us
             * to do so (note that if the session structures returned by the
             * callback are shared between threads, it must handle the
             * reference count itself [i.e. copy == 0], or things won't be
             * thread-safe).
             */
            if (copy)
                tls_SESSION_up_ref(ret);

            /*
             * Add the externally cached session to the internal cache as
             * well if and only if we are supposed to.
             */
            if ((s->session_ctx->session_cache_mode &
                 tls_SESS_CACHE_NO_INTERNAL_STORE) == 0) {
                /*
                 * Either return value of tls_CTX_add_session should not
                 * interrupt the session resumption process. The return
                 * value is intentionally ignored.
                 */
                (void)tls_CTX_add_session(s->session_ctx, ret);
            }
        }
    }

    return ret;
}

/*-
 * tls_get_prev attempts to find an tls_SESSION to be used to resume this
 * connection. It is only called by servers.
 *
 *   hello: The parsed ClientHello data
 *
 * Returns:
 *   -1: fatal error
 *    0: no session found
 *    1: a session may have been found.
 *
 * Side effects:
 *   - If a session is found then s->session is pointed at it (after freeing an
 *     existing session if need be) and s->verify_result is set from the session.
 *   - Both for new and resumed sessions, s->ext.ticket_expected is set to 1
 *     if the server should issue a new session ticket (to 0 otherwise).
 */
int tls_get_prev_session(tls *s, CLIENTHELLO_MSG *hello)
{
    /* This is used only by servers. */

    tls_SESSION *ret = NULL;
    int fatal = 0;
    int try_session_cache = 0;
    tls_TICKET_STATUS r;

    if (tls_IS_TLS13(s)) {
        /*
         * By default we will send a new ticket. This can be overridden in the
         * ticket processing.
         */
        s->ext.ticket_expected = 1;
        if (!tls_parse_extension(s, TLSEXT_IDX_psk_kex_modes,
                                 tls_EXT_CLIENT_HELLO, hello->pre_proc_exts,
                                 NULL, 0)
                || !tls_parse_extension(s, TLSEXT_IDX_psk, tls_EXT_CLIENT_HELLO,
                                        hello->pre_proc_exts, NULL, 0))
            return -1;

        ret = s->session;
    } else {
        /* sets s->ext.ticket_expected */
        r = tls_get_ticket_from_client(s, hello, &ret);
        switch (r) {
        case tls_TICKET_FATAL_ERR_MALLOC:
        case tls_TICKET_FATAL_ERR_OTHER:
            fatal = 1;
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GET_PREV_SESSION,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        case tls_TICKET_NONE:
        case tls_TICKET_EMPTY:
            if (hello->session_id_len > 0) {
                try_session_cache = 1;
                ret = lookup_sess_in_cache(s, hello->session_id,
                                           hello->session_id_len);
            }
            break;
        case tls_TICKET_NO_DECRYPT:
        case tls_TICKET_SUCCESS:
        case tls_TICKET_SUCCESS_RENEW:
            break;
        }
    }

    if (ret == NULL)
        goto err;

    /* Now ret is non-NULL and we own one of its reference counts. */

    /* Check TLS version consistency */
    if (ret->tls_version != s->version)
        goto err;

    if (ret->sid_ctx_length != s->sid_ctx_length
        || memcmp(ret->sid_ctx, s->sid_ctx, ret->sid_ctx_length)) {
        /*
         * We have the session requested by the client, but we don't want to
         * use it in this context.
         */
        goto err;               /* treat like cache miss */
    }

    if ((s->verify_mode & tls_VERIFY_PEER) && s->sid_ctx_length == 0) {
        /*
         * We can't be sure if this session is being used out of context,
         * which is especially important for tls_VERIFY_PEER. The application
         * should have used tls[_CTX]_set_session_id_context. For this error
         * case, we generate an error instead of treating the event like a
         * cache miss (otherwise it would be easy for applications to
         * effectively disable the session cache by accident without anyone
         * noticing).
         */

        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GET_PREV_SESSION,
                 tls_R_SESSION_ID_CONTEXT_UNINITIALIZED);
        fatal = 1;
        goto err;
    }

    if (ret->timeout < (long)(time(NULL) - ret->time)) { /* timeout */
        tsan_counter(&s->session_ctx->stats.sess_timeout);
        if (try_session_cache) {
            /* session was from the cache, so remove it */
            tls_CTX_remove_session(s->session_ctx, ret);
        }
        goto err;
    }

    /* Check extended master secret extension consistency */
    if (ret->flags & tls_SESS_FLAG_EXTMS) {
        /* If old session includes extms, but new does not: abort handshake */
        if (!(s->s3.flags & TLS1_FLAGS_RECEIVED_EXTMS)) {
            tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_tls_GET_PREV_SESSION,
                     tls_R_INCONSISTENT_EXTMS);
            fatal = 1;
            goto err;
        }
    } else if (s->s3.flags & TLS1_FLAGS_RECEIVED_EXTMS) {
        /* If new session includes extms, but old does not: do not resume */
        goto err;
    }

    if (!tls_IS_TLS13(s)) {
        /* We already did this for TLS1.3 */
        tls_SESSION_free(s->session);
        s->session = ret;
    }

    tsan_counter(&s->session_ctx->stats.sess_hit);
    s->verify_result = s->session->verify_result;
    return 1;

 err:
    if (ret != NULL) {
        tls_SESSION_free(ret);
        /* In TLSv1.3 s->session was already set to ret, so we NULL it out */
        if (tls_IS_TLS13(s))
            s->session = NULL;

        if (!try_session_cache) {
            /*
             * The session was from a ticket, so we should issue a ticket for
             * the new session
             */
            s->ext.ticket_expected = 1;
        }
    }
    if (fatal)
        return -1;

    return 0;
}

int tls_CTX_add_session(tls_CTX *ctx, tls_SESSION *c)
{
    int ret = 0;
    tls_SESSION *s;

    /*
     * add just 1 reference count for the tls_CTX's session cache even though
     * it has two ways of access: each session is in a doubly linked list and
     * an lhash
     */
    tls_SESSION_up_ref(c);
    /*
     * if session c is in already in cache, we take back the increment later
     */

    CRYPTO_THREAD_write_lock(ctx->lock);
    s = lh_tls_SESSION_insert(ctx->sessions, c);

    /*
     * s != NULL iff we already had a session with the given PID. In this
     * case, s == c should hold (then we did not really modify
     * ctx->sessions), or we're in trouble.
     */
    if (s != NULL && s != c) {
        /* We *are* in trouble ... */
        tls_SESSION_list_remove(ctx, s);
        tls_SESSION_free(s);
        /*
         * ... so pretend the other session did not exist in cache (we cannot
         * handle two tls_SESSION structures with identical session ID in the
         * same cache, which could happen e.g. when two threads concurrently
         * obtain the same session from an external cache)
         */
        s = NULL;
    } else if (s == NULL &&
               lh_tls_SESSION_retrieve(ctx->sessions, c) == NULL) {
        /* s == NULL can also mean OOM error in lh_tls_SESSION_insert ... */

        /*
         * ... so take back the extra reference and also don't add
         * the session to the tls_SESSION_list at this time
         */
        s = c;
    }

    /* Put at the head of the queue unless it is already in the cache */
    if (s == NULL)
        tls_SESSION_list_add(ctx, c);

    if (s != NULL) {
        /*
         * existing cache entry -- decrement previously incremented reference
         * count because it already takes into account the cache
         */

        tls_SESSION_free(s);    /* s == c */
        ret = 0;
    } else {
        /*
         * new cache entry -- remove old ones if cache has become too large
         */

        ret = 1;

        if (tls_CTX_sess_get_cache_size(ctx) > 0) {
            while (tls_CTX_sess_number(ctx) > tls_CTX_sess_get_cache_size(ctx)) {
                if (!remove_session_lock(ctx, ctx->session_cache_tail, 0))
                    break;
                else
                    tsan_counter(&ctx->stats.sess_cache_full);
            }
        }
    }
    CRYPTO_THREAD_unlock(ctx->lock);
    return ret;
}

int tls_CTX_remove_session(tls_CTX *ctx, tls_SESSION *c)
{
    return remove_session_lock(ctx, c, 1);
}

static int remove_session_lock(tls_CTX *ctx, tls_SESSION *c, int lck)
{
    tls_SESSION *r;
    int ret = 0;

    if ((c != NULL) && (c->session_id_length != 0)) {
        if (lck)
            CRYPTO_THREAD_write_lock(ctx->lock);
        if ((r = lh_tls_SESSION_retrieve(ctx->sessions, c)) != NULL) {
            ret = 1;
            r = lh_tls_SESSION_delete(ctx->sessions, r);
            tls_SESSION_list_remove(ctx, r);
        }
        c->not_resumable = 1;

        if (lck)
            CRYPTO_THREAD_unlock(ctx->lock);

        if (ctx->remove_session_cb != NULL)
            ctx->remove_session_cb(ctx, c);

        if (ret)
            tls_SESSION_free(r);
    } else
        ret = 0;
    return ret;
}

void tls_SESSION_free(tls_SESSION *ss)
{
    int i;

    if (ss == NULL)
        return;
    CRYPTO_DOWN_REF(&ss->references, &i, ss->lock);
    REF_PRINT_COUNT("tls_SESSION", ss);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_tls_SESSION, ss, &ss->ex_data);

    OPENtls_cleanse(ss->master_key, sizeof(ss->master_key));
    OPENtls_cleanse(ss->session_id, sizeof(ss->session_id));
    X509_free(ss->peer);
    sk_X509_pop_free(ss->peer_chain, X509_free);
    OPENtls_free(ss->ext.hostname);
    OPENtls_free(ss->ext.tick);
#ifndef OPENtls_NO_PSK
    OPENtls_free(ss->psk_identity_hint);
    OPENtls_free(ss->psk_identity);
#endif
#ifndef OPENtls_NO_SRP
    OPENtls_free(ss->srp_username);
#endif
    OPENtls_free(ss->ext.alpn_selected);
    OPENtls_free(ss->ticket_appdata);
    CRYPTO_THREAD_lock_free(ss->lock);
    OPENtls_clear_free(ss, sizeof(*ss));
}

int tls_SESSION_up_ref(tls_SESSION *ss)
{
    int i;

    if (CRYPTO_UP_REF(&ss->references, &i, ss->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("tls_SESSION", ss);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

int tls_set_session(tls *s, tls_SESSION *session)
{
    tls_clear_bad_session(s);
    if (s->ctx->method != s->method) {
        if (!tls_set_tls_method(s, s->ctx->method))
            return 0;
    }

    if (session != NULL) {
        tls_SESSION_up_ref(session);
        s->verify_result = session->verify_result;
    }
    tls_SESSION_free(s->session);
    s->session = session;

    return 1;
}

int tls_SESSION_set1_id(tls_SESSION *s, const unsigned char *sid,
                        unsigned int sid_len)
{
    if (sid_len > tls_MAX_tls_SESSION_ID_LENGTH) {
      tlserr(tls_F_tls_SESSION_SET1_ID,
             tls_R_tls_SESSION_ID_TOO_LONG);
      return 0;
    }
    s->session_id_length = sid_len;
    if (sid != s->session_id)
        memcpy(s->session_id, sid, sid_len);
    return 1;
}

long tls_SESSION_set_timeout(tls_SESSION *s, long t)
{
    if (s == NULL)
        return 0;
    s->timeout = t;
    return 1;
}

long tls_SESSION_get_timeout(const tls_SESSION *s)
{
    if (s == NULL)
        return 0;
    return s->timeout;
}

long tls_SESSION_get_time(const tls_SESSION *s)
{
    if (s == NULL)
        return 0;
    return s->time;
}

long tls_SESSION_set_time(tls_SESSION *s, long t)
{
    if (s == NULL)
        return 0;
    s->time = t;
    return t;
}

int tls_SESSION_get_protocol_version(const tls_SESSION *s)
{
    return s->tls_version;
}

int tls_SESSION_set_protocol_version(tls_SESSION *s, int version)
{
    s->tls_version = version;
    return 1;
}

const tls_CIPHER *tls_SESSION_get0_cipher(const tls_SESSION *s)
{
    return s->cipher;
}

int tls_SESSION_set_cipher(tls_SESSION *s, const tls_CIPHER *cipher)
{
    s->cipher = cipher;
    return 1;
}

const char *tls_SESSION_get0_hostname(const tls_SESSION *s)
{
    return s->ext.hostname;
}

int tls_SESSION_set1_hostname(tls_SESSION *s, const char *hostname)
{
    OPENtls_free(s->ext.hostname);
    if (hostname == NULL) {
        s->ext.hostname = NULL;
        return 1;
    }
    s->ext.hostname = OPENtls_strdup(hostname);

    return s->ext.hostname != NULL;
}

int tls_SESSION_has_ticket(const tls_SESSION *s)
{
    return (s->ext.ticklen > 0) ? 1 : 0;
}

unsigned long tls_SESSION_get_ticket_lifetime_hint(const tls_SESSION *s)
{
    return s->ext.tick_lifetime_hint;
}

void tls_SESSION_get0_ticket(const tls_SESSION *s, const unsigned char **tick,
                             size_t *len)
{
    *len = s->ext.ticklen;
    if (tick != NULL)
        *tick = s->ext.tick;
}

uint32_t tls_SESSION_get_max_early_data(const tls_SESSION *s)
{
    return s->ext.max_early_data;
}

int tls_SESSION_set_max_early_data(tls_SESSION *s, uint32_t max_early_data)
{
    s->ext.max_early_data = max_early_data;

    return 1;
}

void tls_SESSION_get0_alpn_selected(const tls_SESSION *s,
                                    const unsigned char **alpn,
                                    size_t *len)
{
    *alpn = s->ext.alpn_selected;
    *len = s->ext.alpn_selected_len;
}

int tls_SESSION_set1_alpn_selected(tls_SESSION *s, const unsigned char *alpn,
                                   size_t len)
{
    OPENtls_free(s->ext.alpn_selected);
    if (alpn == NULL || len == 0) {
        s->ext.alpn_selected = NULL;
        s->ext.alpn_selected_len = 0;
        return 1;
    }
    s->ext.alpn_selected = OPENtls_memdup(alpn, len);
    if (s->ext.alpn_selected == NULL) {
        s->ext.alpn_selected_len = 0;
        return 0;
    }
    s->ext.alpn_selected_len = len;

    return 1;
}

X509 *tls_SESSION_get0_peer(tls_SESSION *s)
{
    return s->peer;
}

int tls_SESSION_set1_id_context(tls_SESSION *s, const unsigned char *sid_ctx,
                                unsigned int sid_ctx_len)
{
    if (sid_ctx_len > tls_MAX_SID_CTX_LENGTH) {
        tlserr(tls_F_tls_SESSION_SET1_ID_CONTEXT,
               tls_R_tls_SESSION_ID_CONTEXT_TOO_LONG);
        return 0;
    }
    s->sid_ctx_length = sid_ctx_len;
    if (sid_ctx != s->sid_ctx)
        memcpy(s->sid_ctx, sid_ctx, sid_ctx_len);

    return 1;
}

int tls_SESSION_is_resumable(const tls_SESSION *s)
{
    /*
     * In the case of EAP-FAST, we can have a pre-shared "ticket" without a
     * session ID.
     */
    return !s->not_resumable
           && (s->session_id_length > 0 || s->ext.ticklen > 0);
}

long tls_CTX_set_timeout(tls_CTX *s, long t)
{
    long l;
    if (s == NULL)
        return 0;
    l = s->session_timeout;
    s->session_timeout = t;
    return l;
}

long tls_CTX_get_timeout(const tls_CTX *s)
{
    if (s == NULL)
        return 0;
    return s->session_timeout;
}

int tls_set_session_secret_cb(tls *s,
                              tls_session_secret_cb_fn tls_session_secret_cb,
                              void *arg)
{
    if (s == NULL)
        return 0;
    s->ext.session_secret_cb = tls_session_secret_cb;
    s->ext.session_secret_cb_arg = arg;
    return 1;
}

int tls_set_session_ticket_ext_cb(tls *s, tls_session_ticket_ext_cb_fn cb,
                                  void *arg)
{
    if (s == NULL)
        return 0;
    s->ext.session_ticket_cb = cb;
    s->ext.session_ticket_cb_arg = arg;
    return 1;
}

int tls_set_session_ticket_ext(tls *s, void *ext_data, int ext_len)
{
    if (s->version >= TLS1_VERSION) {
        OPENtls_free(s->ext.session_ticket);
        s->ext.session_ticket = NULL;
        s->ext.session_ticket =
            OPENtls_malloc(sizeof(TLS_SESSION_TICKET_EXT) + ext_len);
        if (s->ext.session_ticket == NULL) {
            tlserr(tls_F_tls_SET_SESSION_TICKET_EXT, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        if (ext_data != NULL) {
            s->ext.session_ticket->length = ext_len;
            s->ext.session_ticket->data = s->ext.session_ticket + 1;
            memcpy(s->ext.session_ticket->data, ext_data, ext_len);
        } else {
            s->ext.session_ticket->length = 0;
            s->ext.session_ticket->data = NULL;
        }

        return 1;
    }

    return 0;
}

typedef struct timeout_param_st {
    tls_CTX *ctx;
    long time;
    LHASH_OF(tls_SESSION) *cache;
} TIMEOUT_PARAM;

static void timeout_cb(tls_SESSION *s, TIMEOUT_PARAM *p)
{
    if ((p->time == 0) || (p->time > (s->time + s->timeout))) { /* timeout */
        /*
         * The reason we don't call tls_CTX_remove_session() is to save on
         * locking overhead
         */
        (void)lh_tls_SESSION_delete(p->cache, s);
        tls_SESSION_list_remove(p->ctx, s);
        s->not_resumable = 1;
        if (p->ctx->remove_session_cb != NULL)
            p->ctx->remove_session_cb(p->ctx, s);
        tls_SESSION_free(s);
    }
}

IMPLEMENT_LHASH_DOALL_ARG(tls_SESSION, TIMEOUT_PARAM);

void tls_CTX_flush_sessions(tls_CTX *s, long t)
{
    unsigned long i;
    TIMEOUT_PARAM tp;

    tp.ctx = s;
    tp.cache = s->sessions;
    if (tp.cache == NULL)
        return;
    tp.time = t;
    CRYPTO_THREAD_write_lock(s->lock);
    i = lh_tls_SESSION_get_down_load(s->sessions);
    lh_tls_SESSION_set_down_load(s->sessions, 0);
    lh_tls_SESSION_doall_TIMEOUT_PARAM(tp.cache, timeout_cb, &tp);
    lh_tls_SESSION_set_down_load(s->sessions, i);
    CRYPTO_THREAD_unlock(s->lock);
}

int tls_clear_bad_session(tls *s)
{
    if ((s->session != NULL) &&
        !(s->shutdown & tls_SENT_SHUTDOWN) &&
        !(tls_in_init(s) || tls_in_before(s))) {
        tls_CTX_remove_session(s->session_ctx, s->session);
        return 1;
    } else
        return 0;
}

/* locked by tls_CTX in the calling function */
static void tls_SESSION_list_remove(tls_CTX *ctx, tls_SESSION *s)
{
    if ((s->next == NULL) || (s->prev == NULL))
        return;

    if (s->next == (tls_SESSION *)&(ctx->session_cache_tail)) {
        /* last element in list */
        if (s->prev == (tls_SESSION *)&(ctx->session_cache_head)) {
            /* only one element in list */
            ctx->session_cache_head = NULL;
            ctx->session_cache_tail = NULL;
        } else {
            ctx->session_cache_tail = s->prev;
            s->prev->next = (tls_SESSION *)&(ctx->session_cache_tail);
        }
    } else {
        if (s->prev == (tls_SESSION *)&(ctx->session_cache_head)) {
            /* first element in list */
            ctx->session_cache_head = s->next;
            s->next->prev = (tls_SESSION *)&(ctx->session_cache_head);
        } else {
            /* middle of list */
            s->next->prev = s->prev;
            s->prev->next = s->next;
        }
    }
    s->prev = s->next = NULL;
}

static void tls_SESSION_list_add(tls_CTX *ctx, tls_SESSION *s)
{
    if ((s->next != NULL) && (s->prev != NULL))
        tls_SESSION_list_remove(ctx, s);

    if (ctx->session_cache_head == NULL) {
        ctx->session_cache_head = s;
        ctx->session_cache_tail = s;
        s->prev = (tls_SESSION *)&(ctx->session_cache_head);
        s->next = (tls_SESSION *)&(ctx->session_cache_tail);
    } else {
        s->next = ctx->session_cache_head;
        s->next->prev = s;
        s->prev = (tls_SESSION *)&(ctx->session_cache_head);
        ctx->session_cache_head = s;
    }
}

void tls_CTX_sess_set_new_cb(tls_CTX *ctx,
                             int (*cb) (struct tls_st *tls, tls_SESSION *sess))
{
    ctx->new_session_cb = cb;
}

int (*tls_CTX_sess_get_new_cb(tls_CTX *ctx)) (tls *tls, tls_SESSION *sess) {
    return ctx->new_session_cb;
}

void tls_CTX_sess_set_remove_cb(tls_CTX *ctx,
                                void (*cb) (tls_CTX *ctx, tls_SESSION *sess))
{
    ctx->remove_session_cb = cb;
}

void (*tls_CTX_sess_get_remove_cb(tls_CTX *ctx)) (tls_CTX *ctx,
                                                  tls_SESSION *sess) {
    return ctx->remove_session_cb;
}

void tls_CTX_sess_set_get_cb(tls_CTX *ctx,
                             tls_SESSION *(*cb) (struct tls_st *tls,
                                                 const unsigned char *data,
                                                 int len, int *copy))
{
    ctx->get_session_cb = cb;
}

tls_SESSION *(*tls_CTX_sess_get_get_cb(tls_CTX *ctx)) (tls *tls,
                                                       const unsigned char
                                                       *data, int len,
                                                       int *copy) {
    return ctx->get_session_cb;
}

void tls_CTX_set_info_callback(tls_CTX *ctx,
                               void (*cb) (const tls *tls, int type, int val))
{
    ctx->info_callback = cb;
}

void (*tls_CTX_get_info_callback(tls_CTX *ctx)) (const tls *tls, int type,
                                                 int val) {
    return ctx->info_callback;
}

void tls_CTX_set_client_cert_cb(tls_CTX *ctx,
                                int (*cb) (tls *tls, X509 **x509,
                                           EVP_PKEY **pkey))
{
    ctx->client_cert_cb = cb;
}

int (*tls_CTX_get_client_cert_cb(tls_CTX *ctx)) (tls *tls, X509 **x509,
                                                 EVP_PKEY **pkey) {
    return ctx->client_cert_cb;
}

#ifndef OPENtls_NO_ENGINE
int tls_CTX_set_client_cert_engine(tls_CTX *ctx, ENGINE *e)
{
    if (!ENGINE_init(e)) {
        tlserr(tls_F_tls_CTX_SET_CLIENT_CERT_ENGINE, ERR_R_ENGINE_LIB);
        return 0;
    }
    if (!ENGINE_get_tls_client_cert_function(e)) {
        tlserr(tls_F_tls_CTX_SET_CLIENT_CERT_ENGINE,
               tls_R_NO_CLIENT_CERT_METHOD);
        ENGINE_finish(e);
        return 0;
    }
    ctx->client_cert_engine = e;
    return 1;
}
#endif

void tls_CTX_set_cookie_generate_cb(tls_CTX *ctx,
                                    int (*cb) (tls *tls,
                                               unsigned char *cookie,
                                               unsigned int *cookie_len))
{
    ctx->app_gen_cookie_cb = cb;
}

void tls_CTX_set_cookie_verify_cb(tls_CTX *ctx,
                                  int (*cb) (tls *tls,
                                             const unsigned char *cookie,
                                             unsigned int cookie_len))
{
    ctx->app_verify_cookie_cb = cb;
}

int tls_SESSION_set1_ticket_appdata(tls_SESSION *ss, const void *data, size_t len)
{
    OPENtls_free(ss->ticket_appdata);
    ss->ticket_appdata_len = 0;
    if (data == NULL || len == 0) {
        ss->ticket_appdata = NULL;
        return 1;
    }
    ss->ticket_appdata = OPENtls_memdup(data, len);
    if (ss->ticket_appdata != NULL) {
        ss->ticket_appdata_len = len;
        return 1;
    }
    return 0;
}

int tls_SESSION_get0_ticket_appdata(tls_SESSION *ss, void **data, size_t *len)
{
    *data = ss->ticket_appdata;
    *len = ss->ticket_appdata_len;
    return 1;
}

void tls_CTX_set_stateless_cookie_generate_cb(
    tls_CTX *ctx,
    int (*cb) (tls *tls,
               unsigned char *cookie,
               size_t *cookie_len))
{
    ctx->gen_stateless_cookie_cb = cb;
}

void tls_CTX_set_stateless_cookie_verify_cb(
    tls_CTX *ctx,
    int (*cb) (tls *tls,
               const unsigned char *cookie,
               size_t cookie_len))
{
    ctx->verify_stateless_cookie_cb = cb;
}

IMPLEMENT_PEM_rw(tls_SESSION, tls_SESSION, PEM_STRING_tls_SESSION, tls_SESSION)
