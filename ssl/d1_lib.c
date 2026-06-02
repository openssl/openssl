/*
 * Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/e_os.h"
#include "internal/e_winsock.h" /* struct timeval for DTLS_CTRL_GET_TIMEOUT */
#include <stdio.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "ssl_local.h"
#include "internal/time.h"
#include "internal/ssl_unwrap.h"
#include "internal/hashfunc.h"
#include "internal/dtls_record_rx.h"
#include "internal/dgram_demux.h"
#include "internal/dgram_conn_lookup.h"
#include "internal/rio_notifier.h"

static int dtls1_handshake_write(SSL_CONNECTION *s);
static size_t dtls1_link_min_mtu(void);
#ifndef OPENSSL_NO_DTLS
static OSSL_TIME dtls_listener_get_time_direct(DTLS_LISTENER *dl);
#endif

/* XDTLS:  figure out the right values */
static const size_t g_probable_mtu[] = { 1500, 512, 256 };

const SSL3_ENC_METHOD DTLSv1_enc_data = {
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    tls1_final_finish_mac,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls1_alert_code,
    tls1_export_keying_material,
    SSL_ENC_FLAG_DTLS,
    dtls1_set_handshake_header,
    dtls1_close_construct_packet,
    dtls1_handshake_write
};

const SSL3_ENC_METHOD DTLSv1_2_enc_data = {
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    tls1_final_finish_mac,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls1_alert_code,
    tls1_export_keying_material,
    SSL_ENC_FLAG_DTLS | SSL_ENC_FLAG_SIGALGS
        | SSL_ENC_FLAG_SHA256_PRF | SSL_ENC_FLAG_TLS1_2_CIPHERS,
    dtls1_set_handshake_header,
    dtls1_close_construct_packet,
    dtls1_handshake_write
};

const SSL3_ENC_METHOD DTLSv1_3_enc_data = {
    tls13_setup_key_block,
    tls13_generate_master_secret,
    tls13_change_cipher_state,
    tls13_final_finish_mac,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls13_alert_code,
    tls13_export_keying_material,
    SSL_ENC_FLAG_DTLS | SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_SHA256_PRF,
    dtls1_set_handshake_header,
    dtls1_close_construct_packet,
    dtls1_handshake_write
};

OSSL_TIME dtls1_default_timeout(void)
{
    /*
     * 2 hours, the 24 hours mentioned in the DTLSv1 spec is way too long for
     * http, the cache would over fill
     */
    return ossl_seconds2time(60 * 60 * 2);
}

int dtls1_new(SSL *ssl)
{
    DTLS1_STATE *d1;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL)
        return 0;

    if (!DTLS_RECORD_LAYER_new(&s->rlayer)) {
        return 0;
    }

    if (!ssl3_new(ssl))
        return 0;
    if ((d1 = OPENSSL_zalloc(sizeof(*d1))) == NULL) {
        ssl3_free(ssl);
        return 0;
    }

    d1->hello_verify_request = SSL_HVR_NONE;

    s->d1 = d1;

    if (!ssl->method->ssl_clear(ssl))
        return 0;

    return 1;
}

static void dtls1_clear_queues(SSL_CONNECTION *s)
{
    dtls1_clear_received_buffer(s);
    dtls1_clear_sent_buffer(s, 0);
    ossl_list_record_number_elem_free(&s->d1->ack_rec_num);
}

void dtls1_clear_received_buffer(SSL_CONNECTION *s)
{
    pitem *item = NULL;
    hm_fragment *frag = NULL;
    pqueue *rcvd_messages = &s->d1->rcvd_messages;

    while ((item = pqueue_pop(rcvd_messages)) != NULL) {
        frag = (hm_fragment *)item->data;
        dtls1_hm_fragment_free(frag);
        pitem_free(item);
    }
}

void ossl_list_record_number_elem_free(OSSL_LIST(record_number) * p_list)
{
    DTLS1_RECORD_NUMBER *p_elem;
    DTLS1_RECORD_NUMBER *p_elem_next = NULL;

    if (p_list != NULL)
        p_elem_next = ossl_list_record_number_head(p_list);

    while ((p_elem = p_elem_next) != NULL) {
        p_elem_next = ossl_list_record_number_next(p_elem_next);
        ossl_list_record_number_remove(p_list, p_elem);
        OPENSSL_free(p_elem);
    }
}

DTLS1_RECORD_NUMBER *dtls1_record_number_new(uint64_t epoch, uint64_t seqnum)
{
    DTLS1_RECORD_NUMBER *recnum = OPENSSL_zalloc(sizeof(*recnum));

    if (recnum != NULL) {
        recnum->epoch = epoch;
        recnum->seqnum = seqnum;
    }

    return recnum;
}

void dtls1_acknowledge_sent_buffer(SSL_CONNECTION *s, uint64_t before_epoch)
{
    pitem *item = NULL;
    piterator iter = pqueue_iterator(&s->d1->sent_messages);

    while ((item = pqueue_next(&iter)) != NULL) {
        dtls_sent_msg *sent_msg = (dtls_sent_msg *)item->data;
        DTLS1_RECORD_NUMBER *recnum;
        DTLS1_RECORD_NUMBER *recnum_next = ossl_list_record_number_head(&sent_msg->rec_nums);

        while ((recnum = recnum_next) != NULL) {
            recnum_next = ossl_list_record_number_next(recnum_next);

            if (recnum->epoch < before_epoch) {
                ossl_list_record_number_remove(&sent_msg->rec_nums, recnum);
                OPENSSL_free(recnum);
            }
        }
    }
}

void dtls1_clear_sent_buffer(SSL_CONNECTION *s, int keep_unacked_msgs)
{
    pitem *item = NULL;
    pqueue *remaining_sent_messages = pqueue_new();
    pqueue *sent_messages = &s->d1->sent_messages;

    while ((item = pqueue_pop(sent_messages)) != NULL) {
        dtls_sent_msg *sent_msg = (dtls_sent_msg *)item->data;
        unsigned char msg_type = sent_msg->msg_info.msg_type;
        unsigned char record_type = sent_msg->msg_info.record_type;

        if (SSL_CONNECTION_IS_DTLS13(s)
            && !ossl_list_record_number_is_empty(&sent_msg->rec_nums)
            && keep_unacked_msgs) {
            pqueue_insert(remaining_sent_messages, item);
            continue;
        }

        if (((!SSL_CONNECTION_IS_DTLS13(s) && record_type == SSL3_RT_CHANGE_CIPHER_SPEC)
                || (SSL_CONNECTION_IS_DTLS13(s)
                    && (msg_type == SSL3_MT_FINISHED
                        || msg_type == SSL3_MT_SERVER_HELLO
                        || msg_type == SSL3_MT_KEY_UPDATE)))
            && sent_msg->saved_retransmit_state.wrlmethod != NULL
            && s->rlayer.wrl != sent_msg->saved_retransmit_state.wrl) {
            /*
             * If we're freeing the CCS then we're done with the old wrl and it
             * can bee freed
             */
            sent_msg->saved_retransmit_state.wrlmethod->free(sent_msg->saved_retransmit_state.wrl);
        }

        dtls1_sent_msg_free(sent_msg);
        pitem_free(item);
    }

    if (SSL_CONNECTION_IS_DTLS13(s))
        while ((item = pqueue_pop(remaining_sent_messages)) != NULL)
            pqueue_insert(&s->d1->sent_messages, item);

    pqueue_free(remaining_sent_messages);
}

/*
 * Before RECORD_LAYER_clear() frees s->rlayer.wrl, null out any
 * saved_retransmit_state.wrl pointers in the sent_messages queue that
 * reference it.  This transfers ownership of that free exclusively to
 * RECORD_LAYER_clear and prevents dtls1_clear_sent_buffer from freeing
 * the same pointer a second time.  Entries with a different (older) wrl
 * pointer are left untouched and will be freed correctly later.
 */
void dtls1_clear_current_wrl_from_sent_buffer(SSL_CONNECTION *s)
{
    pitem *item;
    piterator iter = pqueue_iterator(&s->d1->sent_messages);

    while ((item = pqueue_next(&iter)) != NULL) {
        dtls_sent_msg *sent_msg = (dtls_sent_msg *)item->data;

        if (sent_msg->saved_retransmit_state.wrl == s->rlayer.wrl) {
            sent_msg->saved_retransmit_state.wrl = NULL;
            sent_msg->saved_retransmit_state.wrlmethod = NULL;
        }
    }
}

int dtls_any_sent_messages_are_missing_acknowledge(SSL_CONNECTION *s)
{
    pitem *item;
    piterator iter = pqueue_iterator(&s->d1->sent_messages);

    while ((item = pqueue_next(&iter)) != NULL) {
        dtls_sent_msg *msg = (dtls_sent_msg *)item->data;

        if (!ossl_list_record_number_is_empty(&msg->rec_nums))
            return 1;
    }

    return 0;
}

void dtls1_free(SSL *ssl)
{
    SSL_CONNECTION *s;

#ifndef OPENSSL_NO_DTLS
    if (IS_DTLS_LISTENER(ssl)) {
        ossl_dtls_listener_free(ssl);
        return;
    }
#endif

    s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL)
        return;

#ifndef OPENSSL_NO_DTLS
    /*
     * If this connection was created by a listener, unregister it from the
     * listener's established_conns lookup table to prevent use-after-free.
     * The listener routes incoming packets to connections via this table,
     * so we must remove ourselves before freeing.
     */
    if (s->d1 != NULL && s->d1->listener != NULL)
        ossl_dtls_listener_unregister_established_conn(s->d1->listener,
            &s->d1->peer_addr);
#endif

    if (s->d1 != NULL)
        dtls1_clear_queues(s);

#ifndef OPENSSL_NO_DTLS
    ossl_dtls_rx_free(s->d1->rx);

    if (s->d1 != NULL && s->d1->listener != NULL) {
        SSL_free(s->d1->listener);
    }
#endif

    DTLS_RECORD_LAYER_free(&s->rlayer);
    ssl3_free(ssl);
    OPENSSL_free(s->d1);
    s->d1 = NULL;
}

int dtls1_clear(SSL *ssl)
{
    size_t mtu;
    size_t link_mtu;
    SSL_CONNECTION *s;

#ifndef OPENSSL_NO_DTLS
    if (IS_DTLS_LISTENER(ssl))
        return 1;
#endif

    s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL)
        return 0;

    DTLS_RECORD_LAYER_clear(&s->rlayer);

    if (s->d1) {
        DTLS_timer_cb timer_cb = s->d1->timer_cb;
#ifndef OPENSSL_NO_SOCK
        BIO_ADDR peer_addr = s->d1->peer_addr;
#endif
#ifndef OPENSSL_NO_DTLS
        DTLS_RX *rx = s->d1->rx;
        SSL *listener = s->d1->listener;
        OSSL_TIME created_at = s->d1->created_at;
#endif

        mtu = s->d1->mtu;
        link_mtu = s->d1->link_mtu;

        dtls1_clear_queues(s);

        memset(s->d1, 0, sizeof(*s->d1));

        /* Restore the timer callback from previous state */
        s->d1->timer_cb = timer_cb;

#ifndef OPENSSL_NO_SOCK
        /*
         * Restore peer address, DTLS_RX, listener, and created_at for
         * listener-created connections. These are set via
         * SSL_set1_initial_peer_addr(), ossl_dtls_rx_new(), and
         * dtls_listener_create_conn_ssl() before the handshake starts,
         * and must be preserved across SSL_clear().
         */
        s->d1->peer_addr = peer_addr;
#endif
#ifndef OPENSSL_NO_DTLS
        s->d1->rx = rx;
        s->d1->listener = listener;
        s->d1->created_at = created_at;
#endif

        if (SSL_get_options(ssl) & SSL_OP_NO_QUERY_MTU) {
            s->d1->mtu = mtu;
            s->d1->link_mtu = link_mtu;
        }
    }

    if (!ssl3_clear(ssl))
        return 0;

    if (ssl->method->version == DTLS_ANY_VERSION)
        s->version = DTLS_MAX_VERSION_INTERNAL;
#ifndef OPENSSL_NO_DTLS1_METHOD
    else if (s->options & SSL_OP_CISCO_ANYCONNECT)
        s->client_version = s->version = DTLS1_BAD_VER;
#endif
    else
        s->version = ssl->method->version;

    return 1;
}

long dtls1_ctrl(SSL *ssl, int cmd, long larg, void *parg)
{
    int ret = 0;
    OSSL_TIME t;
    SSL_CONNECTION *s;

    if (IS_DTLS_LISTENER(ssl))
        return 0;

    s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL)
        return 0;

    switch (cmd) {
    case DTLS_CTRL_GET_TIMEOUT:
        if (dtls1_get_timeout(s, &t)) {
            *(struct timeval *)parg = ossl_time_to_timeval(t);
            ret = 1;
        }
        break;
    case DTLS_CTRL_HANDLE_TIMEOUT:
        ret = dtls1_handle_timeout(s);
        break;
    case DTLS_CTRL_SET_LINK_MTU:
        if (larg < (long)dtls1_link_min_mtu())
            return 0;
        s->d1->link_mtu = larg;
        return 1;
    case DTLS_CTRL_GET_LINK_MIN_MTU:
        return (long)dtls1_link_min_mtu();
    case SSL_CTRL_SET_MTU:
        /*
         *  We may not have a BIO set yet so can't call dtls1_min_mtu()
         *  We'll have to make do with dtls1_link_min_mtu() and max overhead
         */
        if (larg < (long)dtls1_link_min_mtu() - DTLS1_MAX_MTU_OVERHEAD)
            return 0;
        s->d1->mtu = larg;
        return larg;
    default:
        ret = ssl3_ctrl(ssl, cmd, larg, parg);
        break;
    }
    return ret;
}

static void dtls1_bio_set_next_timeout(BIO *bio, const DTLS1_STATE *d1)
{
    struct timeval tv = ossl_time_to_timeval(d1->next_timeout);

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0, &tv);
}

void dtls1_start_timer(SSL_CONNECTION *s)
{
    OSSL_TIME duration;
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);

#ifndef OPENSSL_NO_SCTP
    /* Disable timer for SCTP */
    if (SSL_get_wbio(ssl) != NULL && BIO_dgram_is_sctp(SSL_get_wbio(ssl))) {
        s->d1->next_timeout = ossl_time_zero();
        return;
    }
#endif

    /*
     * If timer is not set, initialize duration with 1 second or
     * a user-specified value if the timer callback is installed.
     */
    if (ossl_time_is_zero(s->d1->next_timeout)) {
        if (s->d1->timer_cb != NULL)
            s->d1->timeout_duration_us = s->d1->timer_cb(ssl, 0);
        else
            s->d1->timeout_duration_us = 1000000;
    }

    /* Set timeout to current time plus duration */
    duration = ossl_us2time(s->d1->timeout_duration_us);
    s->d1->next_timeout = ossl_time_add(ossl_time_now(), duration);

    /* set s->d1->next_timeout into ssl->rbio interface */
    dtls1_bio_set_next_timeout(SSL_get_rbio(ssl), s->d1);
}

int dtls1_get_timeout(const SSL_CONNECTION *s, OSSL_TIME *timeleft)
{
    OSSL_TIME timenow;

    /* If no timeout is set, just return NULL */
    if (ossl_time_is_zero(s->d1->next_timeout))
        return 0;

    /* Get current time */
    timenow = ossl_time_now();

    /*
     * If timer already expired or if remaining time is less than 15 ms,
     * set it to 0 to prevent issues because of small divergences with
     * socket timeouts.
     */
    *timeleft = ossl_time_subtract(s->d1->next_timeout, timenow);
    if (ossl_time_compare(*timeleft, ossl_ms2time(15)) <= 0)
        *timeleft = ossl_time_zero();
    return 1;
}

int dtls1_is_timer_expired(SSL_CONNECTION *s)
{
    OSSL_TIME timeleft;

    /* Get time left until timeout, return false if no timer running */
    if (!dtls1_get_timeout(s, &timeleft))
        return 0;

    /* Return false if timer is not expired yet */
    if (!ossl_time_is_zero(timeleft))
        return 0;

    /* Timer expired, so return true */
    return 1;
}

static void dtls1_double_timeout(SSL_CONNECTION *s)
{
    s->d1->timeout_duration_us *= 2;
    if (s->d1->timeout_duration_us > 60000000)
        s->d1->timeout_duration_us = 60000000;
}

void dtls1_stop_timer(SSL_CONNECTION *s)
{
    /* Reset everything */
    s->d1->timeout_num_alerts = 0;
    s->d1->next_timeout = ossl_time_zero();
    s->d1->timeout_duration_us = 1000000;
    dtls1_bio_set_next_timeout(s->rbio, s->d1);
    /* Clear retransmission buffer */
    dtls1_clear_sent_buffer(s, 0);
}

int dtls1_check_timeout_num(SSL_CONNECTION *s)
{
    size_t mtu;
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);

    s->d1->timeout_num_alerts++;

    /* Reduce MTU after 2 unsuccessful retransmissions */
    if (s->d1->timeout_num_alerts > 2
        && !(SSL_get_options(ssl) & SSL_OP_NO_QUERY_MTU)) {
        mtu = BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0, NULL);
        if (mtu < s->d1->mtu)
            s->d1->mtu = mtu;
    }

    if (s->d1->timeout_num_alerts > DTLS1_TMO_ALERT_COUNT) {
        /* fail the connection, enough alerts have been sent */
        SSLfatal(s, SSL_AD_NO_ALERT, SSL_R_READ_TIMEOUT_EXPIRED);
        return -1;
    }

    return 0;
}

int dtls1_handle_timeout(SSL_CONNECTION *s)
{
    /* if no timer is expired, don't do anything */
    if (!dtls1_is_timer_expired(s)) {
        return 0;
    }

    if (s->d1->timer_cb != NULL)
        s->d1->timeout_duration_us = s->d1->timer_cb(SSL_CONNECTION_GET_USER_SSL(s),
            s->d1->timeout_duration_us);
    else
        dtls1_double_timeout(s);

    if (dtls1_check_timeout_num(s) < 0) {
        /* SSLfatal() already called */
        return -1;
    }

    dtls1_start_timer(s);
    /* Calls SSLfatal() if required */
    return dtls1_retransmit_sent_messages(s);
}

#define LISTEN_SUCCESS 2
#define LISTEN_SEND_VERIFY_REQUEST 1

#ifndef OPENSSL_NO_SOCK
int DTLSv1_listen(SSL *ssl, BIO_ADDR *client)
{
    int next, n, ret = 0;
    unsigned char cookie[DTLS1_COOKIE_LENGTH];
    unsigned char seq[SEQ_NUM_SIZE];
    const unsigned char *data;
    unsigned char *buf = NULL, *wbuf;
    size_t fragoff, fraglen, msglen;
    unsigned int rectype, versmajor, versminor, msgseq, msgtype, clientvers, cookielen;
    BIO *rbio, *wbio;
    BIO_ADDR *tmpclient = NULL;
    PACKET pkt, msgpkt, msgpayload, session, cookiepkt;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL)
        return -1;

    if (s->handshake_func == NULL) {
        /* Not properly initialized yet */
        SSL_set_accept_state(ssl);
    }

    /* Ensure there is no state left over from a previous invocation */
    if (!SSL_clear(ssl))
        return -1;

    ERR_clear_error();

    rbio = SSL_get_rbio(ssl);
    wbio = SSL_get_wbio(ssl);

    if (!rbio || !wbio) {
        ERR_raise(ERR_LIB_SSL, SSL_R_BIO_NOT_SET);
        return -1;
    }

    /*
     * Note: This check deliberately excludes DTLS1_BAD_VER because that version
     * requires the MAC to be calculated *including* the first ClientHello
     * (without the cookie). Since DTLSv1_listen is stateless that cannot be
     * supported. DTLS1_BAD_VER must use cookies in a stateful manner (e.g. via
     * SSL_accept)
     */
    if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00)) {
        ERR_raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_SSL_VERSION);
        return -1;
    }

    /*
     * DTLSv1_listen() only supports the legacy HelloVerifyRequest mechanism
     * which is not used in DTLS 1.3. For DTLS 1.3, use the SSL_new_listener()
     * API instead which supports HelloRetryRequest with cookies.
     *
     * If the SSL object is configured for DTLS 1.3 only (both min and max
     * are set to DTLS 1.3), we must fail since there's no room to downgrade.
     * Otherwise, if max allows DTLS 1.3, we clamp it down to DTLS 1.2 so
     * that the handshake will use HelloVerifyRequest.
     */
    if (SSL_CONNECTION_IS_DTLS(s)) {
        int min_version = s->min_proto_version;
        int max_version = s->max_proto_version;

        /*
         * Check if configured for DTLS 1.3 only - this is not supported.
         * min_proto_version of 0 means "use default" which includes older versions,
         * so only fail if min is explicitly set to DTLS 1.3.
         */
        if (min_version == DTLS1_3_VERSION
            && (max_version == 0 || max_version == DTLS1_3_VERSION)) {
            ERR_raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_SSL_VERSION);
            return -1;
        }

        /* max_proto_version of 0 means "use default" which could include 1.3 */
        if (max_version == 0 || DTLS_VERSION_GE(max_version, DTLS1_3_VERSION)) {
            if (!SSL_set_max_proto_version(ssl, DTLS1_2_VERSION)) {
                ERR_raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_SSL_VERSION);
                return -1;
            }
        }
    }

    buf = OPENSSL_malloc(DTLS1_RT_HEADER_LENGTH + SSL3_RT_MAX_PLAIN_LENGTH);
    if (buf == NULL)
        return -1;
    wbuf = OPENSSL_malloc(DTLS1_RT_HEADER_LENGTH + SSL3_RT_MAX_PLAIN_LENGTH);
    if (wbuf == NULL) {
        OPENSSL_free(buf);
        return -1;
    }

    do {
        /* Get a packet */

        clear_sys_error();
        n = BIO_read(rbio, buf, SSL3_RT_MAX_PLAIN_LENGTH + DTLS1_RT_HEADER_LENGTH);
        if (n <= 0) {
            if (BIO_should_retry(rbio)) {
                /* Non-blocking IO */
                goto end;
            }
            ret = -1;
            goto end;
        }

        if (!PACKET_buf_init(&pkt, buf, n)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            ret = -1;
            goto end;
        }

        /*
         * Parse the received record. If there are any problems with it we just
         * dump it - with no alert. RFC6347 says this "Unlike TLS, DTLS is
         * resilient in the face of invalid records (e.g., invalid formatting,
         * length, MAC, etc.).  In general, invalid records SHOULD be silently
         * discarded, thus preserving the association; however, an error MAY be
         * logged for diagnostic purposes."
         */

        /* this packet contained a partial record, dump it */
        if (n < DTLS1_RT_HEADER_LENGTH) {
            ERR_raise(ERR_LIB_SSL, SSL_R_RECORD_TOO_SMALL);
            goto end;
        }

        /* Get the record header */
        if (!PACKET_get_1(&pkt, &rectype)
            || !PACKET_get_1(&pkt, &versmajor)
            || !PACKET_get_1(&pkt, &versminor)) {
            ERR_raise(ERR_LIB_SSL, SSL_R_LENGTH_MISMATCH);
            goto end;
        }

        if (s->msg_callback)
            s->msg_callback(0, (versmajor << 8) | versminor, SSL3_RT_HEADER, buf,
                DTLS1_RT_HEADER_LENGTH, ssl, s->msg_callback_arg);

        if (rectype != SSL3_RT_HANDSHAKE) {
            ERR_raise(ERR_LIB_SSL, SSL_R_UNEXPECTED_MESSAGE);
            goto end;
        }

        /*
         * Check record version number. We only check that the major version is
         * the same.
         */
        if (versmajor != DTLS1_VERSION_MAJOR) {
            ERR_raise(ERR_LIB_SSL, SSL_R_BAD_PROTOCOL_VERSION_NUMBER);
            goto end;
        }

        /* Save the sequence number: 64 bits, with top 2 bytes = epoch */
        if (!PACKET_copy_bytes(&pkt, seq, SEQ_NUM_SIZE)
            || !PACKET_get_length_prefixed_2(&pkt, &msgpkt)) {
            ERR_raise(ERR_LIB_SSL, SSL_R_LENGTH_MISMATCH);
            goto end;
        }
        /*
         * We allow data remaining at the end of the packet because there could
         * be a second record (but we ignore it)
         */

        /* This is an initial ClientHello so the epoch has to be 0 */
        if (seq[0] != 0 || seq[1] != 0) {
            ERR_raise(ERR_LIB_SSL, SSL_R_UNEXPECTED_MESSAGE);
            goto end;
        }

        /* Get a pointer to the raw message for the later callback */
        data = PACKET_data(&msgpkt);

        /* Finished processing the record header, now process the message */
        if (!PACKET_get_1(&msgpkt, &msgtype)
            || !PACKET_get_net_3_len(&msgpkt, &msglen)
            || !PACKET_get_net_2(&msgpkt, &msgseq)
            || !PACKET_get_net_3_len(&msgpkt, &fragoff)
            || !PACKET_get_net_3_len(&msgpkt, &fraglen)
            || !PACKET_get_sub_packet(&msgpkt, &msgpayload, fraglen)
            || PACKET_remaining(&msgpkt) != 0) {
            ERR_raise(ERR_LIB_SSL, SSL_R_LENGTH_MISMATCH);
            goto end;
        }

        if (msgtype != SSL3_MT_CLIENT_HELLO) {
            ERR_raise(ERR_LIB_SSL, SSL_R_UNEXPECTED_MESSAGE);
            goto end;
        }

        /* Message sequence number can only be 0 or 1 */
        if (msgseq > 1) {
            ERR_raise(ERR_LIB_SSL, SSL_R_INVALID_SEQUENCE_NUMBER);
            goto end;
        }

        /*
         * We don't support fragment reassembly for ClientHellos whilst
         * listening because that would require server side state (which is
         * against the whole point of the ClientHello/HelloVerifyRequest
         * mechanism). Instead we only look at the first ClientHello fragment
         * and require that the cookie must be contained within it.
         */
        if (fragoff != 0 || fraglen > msglen) {
            /* Non initial ClientHello fragment (or bad fragment) */
            ERR_raise(ERR_LIB_SSL, SSL_R_FRAGMENTED_CLIENT_HELLO);
            goto end;
        }

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, data,
                fraglen + DTLS1_HM_HEADER_LENGTH, ssl,
                s->msg_callback_arg);

        if (!PACKET_get_net_2(&msgpayload, &clientvers)) {
            ERR_raise(ERR_LIB_SSL, SSL_R_LENGTH_MISMATCH);
            goto end;
        }

        /*
         * Verify client version is supported
         */
        if (DTLS_VERSION_LT(clientvers, (unsigned int)ssl->method->version) && ssl->method->version != DTLS_ANY_VERSION) {
            ERR_raise(ERR_LIB_SSL, SSL_R_WRONG_VERSION_NUMBER);
            goto end;
        }

        if (!PACKET_forward(&msgpayload, SSL3_RANDOM_SIZE)
            || !PACKET_get_length_prefixed_1(&msgpayload, &session)
            || !PACKET_get_length_prefixed_1(&msgpayload, &cookiepkt)) {
            /*
             * Could be malformed or the cookie does not fit within the initial
             * ClientHello fragment. Either way we can't handle it.
             */
            ERR_raise(ERR_LIB_SSL, SSL_R_LENGTH_MISMATCH);
            goto end;
        }

        /*
         * Check if we have a cookie or not. If not we need to send a
         * HelloVerifyRequest.
         */
        if (PACKET_remaining(&cookiepkt) == 0) {
            next = LISTEN_SEND_VERIFY_REQUEST;
        } else {
            /*
             * We have a cookie, so lets check it.
             */
            if (ssl->ctx->app_verify_cookie_cb == NULL) {
                ERR_raise(ERR_LIB_SSL, SSL_R_NO_VERIFY_COOKIE_CALLBACK);
                /* This is fatal */
                ret = -1;
                goto end;
            }
            if (ssl->ctx->app_verify_cookie_cb(ssl, PACKET_data(&cookiepkt),
                    (unsigned int)PACKET_remaining(&cookiepkt))
                == 0) {
                /*
                 * We treat invalid cookies in the same was as no cookie as
                 * per RFC6347
                 */
                next = LISTEN_SEND_VERIFY_REQUEST;
            } else {
                /* Cookie verification succeeded */
                next = LISTEN_SUCCESS;
            }
        }

        if (next == LISTEN_SEND_VERIFY_REQUEST) {
            WPACKET wpkt;
            unsigned int version;
            size_t wreclen;

            /*
             * There was no cookie in the ClientHello so we need to send a
             * HelloVerifyRequest. If this fails we do not worry about trying
             * to resend, we just drop it.
             */

            /* Generate the cookie */
            if (ssl->ctx->app_gen_cookie_cb == NULL || ssl->ctx->app_gen_cookie_cb(ssl, cookie, &cookielen) == 0 || cookielen > 255) {
                ERR_raise(ERR_LIB_SSL, SSL_R_COOKIE_GEN_CALLBACK_FAILURE);
                /* This is fatal */
                ret = -1;
                goto end;
            }

            /*
             * Special case: for hello verify request, client version 1.0 and we
             * haven't decided which version to use yet send back using version
             * 1.0 header: otherwise some clients will ignore it.
             */
            version = (ssl->method->version == DTLS_ANY_VERSION) ? DTLS1_VERSION
                                                                 : s->version;

            /* Construct the record and message headers */
            if (!WPACKET_init_static_len(&wpkt,
                    wbuf,
                    ssl_get_max_send_fragment(s)
                        + DTLS1_RT_HEADER_LENGTH,
                    0)
                || !WPACKET_put_bytes_u8(&wpkt, SSL3_RT_HANDSHAKE)
                || !WPACKET_put_bytes_u16(&wpkt, version)
                /*
                 * Record sequence number is always the same as in the
                 * received ClientHello
                 */
                || !WPACKET_memcpy(&wpkt, seq, SEQ_NUM_SIZE)
                /* End of record, start sub packet for message */
                || !WPACKET_start_sub_packet_u16(&wpkt)
                /* Message type */
                || !WPACKET_put_bytes_u8(&wpkt,
                    DTLS1_MT_HELLO_VERIFY_REQUEST)
                /*
                 * Message length - doesn't follow normal TLS convention:
                 * the length isn't the last thing in the message header.
                 * We'll need to fill this in later when we know the
                 * length. Set it to zero for now
                 */
                || !WPACKET_put_bytes_u24(&wpkt, 0)
                /*
                 * Message sequence number is always 0 for a
                 * HelloVerifyRequest
                 */
                || !WPACKET_put_bytes_u16(&wpkt, 0)
                /*
                 * We never fragment a HelloVerifyRequest, so fragment
                 * offset is 0
                 */
                || !WPACKET_put_bytes_u24(&wpkt, 0)
                /*
                 * Fragment length is the same as message length, but
                 * this *is* the last thing in the message header so we
                 * can just start a sub-packet. No need to come back
                 * later for this one.
                 */
                || !WPACKET_start_sub_packet_u24(&wpkt)
                /* Create the actual HelloVerifyRequest body */
                || !dtls_raw_hello_verify_request(&wpkt, cookie, cookielen)
                /* Close message body */
                || !WPACKET_close(&wpkt)
                /* Close record body */
                || !WPACKET_close(&wpkt)
                || !WPACKET_get_total_written(&wpkt, &wreclen)
                || !WPACKET_finish(&wpkt)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                WPACKET_cleanup(&wpkt);
                /* This is fatal */
                ret = -1;
                goto end;
            }

            /*
             * Fix up the message len in the message header. Its the same as the
             * fragment len which has been filled in by WPACKET, so just copy
             * that. Destination for the message len is after the record header
             * plus one byte for the message content type. The source is the
             * last 3 bytes of the message header
             */
            memcpy(&wbuf[DTLS1_RT_HEADER_LENGTH + 1],
                &wbuf[DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH - 3],
                3);

            if (s->msg_callback) {
                /* Report the outgoing DTLS record header */
                s->msg_callback(1, (int)version, SSL3_RT_HEADER,
                    wbuf, DTLS1_RT_HEADER_LENGTH,
                    ssl, s->msg_callback_arg);
                /* Report the HelloVerifyRequest handshake message */
                s->msg_callback(1, (int)version, SSL3_RT_HANDSHAKE,
                    wbuf + DTLS1_RT_HEADER_LENGTH,
                    wreclen - DTLS1_RT_HEADER_LENGTH,
                    ssl, s->msg_callback_arg);
            }

            if ((tmpclient = BIO_ADDR_new()) == NULL) {
                ERR_raise(ERR_LIB_SSL, ERR_R_BIO_LIB);
                goto end;
            }

            /*
             * This is unnecessary if rbio and wbio are one and the same - but
             * maybe they're not. We ignore errors here - some BIOs do not
             * support this.
             */
            if (BIO_dgram_get_peer(rbio, tmpclient) > 0) {
                (void)BIO_dgram_set_peer(wbio, tmpclient);
            }
            BIO_ADDR_free(tmpclient);
            tmpclient = NULL;

            if (BIO_write(wbio, wbuf, (int)wreclen) < (int)wreclen) {
                if (BIO_should_retry(wbio)) {
                    /*
                     * Non-blocking IO...but we're stateless, so we're just
                     * going to drop this packet.
                     */
                    goto end;
                }
                ret = -1;
                goto end;
            }

            if (BIO_flush(wbio) <= 0) {
                if (BIO_should_retry(wbio)) {
                    /*
                     * Non-blocking IO...but we're stateless, so we're just
                     * going to drop this packet.
                     */
                    goto end;
                }
                ret = -1;
                goto end;
            }
        }
    } while (next != LISTEN_SUCCESS);

    /*
     * Set expected sequence numbers to continue the handshake.
     */
    s->d1->handshake_read_seq = 1;
    s->d1->handshake_write_seq = 1;
    s->d1->next_handshake_write_seq = 1;
    s->rlayer.wrlmethod->increment_sequence_ctr(s->rlayer.wrl);

    /*
     * We are doing cookie exchange, so make sure we set that option in the
     * SSL object
     */
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    /*
     * Tell the state machine that we've done the initial hello verify
     * exchange
     */
    ossl_statem_set_hello_verify_done(s);

    /*
     * Some BIOs may not support this. If we fail we clear the client address
     */
    if (BIO_dgram_get_peer(rbio, client) <= 0)
        BIO_ADDR_clear(client);

    /* Buffer the record for use by the record layer */
    if (BIO_write(s->rlayer.rrlnext, buf, n) != n) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        ret = -1;
        goto end;
    }

    /*
     * Reset the record layer - but this time we can use the record we just
     * buffered in s->rlayer.rrlnext
     */
    if (!ssl_set_new_record_layer(s, DTLS_ANY_VERSION,
            OSSL_RECORD_DIRECTION_READ,
            OSSL_RECORD_PROTECTION_LEVEL_NONE, NULL, 0,
            NULL, NULL, 0, NULL, 0, NULL, 0, NULL, NULL,
            0, NID_undef, NULL, NULL, NULL)) {
        /* SSLfatal already called */
        ret = -1;
        goto end;
    }

    ret = 1;
end:
    BIO_ADDR_free(tmpclient);
    OPENSSL_free(buf);
    OPENSSL_free(wbuf);
    return ret;
}
#endif

static int dtls1_handshake_write(SSL_CONNECTION *s)
{
    return dtls1_do_write(s, SSL3_RT_HANDSHAKE);
}

int dtls1_shutdown(SSL *s)
{
    int ret;
#ifndef OPENSSL_NO_SCTP
    BIO *wbio;
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(s);

    if (sc == NULL)
        return -1;

    wbio = SSL_get_wbio(s);
    if (wbio != NULL && BIO_dgram_is_sctp(wbio) && !(sc->shutdown & SSL_SENT_SHUTDOWN)) {
        ret = BIO_dgram_sctp_wait_for_dry(wbio);
        if (ret < 0)
            return -1;

        if (ret == 0)
            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN, 1,
                NULL);
    }
#endif
    ret = ssl3_shutdown(s);
#ifndef OPENSSL_NO_SCTP
    BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN, 0, NULL);
#endif
    return ret;
}

int dtls1_query_mtu(SSL_CONNECTION *s)
{
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);

    if (s->d1->link_mtu) {
        s->d1->mtu = s->d1->link_mtu - BIO_dgram_get_mtu_overhead(SSL_get_wbio(ssl));
        s->d1->link_mtu = 0;
    }

    /* AHA!  Figure out the MTU, and stick to the right size */
    if (s->d1->mtu < dtls1_min_mtu(s)) {
        if (!(SSL_get_options(ssl) & SSL_OP_NO_QUERY_MTU)) {
            s->d1->mtu = BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL);

            /*
             * I've seen the kernel return bogus numbers when it doesn't know
             * (initial write), so just make sure we have a reasonable number
             */
            if (s->d1->mtu < dtls1_min_mtu(s)) {
                /* Set to min mtu */
                s->d1->mtu = dtls1_min_mtu(s);
                BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_SET_MTU,
                    (long)s->d1->mtu, NULL);
            }
        } else
            return 0;
    }
    return 1;
}

static size_t dtls1_link_min_mtu(void)
{
    return (g_probable_mtu[(sizeof(g_probable_mtu) / sizeof(g_probable_mtu[0])) - 1]);
}

size_t dtls1_min_mtu(SSL_CONNECTION *s)
{
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);

    return dtls1_link_min_mtu() - BIO_dgram_get_mtu_overhead(SSL_get_wbio(ssl));
}

size_t DTLS_get_data_mtu(const SSL *ssl)
{
    size_t mac_overhead, int_overhead, blocksize, ext_overhead, rechdrlen = 0;
    const SSL_CIPHER *ciph = SSL_get_current_cipher(ssl);
    size_t mtu;
    const SSL_CONNECTION *s = SSL_CONNECTION_FROM_CONST_SSL_ONLY(ssl);

    if (s == NULL)
        return 0;

    mtu = s->d1->mtu;

    if (ciph == NULL)
        return 0;

    if (!ssl_cipher_get_overhead(ciph, &mac_overhead, &int_overhead,
            &blocksize, &ext_overhead))
        return 0;

    if (SSL_READ_ETM(s))
        ext_overhead += mac_overhead;
    else
        int_overhead += mac_overhead;

    if (SSL_version(ssl) == DTLS1_3_VERSION) {
        switch (SSL_get_state(ssl)) {
        case TLS_ST_BEFORE:
        case DTLS_ST_CR_HELLO_VERIFY_REQUEST:
        case TLS_ST_CR_SRVR_HELLO:
        case TLS_ST_CW_CLNT_HELLO:
        case TLS_ST_CW_COMP_CERT:
        case TLS_ST_CW_KEY_EXCH:
        case TLS_ST_SW_HELLO_REQ:
        case TLS_ST_SR_CLNT_HELLO:
        case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        case TLS_ST_SW_SRVR_HELLO:
        case TLS_ST_CR_HELLO_REQ:
            rechdrlen = DTLS1_RT_HEADER_LENGTH;
            break;
        default:
            rechdrlen = DTLS13_UNI_HDR_FIXED_LENGTH;
            break;
        }

        /* Added record type at the end of the data */
        int_overhead++;

    } else {
        rechdrlen = DTLS1_RT_HEADER_LENGTH;
    }

    /* Subtract external overhead (e.g. IV/nonce, separate MAC) */
    if (ext_overhead + rechdrlen >= mtu)
        return 0;
    mtu -= ext_overhead + rechdrlen;

    /* Round encrypted payload down to cipher block size (for CBC etc.)
     * No check for overflow since 'mtu % blocksize' cannot exceed mtu. */
    if (blocksize)
        mtu -= (mtu % blocksize);

    /* Subtract internal overhead (e.g. CBC padding len byte) */
    if (int_overhead >= mtu)
        return 0;
    mtu -= int_overhead;

    return mtu;
}

void DTLS_set_timer_cb(SSL *ssl, DTLS_timer_cb cb)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL)
        return;

    s->d1->timer_cb = cb;
}

#if !defined(OPENSSL_NO_DTLS) && !defined(OPENSSL_NO_SOCK)
/*
 * dtls_listener_create_conn_ssl - create an SSL object for a new connection.
 *
 * Creates and initializes an SSL object for handling a new incoming
 * connection. Sets up the DTLS_RX for URXE-based packet injection, with
 * the write BIO connected to the listener's network BIO.
 *
 * Returns: new SSL object on success, NULL on failure
 */
static SSL *dtls_listener_create_conn_ssl(DTLS_LISTENER *dl,
    const BIO_ADDR *peer)
{
    SSL *ssl = NULL;
    SSL_CONNECTION *sc = NULL;
    BIO *wbio = NULL;

    ssl = SSL_new(dl->ssl.ctx);
    if (ssl == NULL)
        goto err;

    sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    if (sc == NULL || sc->d1 == NULL)
        goto err;

    SSL_set_accept_state(ssl);

    /*
     * Create DTLS_RX for this connection. The demux is owned by the listener
     * and will outlive this connection. DTLS_RX manages the URXE queue for
     * incoming packets.
     */
    sc->d1->rx = ossl_dtls_rx_new(dl->demux);
    if (sc->d1->rx == NULL)
        goto err;

    /*
     * Store reference to parent listener. This allows the connection to
     * trigger the listener's demux pump when reading data.
     */
    sc->d1->listener = &dl->ssl;

    /*
     * Record when this connection was created. This is used to detect and
     * clean up stale pending connections that haven't completed their
     * handshake within the timeout period.
     */
    sc->d1->created_at = dtls_listener_get_time_direct(dl);

    /*
     * For writes, use the shared network wbio. The peer address is NOT set
     * on the BIO itself (which would affect all connections sharing this BIO).
     * Instead, the peer address will be passed to the record layer during
     * SSL_do_handshake(), and the record layer will use BIO_sendmmsg() with
     * the peer address for each write.
     */
    wbio = dl->net_wbio;

    if (wbio == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_BIO_NOT_SET);
        goto err;
    }

    if (!BIO_up_ref(wbio))
        goto err;

    SSL_set0_rbio(ssl, NULL);
    SSL_set0_wbio(ssl, wbio);
    wbio = NULL; /* ownership transferred */

    /*
     * Store the peer address in the SSL connection. This will be passed to
     * the record layer when it is created during SSL_do_handshake().
     */
    if (!SSL_set1_initial_peer_addr(ssl, peer))
        goto err;

    /*
     * Enable cookie exchange if required by listener flags.
     * This tells the state machine to perform HVR (DTLS 1.2) or
     * HRR with cookie (DTLS 1.3) validation.
     */
    if (dl->require_hvr_cookie || dl->require_hrr_cookie)
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    return ssl;

err:
    SSL_free(ssl);
    return NULL;
}

/*
 * dtls_listener_packet_handler - callback for handling incoming datagrams.
 *
 * This callback is invoked by the demux for each received datagram. It routes
 * the URXE to the appropriate connection based on peer address, creating a
 * new pending connection if necessary.
 *
 * The URXE ownership is transferred to the connection's DTLS_RX queue.
 * If routing fails, the URXE is released back to the demux.
 */
static void dtls_listener_packet_handler(DGRAM_URXE *urxe, void *arg)
{
    DTLS_LISTENER *dl = arg;
    SSL *conn_ssl = NULL;
    SSL_CONNECTION *sc = NULL;

    /*
     * Check established connections first
     */
    conn_ssl = ossl_dtls_listener_find_established_conn(dl, urxe);
    if (conn_ssl != NULL) {
        sc = SSL_CONNECTION_FROM_SSL_ONLY(conn_ssl);
        if (sc != NULL && sc->d1 != NULL && sc->d1->rx != NULL)
            goto inject;

        /* Fall through to release if injection failed */
        goto release;
    }

    /*
     * Check pending connections
     */
    conn_ssl = ossl_dgram_conn_lookup_find(dl->pending_conns, urxe);
    if (conn_ssl != NULL) {
        sc = SSL_CONNECTION_FROM_SSL_ONLY(conn_ssl);
        if (sc != NULL && sc->d1 != NULL && sc->d1->rx != NULL)
            goto inject;

        /* Fall through to release if injection failed */
        goto release;
    }

    /*
     * No existing connection so create a new pending connection.
     */
    conn_ssl = dtls_listener_create_conn_ssl(dl, &urxe->peer);
    if (conn_ssl == NULL)
        goto release;

    sc = SSL_CONNECTION_FROM_SSL_ONLY(conn_ssl);
    if (sc != NULL && sc->d1 != NULL && sc->d1->rx != NULL) {
        if (!ossl_dgram_conn_lookup_register(dl->pending_conns, urxe, conn_ssl)) {
            SSL_free(conn_ssl);
            goto release;
        }
    } else {
        SSL_free(conn_ssl);
        goto release;
    }

inject:
    ossl_dtls_rx_inject_urxe(sc->d1->rx, urxe);

    if (dl->have_notifier) {
#if defined(OPENSSL_THREADS)
        ossl_crypto_mutex_lock(dl->mutex);
#endif
        if (dl->cur_blocking_waiters > 0 && !dl->signalled_notifier) {
            ossl_rio_notifier_signal(&dl->notifier);
            dl->signalled_notifier = 1;
        }
#if defined(OPENSSL_THREADS)
        ossl_crypto_mutex_unlock(dl->mutex);
#endif
    }

    return;

release:
    ossl_dgram_demux_release_urxe(dl->demux, urxe);
}

/*
 * DTLS Listener Internal Cookie Callbacks
 *
 * These callbacks are used internally by the DTLS listener to generate and
 * verify cookies for address validation. They use HMAC-SHA256 with the
 * SSL_CTX's cookie_hmac_key to create cookies that bind to the client's
 * address.
 *
 * Cookie format:
 *   - 8 bytes: timestamp (seconds since epoch)
 *   - 32 bytes: HMAC-SHA256(timestamp || peer_address)
 *
 * Total cookie size: 40 bytes
 */
#define DTLS_LISTENER_COOKIE_TIMESTAMP_LEN 8
#define DTLS_LISTENER_COOKIE_HMAC_LEN 32
#define DTLS_LISTENER_COOKIE_LEN (DTLS_LISTENER_COOKIE_TIMESTAMP_LEN + DTLS_LISTENER_COOKIE_HMAC_LEN)

/* Maximum age of a cookie in seconds (default: 60 seconds) */
#define DTLS_LISTENER_COOKIE_MAX_AGE 60

/*
 * dtls_listener_get_time - get current time from the listener
 *
 * Returns the current time using the listener's time callback if set,
 * otherwise uses ossl_time_now().
 *
 * If ssl is not associated with a listener, returns ossl_time_now().
 */
static OSSL_TIME dtls_listener_get_time(SSL *ssl)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    DTLS_LISTENER *dl;

    if (sc == NULL || sc->d1 == NULL || sc->d1->listener == NULL)
        return ossl_time_now();

    dl = (DTLS_LISTENER *)sc->d1->listener;

    if (dl->now_cb == NULL)
        return ossl_time_now();

    return dl->now_cb(dl->now_cb_arg);
}

/*
 * dtls_listener_get_time_direct - get current time directly from listener
 *
 * Same as dtls_listener_get_time but takes the listener directly.
 * Used during connection creation before listener reference is fully set up.
 */
static OSSL_TIME dtls_listener_get_time_direct(DTLS_LISTENER *dl)
{
    if (dl == NULL)
        return ossl_time_now();

    if (dl->now_cb == NULL)
        return ossl_time_now();

    return dl->now_cb(dl->now_cb_arg);
}

/*
 * dtls_listener_cookie_hmac - compute HMAC for cookie validation
 *
 * Computes HMAC-SHA256(timestamp || port || raw_address) using the
 * context's cookie_hmac_key.
 *
 * Returns 1 on success, 0 on failure.
 */
static int dtls_listener_cookie_hmac(SSL *ssl, uint64_t timestamp,
    unsigned char *hmac_out)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_CTX *ctx;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM params[2];
    /* 8 (timestamp) + 2 (port) + max address size */
    unsigned char data[8 + sizeof(uint16_t) + 64];
    unsigned char addr_buf[64];
    size_t data_len = 0;
    size_t addr_len = 0;
    size_t hmac_len = DTLS_LISTENER_COOKIE_HMAC_LEN;
    uint16_t port;
    WPACKET pkt;
    int ret = 0;

    if (sc == NULL || sc->d1 == NULL)
        return 0;

    ctx = SSL_CONNECTION_GET_CTX(sc);
    if (ctx == NULL)
        return 0;

    /* Get port and raw address */
    port = BIO_ADDR_rawport(&sc->d1->peer_addr);

    if (!BIO_ADDR_rawaddress(&sc->d1->peer_addr, addr_buf, &addr_len))
        return 0;

    /* Build data to HMAC: timestamp || port || raw_address */
    if (!WPACKET_init_static_len(&pkt, data, sizeof(data), 0)
        || !WPACKET_put_bytes_u64(&pkt, timestamp)
        || !WPACKET_put_bytes_u16(&pkt, port)
        || !WPACKET_memcpy(&pkt, addr_buf, addr_len)
        || !WPACKET_get_total_written(&pkt, &data_len)
        || !WPACKET_finish(&pkt)) {
        WPACKET_cleanup(&pkt);
        return 0;
    }

    mac = EVP_MAC_fetch(ctx->libctx, "HMAC", ctx->propq);
    if (mac == NULL)
        goto err;

    mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL)
        goto err;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
        "SHA2-256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(mctx, ctx->ext.cookie_hmac_key,
            sizeof(ctx->ext.cookie_hmac_key), params))
        goto err;

    if (!EVP_MAC_update(mctx, data, data_len))
        goto err;

    if (!EVP_MAC_final(mctx, hmac_out, &hmac_len, hmac_len))
        goto err;

    ret = 1;

err:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    return ret;
}

/*
 * dtls_listener_gen_cookie_cb - internal HVR cookie generate callback
 *
 * Generates a cookie for HelloVerifyRequest (DTLS 1.2).
 * Cookie format: timestamp (8 bytes) || HMAC (32 bytes)
 */
static int dtls_listener_gen_cookie_cb(SSL *ssl, unsigned char *cookie,
    unsigned int *cookie_len)
{
    uint64_t now = ossl_time2seconds(dtls_listener_get_time(ssl));

    /* Write timestamp */
    cookie[0] = (unsigned char)(now >> 56);
    cookie[1] = (unsigned char)(now >> 48);
    cookie[2] = (unsigned char)(now >> 40);
    cookie[3] = (unsigned char)(now >> 32);
    cookie[4] = (unsigned char)(now >> 24);
    cookie[5] = (unsigned char)(now >> 16);
    cookie[6] = (unsigned char)(now >> 8);
    cookie[7] = (unsigned char)(now);

    /* Compute and append HMAC */
    if (!dtls_listener_cookie_hmac(ssl, now, cookie + DTLS_LISTENER_COOKIE_TIMESTAMP_LEN))
        return 0;

    *cookie_len = DTLS_LISTENER_COOKIE_LEN;
    return 1;
}

/*
 * dtls_listener_verify_cookie_cb - internal HVR cookie verify callback
 *
 * Verifies a cookie from ClientHello (DTLS 1.2).
 * Checks that:
 *   1. Cookie length is correct
 *   2. Timestamp is not too old
 *   3. HMAC matches
 */
static int dtls_listener_verify_cookie_cb(SSL *ssl, const unsigned char *cookie,
    unsigned int cookie_len)
{
    uint64_t cookie_time, now;
    unsigned char expected_hmac[DTLS_LISTENER_COOKIE_HMAC_LEN];

    if (cookie_len != DTLS_LISTENER_COOKIE_LEN)
        return 0;

    /* Extract timestamp from cookie */
    cookie_time = ((uint64_t)cookie[0] << 56)
        | ((uint64_t)cookie[1] << 48)
        | ((uint64_t)cookie[2] << 40)
        | ((uint64_t)cookie[3] << 32)
        | ((uint64_t)cookie[4] << 24)
        | ((uint64_t)cookie[5] << 16)
        | ((uint64_t)cookie[6] << 8)
        | ((uint64_t)cookie[7]);

    /* Check timestamp is not too old */
    now = ossl_time2seconds(dtls_listener_get_time(ssl));
    if (now > cookie_time && (now - cookie_time) > DTLS_LISTENER_COOKIE_MAX_AGE)
        return 0;

    /* Compute expected HMAC and compare */
    if (!dtls_listener_cookie_hmac(ssl, cookie_time, expected_hmac))
        return 0;

    if (CRYPTO_memcmp(cookie + DTLS_LISTENER_COOKIE_TIMESTAMP_LEN,
            expected_hmac, DTLS_LISTENER_COOKIE_HMAC_LEN)
        != 0)
        return 0;

    return 1;
}

/*
 * dtls_listener_gen_stateless_cookie_cb - internal HRR cookie generate callback
 *
 * Generates a cookie for HelloRetryRequest (DTLS 1.3).
 * Uses the same format as the HVR cookie.
 */
static int dtls_listener_gen_stateless_cookie_cb(SSL *ssl, unsigned char *cookie,
    size_t *cookie_len)
{
    uint64_t now = ossl_time2seconds(dtls_listener_get_time(ssl));

    /* Write timestamp */
    cookie[0] = (unsigned char)(now >> 56);
    cookie[1] = (unsigned char)(now >> 48);
    cookie[2] = (unsigned char)(now >> 40);
    cookie[3] = (unsigned char)(now >> 32);
    cookie[4] = (unsigned char)(now >> 24);
    cookie[5] = (unsigned char)(now >> 16);
    cookie[6] = (unsigned char)(now >> 8);
    cookie[7] = (unsigned char)(now);

    /* Compute and append HMAC */
    if (!dtls_listener_cookie_hmac(ssl, now, cookie + DTLS_LISTENER_COOKIE_TIMESTAMP_LEN))
        return 0;

    *cookie_len = DTLS_LISTENER_COOKIE_LEN;
    return 1;
}

/*
 * dtls_listener_verify_stateless_cookie_cb - internal HRR cookie verify callback
 *
 * Verifies a cookie from ClientHello (DTLS 1.3).
 * Uses the same verification logic as the HVR cookie.
 */
static int dtls_listener_verify_stateless_cookie_cb(SSL *ssl,
    const unsigned char *cookie,
    size_t cookie_len)
{
    uint64_t cookie_time, now;
    unsigned char expected_hmac[DTLS_LISTENER_COOKIE_HMAC_LEN];

    if (cookie_len != DTLS_LISTENER_COOKIE_LEN)
        return 0;

    /* Extract timestamp from cookie */
    cookie_time = ((uint64_t)cookie[0] << 56)
        | ((uint64_t)cookie[1] << 48)
        | ((uint64_t)cookie[2] << 40)
        | ((uint64_t)cookie[3] << 32)
        | ((uint64_t)cookie[4] << 24)
        | ((uint64_t)cookie[5] << 16)
        | ((uint64_t)cookie[6] << 8)
        | ((uint64_t)cookie[7]);

    /* Check timestamp is not too old */
    now = ossl_time2seconds(dtls_listener_get_time(ssl));
    if (now > cookie_time && (now - cookie_time) > DTLS_LISTENER_COOKIE_MAX_AGE)
        return 0;

    /* Compute expected HMAC and compare */
    if (!dtls_listener_cookie_hmac(ssl, cookie_time, expected_hmac))
        return 0;

    if (CRYPTO_memcmp(cookie + DTLS_LISTENER_COOKIE_TIMESTAMP_LEN,
            expected_hmac, DTLS_LISTENER_COOKIE_HMAC_LEN)
        != 0)
        return 0;

    return 1;
}

SSL *ossl_dtls_new_listener(SSL_CTX *ctx, uint64_t flags)
{
    DTLS_LISTENER *dl = NULL;
    int ssl_init_done = 0;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if ((dl = OPENSSL_zalloc(sizeof(*dl))) == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB);
        goto err;
    }

    /*
     * Use ossl_ssl_init to initialize the SSL object header consistently
     * with other SSL object types.
     */
    if (!ossl_ssl_init(&dl->ssl, ctx, ctx->method, SSL_TYPE_DTLS_LISTENER)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB);
        goto err;
    }
    ssl_init_done = 1;

#if defined(OPENSSL_THREADS)
    if ((dl->mutex = ossl_crypto_mutex_new()) == NULL)
        goto err;
    if ((dl->write_mutex = ossl_crypto_mutex_new()) == NULL)
        goto err;
#endif

    /* Create demux with internal locking for thread safety. */
    dl->demux = ossl_dgram_demux_new(NULL, 1, NULL, NULL);
    if (dl->demux == NULL)
        goto err;

    /* Set up the packet handler callback for routing datagrams to connections */
    ossl_dgram_demux_set_default_handler(dl->demux, dtls_listener_packet_handler, dl);

    dl->incoming_connections = sk_SSL_new_null();
    if (dl->incoming_connections == NULL)
        goto err;

    dl->pending_conns = ossl_dgram_conn_lookup_new_addr();
    if (dl->pending_conns == NULL)
        goto err;

    dl->established_conns = ossl_dgram_conn_lookup_new_addr();
    if (dl->established_conns == NULL)
        goto err;

    dl->net_rbio = NULL;
    dl->net_wbio = NULL;
    dl->listening = 0;
    dl->fatal = 0;

    /* Default timeout for pending connections: 30 seconds */
    dl->pending_timeout = ossl_seconds2time(30);

    /* Handle cookie validation flags */
    if ((flags & SSL_LISTENER_FLAG_NO_VALIDATE) == 0) {
        if (flags & SSL_LISTENER_FLAG_REQUIRE_HVR) {
            dl->require_hvr_cookie = 1;
            /*
             * Install internal cookie callbacks for HVR if the user hasn't
             * provided their own. This allows the listener to handle address
             * validation automatically.
             */
            if (ctx->app_gen_cookie_cb == NULL)
                ctx->app_gen_cookie_cb = dtls_listener_gen_cookie_cb;
            if (ctx->app_verify_cookie_cb == NULL)
                ctx->app_verify_cookie_cb = dtls_listener_verify_cookie_cb;
        }
        if (flags & SSL_LISTENER_FLAG_REQUIRE_HRR) {
            dl->require_hrr_cookie = 1;
            /*
             * Install internal stateless cookie callbacks for HRR if the user
             * hasn't provided their own.
             */
            if (ctx->gen_stateless_cookie_cb == NULL)
                ctx->gen_stateless_cookie_cb = dtls_listener_gen_stateless_cookie_cb;
            if (ctx->verify_stateless_cookie_cb == NULL)
                ctx->verify_stateless_cookie_cb = dtls_listener_verify_stateless_cookie_cb;
        }
    }

    dl->have_notifier = 0;
    dl->signalled_notifier = 0;
    dl->cur_blocking_waiters = 0;

    if ((flags & SSL_LISTENER_FLAG_MULTI_THREAD) != 0) {
        if (!ossl_rio_notifier_init(&dl->notifier))
            goto err;

        dl->notifier_cv = ossl_crypto_condvar_new();
        if (dl->notifier_cv == NULL) {
            ossl_rio_notifier_cleanup(&dl->notifier);
            goto err;
        }

        dl->have_notifier = 1;
    }

    return &dl->ssl;

err:
    if (dl == NULL)
        return NULL;

    if (dl->notifier_cv != NULL)
        ossl_crypto_condvar_free(&dl->notifier_cv);

    /*
     * If ossl_ssl_init succeeded, SSL_free handles all cleanup
     * including incoming_connections and OPENSSL_free(dl)
     * itself via ossl_dtls_listener_free. Otherwise ossl_ssl_init
     * did not run or partially failed, so we must free the raw
     * allocation directly.
     */
    if (ssl_init_done)
        SSL_free(&dl->ssl);
    else
        OPENSSL_free(dl);
    return NULL;
}

static void dtls_listener_connection_free(SSL *ssl)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (sc != NULL && sc->d1 != NULL) {
        /* Clear reference to listener before freeing */
        if (sc->d1->listener != NULL)
            sc->d1->listener = NULL;
    }
    SSL_free(ssl);
}

/*
 * Callback to free SSL objects in pending_conns hash table.
 * The pending_conns hash table owns the SSL objects it contains,
 * so we must free them before freeing the hash table itself.
 */
static void dtls_free_pending_ssl_cb(SSL *ssl, const BIO_ADDR *peer, void *arg)
{
    dtls_listener_connection_free(ssl);
}

void ossl_dtls_listener_free(SSL *s)
{
    DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return;

    dl = (DTLS_LISTENER *)s;

    /* Free any pending incoming connections */
    if (dl->incoming_connections != NULL) {
        while (sk_SSL_num(dl->incoming_connections) > 0) {
            SSL *conn = sk_SSL_pop(dl->incoming_connections);

            dtls_listener_connection_free(conn);
        }
        sk_SSL_free(dl->incoming_connections);
    }

    /*
     * Free all pending connections in the hash table.
     */
    if (dl->pending_conns != NULL) {
        ossl_dgram_conn_lookup_foreach(dl->pending_conns, dtls_free_pending_ssl_cb, NULL);
        ossl_dgram_conn_lookup_free(dl->pending_conns);
    }

    /* Free the demux after all connections that reference it are freed */
    if (dl->demux != NULL)
        ossl_dgram_demux_free(dl->demux);

    /* Free all established connections in the hash table (no SSL ownership) */
    if (dl->established_conns != NULL)
        ossl_dgram_conn_lookup_free(dl->established_conns);

    BIO_free_all(dl->net_wbio);
    BIO_free_all(dl->net_rbio);

    if (dl->have_notifier) {
        ossl_crypto_condvar_free(&dl->notifier_cv);
        ossl_rio_notifier_cleanup(&dl->notifier);
    }

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_free(&dl->write_mutex);
    ossl_crypto_mutex_free(&dl->mutex);
#endif
}

SSL *ossl_dtls_get0_listener(const SSL *ssl)
{
    if (!IS_DTLS_LISTENER(ssl))
        return NULL;

    return (SSL *)ssl;
}

/*
 * ossl_dtls_listen - start a DTLS listener accepting incoming connections.
 */
int ossl_dtls_listen(SSL *ssl)
{
    DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(ssl)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    dl = (DTLS_LISTENER *)ssl;

    /* Already listening is not an error. */
    if (dl->listening)
        return 1;

    dl->listening = 1;
    return 1;
}

/*
 * dtls_listener_conn_ready - check if connection is ready for accept queue.
 *
 * Determines whether the SSL object has completed cookie validation (if required)
 * or has received a valid ClientHello (if no validation) and is ready to be
 * moved to the incoming_connections queue.
 *
 * The connection is returned to the application BEFORE the handshake completes,
 * allowing the application to finish the handshake itself. This provides more
 * control over the handshake process.
 *
 * For HRR (DTLS 1.3 with validation): Ready when sc->ext.cookieok is set
 * For HVR (DTLS 1.2 with validation): Ready when sc->d1->cookie_verified is set
 * For no validation: Ready after receiving the first ClientHello
 *
 * Returns: 1 if ready, 0 if still in progress
 */
static int dtls_listener_conn_ready(SSL *ssl, DTLS_LISTENER *dl)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (sc == NULL)
        return 0;

    /*
     * No validation required (SSL_LISTENER_FLAG_NO_VALIDATE):
     * Ready immediately after receiving the first ClientHello.
     * The connection exists in pending_conns, so it's ready.
     */
    if (!dl->require_hrr_cookie && !dl->require_hvr_cookie)
        return 1;

    /*
     * For DTLS 1.3 with HRR requirement:
     * Ready when the cookie has been validated (second ClientHello received
     * with valid cookie after HRR was sent). The cookieok flag is set during
     * ClientHello processing when the HRR cookie is successfully verified.
     */
    if (dl->require_hrr_cookie && sc->ext.cookieok)
        return 1;

    /*
     * For DTLS 1.2 (and earlier) with HVR requirement:
     * Ready when the cookie has been validated (second ClientHello received
     * with valid cookie after HVR was sent). The cookie_verified flag is set
     * during ClientHello processing when the HVR cookie is successfully verified.
     */
    if (dl->require_hvr_cookie && sc->d1 != NULL && sc->d1->cookie_verified)
        return 1;

    /* Not ready yet - still waiting for cookie validation */
    return 0;
}

/*
 * dtls_listener_conn_needs_retry - check if connection is waiting for more data.
 *
 * Determines whether the SSL object has sent an HRR/HVR and is waiting
 * for the client's response.
 *
 * Returns: 1 if waiting for retry, 0 otherwise
 */
static int dtls_listener_conn_needs_retry(SSL *ssl)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (sc == NULL)
        return 0;

    /*
     * For DTLS 1.3: HRR has been sent, waiting for second ClientHello
     */
    if (sc->hello_retry_request == SSL_HRR_PENDING
        && !ossl_statem_in_error(sc))
        return 1;

    /*
     * For DTLS 1.2: Check if we're in a state that indicates HVR was sent.
     * The state machine will be waiting for the next ClientHello.
     */
    if (sc->statem.hand_state == DTLS_ST_SW_HELLO_VERIFY_REQUEST)
        return 1;

    return 0;
}

/*
 * Context for drive_pending iteration.
 */
typedef struct {
    DTLS_LISTENER *dl;
    int ready_count; /* Connections ready to move to established */
    int error_count; /* Connections with fatal errors */
    STACK_OF(SSL) *ready_conns; /* Connections to move */
    STACK_OF(SSL) *failed_conns; /* Connections to remove */
} DRIVE_PENDING_CTX;

/*
 * Callback for iterating pending connections and driving their handshakes.
 */
static void drive_pending_cb(SSL *ssl, const BIO_ADDR *peer, void *arg)
{
    DRIVE_PENDING_CTX *ctx = arg;
    DTLS_LISTENER *dl = ctx->dl;
    SSL_CONNECTION *sc;
    int ret, ssl_err;

    sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    if (sc == NULL)
        return;

    /*
     * Check if this connection has data in its DTLS_RX queue.
     * If not, skip it - no point driving a connection with no data.
     */
    if (sc->d1 == NULL || sc->d1->rx == NULL)
        return;

    /*
     * Check if this pending connection has exceeded the timeout.
     * Stale connections that haven't completed their handshake are removed
     * to prevent resource exhaustion from incomplete handshakes.
     */
    if (!ossl_time_is_infinite(dl->pending_timeout)) {
        OSSL_TIME now = dtls_listener_get_time_direct(dl);
        OSSL_TIME age = ossl_time_subtract(now, sc->d1->created_at);

        if (ossl_time_compare(age, dl->pending_timeout) > 0) {
            /* Connection has timed out - mark for removal */
            if (ctx->failed_conns != NULL)
                sk_SSL_push(ctx->failed_conns, ssl);
            ctx->error_count++;
            return;
        }
    }

    /*
     * HRR State Reset for DTLS 1.3:
     *
     * When the server sends a HelloRetryRequest (HRR), it processes the first
     * ClientHello which sets internal state (e.g., s->s3.peer_tmp from parsing
     * the key_share extension). When the second ClientHello arrives, this state
     * must be cleared or tls_parse_ctos_key_share() will fail with an internal
     * error because it expects peer_tmp to be NULL.
     *
     * SSL_clear() resets handshake state including peer_tmp, but also resets
     * things we need to preserve:
     *   - Handshake sequence numbers: The second ClientHello has msg_seq=1,
     *     so handshake_read_seq must be 1 to accept it (not 0)
     *   - Record layer sequence numbers: For proper DTLS record handling
     *   - Write BIO: SSL_clear() frees it, but we need it to send responses
     */
    if (sc->hello_retry_request == SSL_HRR_PENDING
        && !ossl_statem_in_error(sc)) {
        uint16_t handshake_read_seq = sc->d1->handshake_read_seq;
        uint16_t next_handshake_write_seq = sc->d1->next_handshake_write_seq;
        uint64_t rl_read_seq = 0, rl_write_seq = 0;
        BIO *wbio = SSL_get_wbio(ssl);

        /* Save record layer sequences */
        if (sc->rlayer.rrlmethod != NULL
            && sc->rlayer.rrlmethod->get_sequence != NULL
            && sc->rlayer.wrlmethod != NULL
            && sc->rlayer.wrlmethod->get_sequence != NULL) {
            if (!sc->rlayer.rrlmethod->get_sequence(sc->rlayer.rrl, &rl_read_seq)
                || !sc->rlayer.wrlmethod->get_sequence(sc->rlayer.wrl, &rl_write_seq)) {
                /* Failed to get sequences - mark as error */
                if (ctx->failed_conns != NULL)
                    sk_SSL_push(ctx->failed_conns, ssl);
                ctx->error_count++;
                return;
            }
        }

        /* Up-ref wbio before SSL_clear frees it */
        if (wbio != NULL && !BIO_up_ref(wbio)) {
            if (ctx->failed_conns != NULL)
                sk_SSL_push(ctx->failed_conns, ssl);
            ctx->error_count++;
            return;
        }

        /* Clear state (dtls1_clear preserves peer_addr, rx, listener, created_at) */
        if (!SSL_clear(ssl)) {
            BIO_free(wbio);
            if (ctx->failed_conns != NULL)
                sk_SSL_push(ctx->failed_conns, ssl);
            ctx->error_count++;
            return;
        }

        /* Restore wbio (rbio stays NULL for listener connections) */
        SSL_set0_wbio(ssl, wbio);

        /* Restore sequences for second ClientHello */
        sc->d1->handshake_read_seq = handshake_read_seq;
        sc->d1->next_handshake_write_seq = next_handshake_write_seq;

        if (sc->rlayer.rrlmethod != NULL
            && sc->rlayer.rrlmethod->set_sequence != NULL
            && sc->rlayer.wrlmethod != NULL
            && sc->rlayer.wrlmethod->set_sequence != NULL) {
            if (!sc->rlayer.rrlmethod->set_sequence(sc->rlayer.rrl, rl_read_seq)
                || !sc->rlayer.wrlmethod->set_sequence(sc->rlayer.wrl, rl_write_seq)) {
                if (ctx->failed_conns != NULL)
                    sk_SSL_push(ctx->failed_conns, ssl);
                ctx->error_count++;
                return;
            }
        }
    }

    /*
     * Drive the state machine with SSL_accept().
     *
     * We MUST set TLS1_FLAGS_STATELESS to prevent the state machine from
     * calling SSL_clear() when entering the handshake.
     *
     * Without the flag, the state machine in state_machine() calls SSL_clear()
     * when SSL_in_before() is true, which wipes out our restored state.
     */
    if (dl->require_hrr_cookie || dl->require_hvr_cookie)
        sc->s3.flags |= TLS1_FLAGS_STATELESS;

    ret = SSL_accept(ssl);

    /*
     * Always clear the stateless flag after SSL_accept() completes.
     */
    if (dl->require_hrr_cookie || dl->require_hvr_cookie)
        sc->s3.flags &= ~TLS1_FLAGS_STATELESS;

    /* Check if connection is ready to move to established */
    if (dtls_listener_conn_ready(ssl, dl)) {
        if (ctx->ready_conns != NULL)
            sk_SSL_push(ctx->ready_conns, ssl);
        ctx->ready_count++;
        return;
    }

    /* Check if connection needs retry (HRR/HVR sent) */
    if (dtls_listener_conn_needs_retry(ssl))
        return;

    /* Check SSL error */
    ssl_err = SSL_get_error(ssl, ret);

    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
        /* Handshake in progress, needs more data - keep pending */
        return;
    }

    /* Fatal error on this connection - mark for removal */
    if (ssl_err == SSL_ERROR_SYSCALL || ssl_err == SSL_ERROR_SSL) {
        if (ctx->failed_conns != NULL)
            sk_SSL_push(ctx->failed_conns, ssl);
        ctx->error_count++;
    }
}

/*
 * dtls_listener_drive_pending - drive handshakes for all pending connections.
 *
 * Iterates through pending connections and calls SSL_accept() to advance
 * their handshakes. Connections that complete successfully are moved to
 * established_conns and added to the incoming queue.
 *
 * Returns:
 *   1   At least one connection was moved to incoming_connections
 *   0   No connections completed (all still pending or failed)
 *  -1   Fatal error
 */
static int dtls_listener_drive_pending(DTLS_LISTENER *dl)
{
    DRIVE_PENDING_CTX ctx;
    SSL *ssl;
    SSL_CONNECTION *sc;
    int i, result = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.dl = dl;
    ctx.ready_conns = sk_SSL_new_null();
    ctx.failed_conns = sk_SSL_new_null();

    if (ctx.ready_conns == NULL || ctx.failed_conns == NULL) {
        sk_SSL_free(ctx.ready_conns);
        sk_SSL_free(ctx.failed_conns);
        return -1;
    }

    /* Drive all pending connections */
    ossl_dgram_conn_lookup_foreach(dl->pending_conns, drive_pending_cb, &ctx);

    /* Move ready connections to established and incoming queue */
    for (i = 0; i < sk_SSL_num(ctx.ready_conns); i++) {
        ssl = sk_SSL_value(ctx.ready_conns, i);
        sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

        if (sc == NULL || sc->d1 == NULL)
            continue;

        /* Get peer address from the connection */
        if (BIO_ADDR_family(&sc->d1->peer_addr) != AF_UNSPEC) {

            /* Remove from pending */
            ossl_dgram_conn_lookup_unregister(dl->pending_conns, &sc->d1->peer_addr);

            /* Add to established connections (uses locking API) */
            if (!ossl_dtls_listener_register_established_conn(dl, &sc->d1->peer_addr, ssl)) {
                dtls_listener_connection_free(ssl);
                continue;
            }

            /* Add to incoming queue */
            if (sk_SSL_push(dl->incoming_connections, ssl) > 0) {
                result = 1;
            } else {
                /* Failed to add to queue, unregister and free */
                ossl_dtls_listener_unregister_established_conn(&dl->ssl, &sc->d1->peer_addr);
                dtls_listener_connection_free(ssl);
            }
        }
    }

    /* Remove failed connections */
    for (i = 0; i < sk_SSL_num(ctx.failed_conns); i++) {
        ssl = sk_SSL_value(ctx.failed_conns, i);
        sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

        if (sc != NULL && sc->d1 != NULL)
            ossl_dgram_conn_lookup_unregister(dl->pending_conns, &sc->d1->peer_addr);

        dtls_listener_connection_free(ssl);
    }

    sk_SSL_free(ctx.ready_conns);
    sk_SSL_free(ctx.failed_conns);

    return result;
}

/*
 * ossl_dtls_tick - drive one iteration of the DTLS listener I/O loop.
 *
 * Uses the demux pump/callback architecture for efficient packet handling:
 *   1. Call ossl_dgram_demux_pump() to read datagrams from the network
 *   2. The demux invokes dtls_listener_packet_handler() for each datagram
 *   3. The handler routes URXEs to connections (established or pending)
 *   4. Drive handshakes for pending connections
 *   5. Move completed connections to established_conns and incoming queue
 *
 * Return values:
 *   1   A verified connection was pushed onto dl->incoming_connections.
 *   0   Exchange incomplete (HRR/HVR sent, or no data yet); call again.
 *  -1   Fatal error; dl->fatal is set.
 */
int ossl_dtls_tick(DTLS_LISTENER *dl)
{
    int pump_ret;

    if (dl->net_rbio == NULL)
        return 0;

    /*
     * Get datagrams from the network and route them to connections.
     */
    pump_ret = ossl_dgram_demux_pump(dl->demux);

    if (pump_ret == DGRAM_DEMUX_PUMP_RES_PERMANENT_FAIL) {
        /* Fatal BIO or allocation error */
        dl->fatal = 1;
        return -1;
    }

    /*
     * Drive Handshakes for pending connections.
     * call even if pump_ret indicates no data or temporary failure,
     * to allow handshakes to progress even when no new data is arriving
     */
    return dtls_listener_drive_pending(dl);
}

SSL *ossl_dtls_accept_connection(SSL *ssl, uint64_t flags)
{
    DTLS_LISTENER *dl;
    SSL *conn = NULL;
    SSL_CONNECTION *sc = NULL;
    int no_block = ((flags & SSL_ACCEPT_CONNECTION_NO_BLOCK) != 0);

    if (!IS_DTLS_LISTENER(ssl)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    dl = (DTLS_LISTENER *)ssl;

    if (!ossl_dtls_listen(ssl))
        return NULL;

    /* If a previous tick produced a fatal BIO error, do not try again. */
    if (dl->fatal)
        return NULL;

    /* Fast path: return any already-queued connection immediately. */
    conn = sk_SSL_shift(dl->incoming_connections);
    if (conn != NULL)
        goto end;

    if (no_block) {
        /*
         * Non-blocking: run one tick to drain any pending datagram, then
         * return whatever is in the queue
         */
        if (dl->net_rbio != NULL) {
            if (ossl_dtls_tick(dl) < 0)
                return NULL;
        }
        conn = sk_SSL_shift(dl->incoming_connections);
        goto end;
    }

    /* Blocking path: we need a BIO to make any progress. */
    if (dl->net_rbio == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_BIO_NOT_SET);
        return NULL;
    }

    /*
     * Loop calling ossl_dtls_tick() until a verified connection arrives or
     * a fatal error occurs.  Each tick blocks inside BIO_read() until
     * a datagram is received, so this loop does not spin.
     */
    for (;;) {
        if (ossl_dtls_tick(dl) < 0)
            break; /* fatal BIO error */

        conn = sk_SSL_shift(dl->incoming_connections);
        if (conn != NULL)
            break;
    }

end:
    if (conn != NULL) {
        sc = SSL_CONNECTION_FROM_SSL(conn);
        if (sc == NULL || sc->d1 == NULL || !SSL_up_ref(sc->d1->listener)) {
            dtls_listener_connection_free(conn);
            return NULL;
        }
    }
    return conn;
}

void ossl_dtls_listener_set0_net_rbio(SSL *s, BIO *bio)
{
    DTLS_LISTENER *dl;
    BIO *old_rbio;

    if (!IS_DTLS_LISTENER(s))
        return;

    dl = (DTLS_LISTENER *)s;
    ossl_dgram_demux_set_bio(dl->demux, bio);

    old_rbio = dl->net_rbio;

    /* No change - nothing to do */
    if (old_rbio == bio)
        return;

    dl->net_rbio = bio;

    /* Free the old BIO now that we've taken ownership of the new one */
    BIO_free_all(old_rbio);

    /*
     * Any pending/established connections hold references to the old BIO.
     * Clear them so the next tick starts fresh with the new BIO.
     * The pending_conns hash table owns the SSL objects, so free them first.
     */
    if (dl->pending_conns != NULL) {
        ossl_dgram_conn_lookup_foreach(dl->pending_conns, dtls_free_pending_ssl_cb, NULL);
        ossl_dgram_conn_lookup_free(dl->pending_conns);
    }
    dl->pending_conns = ossl_dgram_conn_lookup_new_addr();

    /* Clear established_conns (uses locking API) */
    ossl_dtls_listener_clear_established_conns(dl);

    /*
     * incoming_connections also holds SSL objects that reference the old BIO.
     * Free them as they are no longer valid with the new BIO.
     */
    if (dl->incoming_connections != NULL) {
        while (sk_SSL_num(dl->incoming_connections) > 0) {
            SSL *conn = sk_SSL_pop(dl->incoming_connections);
            dtls_listener_connection_free(conn);
        }
    }
}

void ossl_dtls_listener_set0_net_wbio(SSL *s, BIO *bio)
{
    DTLS_LISTENER *dl;
    BIO *old_wbio;

    if (!IS_DTLS_LISTENER(s))
        return;

    dl = (DTLS_LISTENER *)s;
    old_wbio = dl->net_wbio;

    /* No change - nothing to do */
    if (old_wbio == bio)
        return;

    dl->net_wbio = bio;

    /* Free the old BIO now that we've taken ownership of the new one */
    BIO_free_all(old_wbio);
}

BIO *ossl_dtls_listener_get_net_rbio(const SSL *s)
{
    const DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return NULL;

    dl = (const DTLS_LISTENER *)s;

    return dl->net_rbio;
}

BIO *ossl_dtls_listener_get_net_wbio(const SSL *s)
{
    const DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return NULL;

    dl = (const DTLS_LISTENER *)s;

    return dl->net_wbio;
}

/*
 * Established connections API - these handle their own locking.
 *
 * The established_conns lookup table is accessed from multiple threads:
 * - Listener thread: looking up and registering connections
 * - Connection thread: unregistering via SSL_free -> dtls1_free
 */

/*
 * ossl_dtls_listener_find_established_conn - find an established connection.
 *
 * Looks up a connection in the established_conns table by peer address.
 * Returns the SSL connection if found, NULL otherwise.
 */
SSL *ossl_dtls_listener_find_established_conn(DTLS_LISTENER *dl,
    const DGRAM_URXE *urxe)
{
    SSL *result = NULL;

    if (dl == NULL || urxe == NULL)
        return NULL;

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_lock(dl->mutex);
#endif

    if (dl->established_conns != NULL)
        result = ossl_dgram_conn_lookup_find(dl->established_conns, urxe);

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_unlock(dl->mutex);
#endif
    return result;
}

/*
 * ossl_dtls_listener_register_established_conn - register an established connection.
 *
 * Adds a connection to the established_conns table for packet routing.
 * Returns 1 on success, 0 on failure.
 */
int ossl_dtls_listener_register_established_conn(DTLS_LISTENER *dl,
    const BIO_ADDR *peer,
    SSL *ssl)
{
    int result = 0;

    if (dl == NULL || peer == NULL || ssl == NULL)
        return 0;

    if (BIO_ADDR_family(peer) == AF_UNSPEC)
        return 0;

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_lock(dl->mutex);
#endif

    if (dl->established_conns != NULL)
        result = ossl_dgram_conn_lookup_register_addr(dl->established_conns,
            peer, ssl);

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_unlock(dl->mutex);
#endif
    return result;
}

/*
 * ossl_dtls_listener_unregister_established_conn - unregister an established
 * connection from the listener.
 *
 * Called when a DTLS connection created by this listener is being freed.
 */
void ossl_dtls_listener_unregister_established_conn(SSL *s, const BIO_ADDR *peer_addr)
{
    DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return;

    if (peer_addr == NULL || BIO_ADDR_family(peer_addr) == AF_UNSPEC)
        return;

    dl = (DTLS_LISTENER *)s;

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_lock(dl->mutex);
#endif

    if (dl->established_conns != NULL)
        ossl_dgram_conn_lookup_unregister(dl->established_conns, peer_addr);

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_unlock(dl->mutex);
#endif
}

/*
 * ossl_dtls_listener_clear_established_conns - clear and recreate the
 * established_conns table.
 */
void ossl_dtls_listener_clear_established_conns(DTLS_LISTENER *dl)
{
    if (dl == NULL)
        return;

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_lock(dl->mutex);
#endif

    if (dl->established_conns != NULL)
        ossl_dgram_conn_lookup_free(dl->established_conns);
    dl->established_conns = ossl_dgram_conn_lookup_new_addr();

#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_unlock(dl->mutex);
#endif
}

size_t ossl_dtls_get_accept_connection_queue_len(SSL *ssl)
{
    DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(ssl))
        return 0;

    dl = (DTLS_LISTENER *)ssl;

    return (size_t)sk_SSL_num(dl->incoming_connections);
}

/*
 * Set an override time callback for the DTLS listener.
 * This is primarily for testing purposes to allow time injection.
 * If now_cb is NULL, the listener will use ossl_time_now().
 */
int ossl_dtls_listener_set_override_now_cb(SSL *s,
    OSSL_TIME (*now_cb)(void *arg),
    void *now_cb_arg)
{
    DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return 0;

    dl = (DTLS_LISTENER *)s;
    dl->now_cb = now_cb;
    dl->now_cb_arg = now_cb_arg;

    return 1;
}

/*
 * Set the pending connection timeout for the DTLS listener.
 *
 * Connections that haven't completed their handshake within this duration
 * are considered stale and will be cleaned up. This helps prevent resource
 * exhaustion from abandoned or slow connections.
 *
 * Parameters:
 *   s       - The DTLS listener SSL object
 *   timeout - The timeout duration. Use ossl_time_infinite() to disable timeout.
 *             Use ossl_time_zero() or a negative duration for invalid input (returns 0).
 *
 * Returns:
 *   1 on success
 *   0 on failure (NULL pointer, not a listener, or invalid timeout)
 */
int ossl_dtls_listener_set_pending_timeout(SSL *s, OSSL_TIME timeout)
{
    DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return 0;

    dl = (DTLS_LISTENER *)s;
    dl->pending_timeout = timeout;

    return 1;
}

/*
 * Get the current pending connection timeout for the DTLS listener.
 *
 * Returns:
 *   The current timeout duration, or ossl_time_zero() if s is NULL or not a listener.
 */
OSSL_TIME ossl_dtls_listener_get_pending_timeout(const SSL *s)
{
    const DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return ossl_time_zero();

    dl = (const DTLS_LISTENER *)s;
    return dl->pending_timeout;
}

void ossl_dtls_listener_enter_blocking_section(SSL *s)
{
    DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return;

    dl = (DTLS_LISTENER *)s;

    if (dl->have_notifier)
        dl->cur_blocking_waiters++;
}

void ossl_dtls_listener_leave_blocking_section(SSL *s)
{
    DTLS_LISTENER *dl;

    if (!IS_DTLS_LISTENER(s))
        return;

    dl = (DTLS_LISTENER *)s;

    if (dl->have_notifier) {
        assert(dl->cur_blocking_waiters > 0);
        --dl->cur_blocking_waiters;

        if (dl->signalled_notifier) {
#if defined(OPENSSL_THREADS)
            if (dl->cur_blocking_waiters == 0) {
                ossl_rio_notifier_unsignal(&dl->notifier);
                dl->signalled_notifier = 0;

                /*
                 * Release the other threads which have woken up
                 */
                ossl_crypto_condvar_broadcast(dl->notifier_cv);
            } else {
                /* We are not the last waiter out - so wait for that one. */
                while (dl->signalled_notifier)
                    /* Using the existing DTLS Listener mutex here */
                    ossl_crypto_condvar_wait(dl->notifier_cv, dl->mutex);
            }
#else
            ossl_rio_notifier_unsignal(&dl->notifier);
            dl->signalled_notifier = 0;
#endif
        }
    }
}

int ossl_dtls_listener_poll_events(SSL *s, uint64_t events, int do_tick,
    uint64_t *revents)
{
    DTLS_LISTENER *dl;
    uint64_t result = 0;

    if (!ossl_assert(IS_DTLS_LISTENER(s)))
        return 0;

    dl = (DTLS_LISTENER *)s;

    if (do_tick)
        ossl_dtls_tick(dl);

    if ((events & SSL_POLL_EVENT_IC) != 0) {
        if (SSL_get_accept_connection_queue_len(s) > 0)
            result |= SSL_POLL_EVENT_IC;
    }

    if ((events & SSL_POLL_EVENT_R) != 0) {
        BIO *rbio = SSL_get_rbio(s);
        if (rbio != NULL && BIO_pending(rbio) > 0)
            result |= SSL_POLL_EVENT_R;
    }

    *revents = result;
    return 1;
}

int ossl_dtls_conn_poll_events(SSL *s, uint64_t events, int do_tick,
    uint64_t *revents)
{
    SSL_CONNECTION *sc;
    uint64_t result = 0;

    sc = SSL_CONNECTION_FROM_SSL(s);
    if (sc == NULL || sc->d1 == NULL)
        return 0;

    /*
     * For DTLS connections that came from a listener, data arrives via
     * URXEs injected by the listener's demux. When do_tick is set and
     * we have a listener reference, pump the demux to get new data.
     */
    if (do_tick && sc->d1->listener != NULL) {
        DTLS_LISTENER *dl = (DTLS_LISTENER *)sc->d1->listener;
        ossl_dtls_tick(dl);
    }

    if ((events & SSL_POLL_EVENT_R) != 0) {
        if (SSL_has_pending(s) || SSL_pending(s) > 0) {
            result |= SSL_POLL_EVENT_R;
        } else if (sc->d1->rx != NULL) {
            /* Listener-based connection: check URXE queue */
            if (!ossl_list_urxe_is_empty(&sc->d1->rx->urxe_pending))
                result |= SSL_POLL_EVENT_R;
        } else {
            /*
             * Standalone DTLS SSL object (not from a listener).
             * Check the underlying socket for readability.
             */
            BIO *rbio = SSL_get_rbio(s);

            if (rbio != NULL) {
                if ((BIO_method_type(rbio) & BIO_TYPE_DESCRIPTOR) != 0) {
                    int fd = BIO_get_fd(rbio, NULL);
                    if (fd >= 0 && BIO_socket_ready(fd, 1) > 0)
                        result |= SSL_POLL_EVENT_R;
                } else {
                    /* Checking non-socket BIO */
                    if (BIO_pending(rbio) > 0)
                        result |= SSL_POLL_EVENT_R;
                }
            }
        }
    }

    if ((events & SSL_POLL_EVENT_W) != 0) {
        result |= SSL_POLL_EVENT_W;
    }

    if ((events & (SSL_POLL_EVENT_EC | SSL_POLL_EVENT_F)) != 0) {
        if (SSL_get_error(s, 0) == SSL_ERROR_SSL || SSL_get_shutdown(s) != 0)
            result |= SSL_POLL_EVENT_EC;
    }

    *revents = result;
    return 1;
}

#endif /* !OPENSSL_NO_DTLS && !OPENSSL_NO_SOCK */
