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
#include "ssl_local.h"
#include "internal/time.h"
#include "internal/ssl_unwrap.h"

static int dtls1_handshake_write(SSL_CONNECTION *s);
static size_t dtls1_link_min_mtu(void);

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
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL)
        return;

    if (s->d1 != NULL)
        dtls1_clear_queues(s);

    DTLS_RECORD_LAYER_free(&s->rlayer);
    ssl3_free(ssl);
    OPENSSL_free(s->d1);
    s->d1 = NULL;
}

int dtls1_clear(SSL *ssl)
{
    size_t mtu;
    size_t link_mtu;

    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL)
        return 0;

    DTLS_RECORD_LAYER_clear(&s->rlayer);

    if (s->d1) {
        DTLS_timer_cb timer_cb = s->d1->timer_cb;

        mtu = s->d1->mtu;
        link_mtu = s->d1->link_mtu;

        dtls1_clear_queues(s);

        memset(s->d1, 0, sizeof(*s->d1));

        /* Restore the timer callback from previous state */
        s->d1->timer_cb = timer_cb;

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
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

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
    if (BIO_dgram_is_sctp(SSL_get_wbio(ssl))) {
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
#define LISTEN_SEND_HELLO_RETRY_REQUEST 3

#ifndef OPENSSL_NO_SOCK
/* The HelloRetryRequest sentinel random value from RFC 8446 s4.1.3 */
extern const unsigned char hrrrandom[];

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
    PACKET ciphers, compmeths, extensions, ext_data;
    int dtls13;
    unsigned char hrr_cookie[SSL_COOKIE_LENGTH];
    size_t hrr_cookie_len;
    const SSL_CIPHER *hrr_cipher = NULL;
    unsigned int ext_type;
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
         * Scan the extensions in the ClientHello to determine whether the
         * client supports DTLS 1.3, and if so whether a TLS 1.3 cookie
         * extension is present.
         */
        dtls13 = 0;
        hrr_cookie_len = 0;
        memset(&ciphers, 0, sizeof(ciphers));

        if (PACKET_get_length_prefixed_2(&msgpayload, &ciphers)
            && PACKET_remaining(&ciphers) > 0
            && PACKET_get_length_prefixed_1(&msgpayload, &compmeths)
            && PACKET_remaining(&compmeths) > 0
            && PACKET_get_length_prefixed_2(&msgpayload, &extensions)) {
            while (PACKET_remaining(&extensions) > 0) {
                if (!PACKET_get_net_2(&extensions, &ext_type)
                    || !PACKET_get_length_prefixed_2(&extensions,
                        &ext_data))
                    break;
                if (ext_type == TLSEXT_TYPE_supported_versions) {
                    /*
                     * supported_versions in a ClientHello is a
                     * ProtocolVersion list prefixed with a 1-byte length.
                     */
                    PACKET sv_list;
                    unsigned int sv;

                    if (!PACKET_get_length_prefixed_1(&ext_data, &sv_list))
                        break;
                    while (PACKET_get_net_2(&sv_list, &sv)) {
                        if (sv == DTLS1_3_VERSION) {
                            dtls13 = 1;
                            break;
                        }
                    }
                } else if (ext_type == TLSEXT_TYPE_cookie) {
                    /*
                     * TLS 1.3 cookie extension: 2-byte length-prefixed
                     * cookie value. Save it for DTLS 1.3 verification.
                     */
                    PACKET cookie_data;

                    if (PACKET_get_length_prefixed_2(&ext_data,
                            &cookie_data)
                        && PACKET_remaining(&cookie_data) <= SSL_COOKIE_LENGTH) {
                        hrr_cookie_len = PACKET_remaining(&cookie_data);
                        memcpy(hrr_cookie, PACKET_data(&cookie_data),
                            hrr_cookie_len);
                    }
                }
            }
        }

        /*
         * Check if we have a cookie or not. If not we need to send a
         * HelloVerifyRequest (DTLS <= 1.2) or HelloRetryRequest (DTLS 1.3).
         *
         * We take the HRR path if gen_stateless_cookie_cb is set AND the
         * legacy cookie field is empty AND dtls13==1 (supported_versions
         * extension was parsed and indicates DTLS 1.3 support).
         *
         * Note: Fragmented DTLS 1.3 ClientHellos are rejected earlier with
         * SSL_R_FRAGMENTED_CLIENT_HELLO because we cannot compute the
         * transcript hash without the full message.
         *
         * If the legacy cookie is non-empty we always go through the legacy
         * HelloVerifyRequest path, even if stateless callbacks are registered,
         * so that a DTLS <= 1.2 client with a legacy cookie is handled correctly.
         *
         * If gen_stateless_cookie_cb is NULL we fall through to the legacy
         * HelloVerifyRequest path, allowing callers that only set the legacy
         * callbacks to continue working.
         */
        if (ssl->ctx->gen_stateless_cookie_cb != NULL
            && PACKET_remaining(&cookiepkt) == 0) {
            if (hrr_cookie_len > 0) {
                if (ssl->ctx->verify_stateless_cookie_cb == NULL) {
                    ERR_raise(ERR_LIB_SSL, SSL_R_NO_VERIFY_COOKIE_CALLBACK);
                    /* This is fatal */
                    ret = -1;
                    goto end;
                }
                if (ssl->ctx->verify_stateless_cookie_cb(ssl, hrr_cookie,
                        hrr_cookie_len)
                    == 0) {
                    next = LISTEN_SEND_HELLO_RETRY_REQUEST;
                } else {
                    next = LISTEN_SUCCESS;
                }
            } else {
                /*
                 * No TLS cookie found. If msgseq == 1, this is a response to
                 * our previous HRR, so the client should have included a cookie.
                 * If we can't find it (likely due to fragmentation), we must
                 * not send another HRR or we'll create an infinite loop.
                 */
                if (msgseq == 1) {
                    ERR_raise(ERR_LIB_SSL, SSL_R_COOKIE_MISMATCH);
                    ret = -1;
                    goto end;
                }
                next = LISTEN_SEND_HELLO_RETRY_REQUEST;
            }
        } else if (PACKET_remaining(&cookiepkt) == 0) {
            next = LISTEN_SEND_VERIFY_REQUEST;
        } else {
            /*
             * DTLS <= 1.2: verify via the legacy app cookie callback.
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
-                * per RFC6347
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

        if (next == LISTEN_SEND_HELLO_RETRY_REQUEST) {
            WPACKET wpkt;
            size_t wreclen;
            unsigned int hrr_cipher_id = 0;
            unsigned int cipher_id;
            STACK_OF(SSL_CIPHER) *srvr_ciphers = SSL_get_ciphers(ssl);
            PACKET ciphers_copy = ciphers;
            size_t hrr_body_len;
            const unsigned char *hrr_start = NULL;
            const EVP_MD *md;
            EVP_MD_CTX *ctx;
            unsigned int hash_size;

            /*
             * DTLS 1.3 requires the transcript hash to include the full
             * ClientHello1. DTLSv1_listen() is stateless and cannot reassemble
             * fragments, so if the ClientHello is fragmented we cannot compute
             * the correct transcript hash. The handshake would fail later with
             * a transcript mismatch.
             *
             * This is a fundamental limitation: DTLSv1_listen() cannot support
             * DTLS 1.3 with fragmented ClientHellos. Applications using large
             * key exchanges (e.g., post-quantum ML-KEM) that cause fragmentation
             * must use SSL_accept() directly instead of DTLSv1_listen().
             */
            if (fraglen < msglen) {
                ERR_raise(ERR_LIB_SSL, SSL_R_FRAGMENTED_CLIENT_HELLO);
                ret = -1;
                goto end;
            }
            /*
             * Select the best mutually supported TLS 1.3 cipher from the
             * client's cipher list.  We walk ciphers (which holds the raw
             * 2-byte cipher IDs offered by the client) and for each one:
             *   1. Look it up with SSL_CIPHER_find().
             *   2. Skip it if it is not a TLS 1.3 cipher (min_tls != TLS1_3_VERSION).
             *   3. Skip it if the server does not have it enabled.
             * We pick the first match (client-preference order), if no match
             * we exit with an error
             */

            while (PACKET_get_net_2(&ciphers_copy, &cipher_id)) {
                unsigned char client_cipher_id[2];
                const SSL_CIPHER *cipher;

                client_cipher_id[0] = (unsigned char)(cipher_id >> 8);
                client_cipher_id[1] = (unsigned char)(cipher_id & 0xff);
                cipher = SSL_CIPHER_find(ssl, client_cipher_id);
                if (cipher == NULL)
                    continue;
                /* Only TLS 1.3 ciphersuites are valid in an HRR */
                if (cipher->min_tls != TLS1_3_VERSION)
                    continue;
                /* Confirm the server has this cipher enabled */
                if (srvr_ciphers != NULL
                    && sk_SSL_CIPHER_find(srvr_ciphers, cipher) < 0)
                    continue;
                /* Found a mutually acceptable TLS 1.3 cipher */
                hrr_cipher = cipher;
                hrr_cipher_id = cipher_id;
                break;
            }

            if (hrr_cipher_id == 0) {
                /*
                 * No mutually acceptable TLS 1.3 cipher was found.
                 * Since fragmented ClientHellos are rejected earlier,
                 * we know the cipher list was present but had no match.
                 */
                ERR_raise(ERR_LIB_SSL, SSL_R_NO_SHARED_CIPHER);
                ret = -1;
                goto end;
            }

            /* Generate the stateless cookie via the TLS 1.3 callback */
            if (ssl->ctx->gen_stateless_cookie_cb == NULL) {
                ERR_raise(ERR_LIB_SSL, SSL_R_NO_COOKIE_CALLBACK_SET);
                ret = -1;
                goto end;
            }
            hrr_cookie_len = SSL_COOKIE_LENGTH;
            if (ssl->ctx->gen_stateless_cookie_cb(ssl, hrr_cookie,
                    &hrr_cookie_len)
                == 0) {
                ERR_raise(ERR_LIB_SSL, SSL_R_COOKIE_GEN_CALLBACK_FAILURE);
                ret = -1;
                goto end;
            }

            if (!WPACKET_init_static_len(&wpkt, wbuf,
                    ssl_get_max_send_fragment(s) + DTLS1_RT_HEADER_LENGTH, 0)
                /* Record header */
                || !WPACKET_put_bytes_u8(&wpkt, SSL3_RT_HANDSHAKE)
                || !WPACKET_put_bytes_u16(&wpkt, DTLS1_2_VERSION)
                || !WPACKET_memcpy(&wpkt, seq, SEQ_NUM_SIZE)
                /* Record body length (filled by sub-packet close) */
                || !WPACKET_start_sub_packet_u16(&wpkt)
                /* Handshake message type */
                || !WPACKET_put_bytes_u8(&wpkt, SSL3_MT_SERVER_HELLO)
                /*
                 * Handshake message length: written at offset 1 within the
                 * handshake header (3 bytes), we will patch it up the same
                 * way DTLSv1_listen does for HelloVerifyRequest.
                 */
                || !WPACKET_put_bytes_u24(&wpkt, 0) /* placeholder length */
                /* msg_seq = 0 (this is the server's first handshake message) */
                || !WPACKET_put_bytes_u16(&wpkt, 0)
                /* fragment_offset = 0 (never fragment an HRR) */
                || !WPACKET_put_bytes_u24(&wpkt, 0)
                /* fragment_length == message_length: use a sub-packet */
                || !WPACKET_start_sub_packet_u24(&wpkt)
                /* ServerHello body */
                || !WPACKET_put_bytes_u16(&wpkt, DTLS1_2_VERSION)
                || !WPACKET_memcpy(&wpkt, hrrrandom, SSL3_RANDOM_SIZE)
                /* legacy_session_id: empty for DTLS 1.3 */
                || !WPACKET_put_bytes_u8(&wpkt, 0)
                /* cipher_suite: best mutually supported TLS 1.3 cipher */
                || !WPACKET_put_bytes_u16(&wpkt, hrr_cipher_id)
                /* legacy_compression_method: null */
                || !WPACKET_put_bytes_u8(&wpkt, 0)
                /* Extensions (u16-prefixed block) */
                || !WPACKET_start_sub_packet_u16(&wpkt)
                /* supported_versions extension: type + u16 data len + u16 version */
                || !WPACKET_put_bytes_u16(&wpkt, TLSEXT_TYPE_supported_versions)
                || !WPACKET_start_sub_packet_u16(&wpkt)
                || !WPACKET_put_bytes_u16(&wpkt, DTLS1_3_VERSION)
                || !WPACKET_close(&wpkt) /* supported_versions ext data */
                /* cookie extension: type + u16 data len + u16 cookie len + cookie */
                || !WPACKET_put_bytes_u16(&wpkt, TLSEXT_TYPE_cookie)
                || !WPACKET_start_sub_packet_u16(&wpkt)
                || !WPACKET_sub_memcpy_u16(&wpkt, hrr_cookie, hrr_cookie_len)
                || !WPACKET_close(&wpkt) /* cookie ext data */
                || !WPACKET_close(&wpkt) /* extensions block */
                || !WPACKET_close(&wpkt) /* fragment (inner sub-packet) */
                || !WPACKET_close(&wpkt) /* record body */
                || !WPACKET_get_total_written(&wpkt, &wreclen)
                || !WPACKET_finish(&wpkt)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                WPACKET_cleanup(&wpkt);
                ret = -1;
                goto end;
            }

            /*
             * Patch the handshake message length field (bytes 1-3 of the
             * handshake header) to equal the fragment length (bytes 9-11).
             * These are located at DTLS1_RT_HEADER_LENGTH+1 and
             * DTLS1_RT_HEADER_LENGTH+DTLS1_HM_HEADER_LENGTH-3 respectively,
             * matching the same fixup done for HelloVerifyRequest above.
             */
            memcpy(&wbuf[DTLS1_RT_HEADER_LENGTH + 1],
                &wbuf[DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH - 3],
                3);

            /*
             * Save the HRR message (handshake portion, without record header)
             * for later transcript hash reconstruction. We need the HRR in
             * DTLS format (full 12-byte handshake header + body) because
             * ssl3_finish_mac/ssl3_digest_cached_records expects DTLS-format
             * messages and will strip out the DTLS-specific fields when
             * computing the actual transcript hash.
             */
            hrr_start = wbuf + DTLS1_RT_HEADER_LENGTH;

            /* HRR body length is in bytes 1-3 of handshake header */
            hrr_body_len = ((size_t)hrr_start[1] << 16)
                | ((size_t)hrr_start[2] << 8)
                | (size_t)hrr_start[3];
            /*
             * Store the full DTLS handshake message (12-byte header + body).
             */
            s->dtls13_listen_saved_hrr_len = DTLS1_HM_HEADER_LENGTH + hrr_body_len;
            OPENSSL_free(s->dtls13_listen_saved_hrr);
            s->dtls13_listen_saved_hrr = OPENSSL_malloc(s->dtls13_listen_saved_hrr_len);
            if (s->dtls13_listen_saved_hrr != NULL) {
                /* Copy full DTLS handshake message (header + body) */
                memcpy(s->dtls13_listen_saved_hrr, hrr_start, s->dtls13_listen_saved_hrr_len);
            } else {
                s->dtls13_listen_saved_hrr_len = 0;
            }

            /*
             * Compute hash of ClientHello1 for transcript reconstruction.
             * For DTLS 1.3, the hash is computed over the TLS 1.3 style message:
             * first 4 bytes of handshake header (msg_type + msg_length) plus body.
             *
             * Get the hash algorithm from the selected cipher.
             * For TLS 1.3 ciphers, the hash is determined by the cipher.
             */
            md = ssl_md(SSL_CONNECTION_GET_CTX(s), hrr_cipher->algorithm2);
            if (md == NULL) {
                ERR_raise(ERR_LIB_SSL, SSL_R_NO_SUITABLE_DIGEST_ALGORITHM);
                ret = -1;
                goto end;
            }

            ctx = EVP_MD_CTX_new();
            if (ctx == NULL) {
                ERR_raise(ERR_LIB_SSL, ERR_R_EVP_LIB);
                ret = -1;
                goto end;
            }

            if (!EVP_DigestInit_ex(ctx, md, NULL)) {
                EVP_MD_CTX_free(ctx);
                ERR_raise(ERR_LIB_SSL, ERR_R_EVP_LIB);
                ret = -1;
                goto end;
            }

            /*
             * Hash the ClientHello1 in TLS 1.3 style:
             * - First 4 bytes of DTLS header (msg_type + msg_length)
             * - Body (skip message_seq, fragment_offset, fragment_length)
             *
             * 'data' points to start of handshake message (msg_type)
             * 'fraglen' is the length of the fragment body
             */
            if (!EVP_DigestUpdate(ctx, data, SSL3_HM_HEADER_LENGTH)
                || !EVP_DigestUpdate(ctx, data + DTLS1_HM_HEADER_LENGTH, fraglen)) {
                EVP_MD_CTX_free(ctx);
                ERR_raise(ERR_LIB_SSL, ERR_R_EVP_LIB);
                ret = -1;
                goto end;
            }

            if (!EVP_DigestFinal_ex(ctx, s->dtls13_listen_ch1_hash, &hash_size)) {
                EVP_MD_CTX_free(ctx);
                ERR_raise(ERR_LIB_SSL, ERR_R_EVP_LIB);
                ret = -1;
                goto end;
            }
            s->dtls13_listen_ch1_hash_len = hash_size;
            EVP_MD_CTX_free(ctx);

            if (s->msg_callback) {
                s->msg_callback(1, DTLS1_2_VERSION, SSL3_RT_HEADER,
                    wbuf, DTLS1_RT_HEADER_LENGTH,
                    ssl, s->msg_callback_arg);
                s->msg_callback(1, DTLS1_2_VERSION, SSL3_RT_HANDSHAKE,
                    wbuf + DTLS1_RT_HEADER_LENGTH,
                    wreclen - DTLS1_RT_HEADER_LENGTH,
                    ssl, s->msg_callback_arg);
            }

            if ((tmpclient = BIO_ADDR_new()) == NULL) {
                ERR_raise(ERR_LIB_SSL, ERR_R_BIO_LIB);
                goto end;
            }

            if (BIO_dgram_get_peer(rbio, tmpclient) > 0)
                (void)BIO_dgram_set_peer(wbio, tmpclient);
            BIO_ADDR_free(tmpclient);
            tmpclient = NULL;

            if (BIO_write(wbio, wbuf, (int)wreclen) < (int)wreclen) {
                if (BIO_should_retry(wbio))
                    goto end;
                ret = -1;
                goto end;
            }

            if (BIO_flush(wbio) <= 0) {
                if (BIO_should_retry(wbio))
                    goto end;
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

    if (dtls13) {
        /*
         * For DTLS 1.3 we sent a HelloRetryRequest rather than a
         * HelloVerifyRequest.  Signal this to the state machine so that the
         * subsequent SSL_accept() call handles the second ClientHello
         * correctly (transcript hash, key_share selection, etc.).
         *
         * Also set new_cipher to the cipher we advertised in the HRR.
         * tls_early_post_process_client_hello checks that the cipher in the
         * second ClientHello matches new_cipher when hello_retry_request is
         * SSL_HRR_PENDING.
         */
        s->hello_retry_request = SSL_HRR_PENDING;

        if (hrr_cipher == NULL) {
            /*
             * Second invocation: we went straight to LISTEN_SUCCESS without
             * sending an HRR, so hrr_cipher was never set this call.
             * Re-select from the client's cipher list now.
             */
            unsigned int cipher_id;
            STACK_OF(SSL_CIPHER) *srvr_ciphers = SSL_get_ciphers(ssl);
            PACKET cp = ciphers;

            while (PACKET_get_net_2(&cp, &cipher_id)) {
                unsigned char client_cipher_id[2];
                const SSL_CIPHER *client_cipher;

                client_cipher_id[0] = (unsigned char)(cipher_id >> 8);
                client_cipher_id[1] = (unsigned char)(cipher_id & 0xff);
                client_cipher = SSL_CIPHER_find(ssl, client_cipher_id);
                if (client_cipher == NULL || client_cipher->min_tls != TLS1_3_VERSION)
                    continue;
                if (srvr_ciphers != NULL
                    && sk_SSL_CIPHER_find(srvr_ciphers, client_cipher) < 0)
                    continue;
                hrr_cipher = client_cipher;
                break;
            }
        }

        if (hrr_cipher != NULL)
            s->s3.tmp.new_cipher = hrr_cipher;

        /*
         * Set up the transcript hash for DTLS 1.3.
         * If we sent an HRR (dtls13_listen_ch1_hash_len > 0), we need to:
         * 1. Initialize the transcript with a synthetic message_hash of ClientHello1
         * 2. Add the HRR to the transcript
         *
         * The subsequent SSL_accept() will then add ClientHello2 to the transcript.
         */
        if (s->dtls13_listen_ch1_hash_len > 0 && s->dtls13_listen_saved_hrr_len > 0) {
            /*
             * Create the synthetic message_hash. This:
             * 1. Reinitializes the transcript hash
             * 2. Injects message_hash(Hash(ClientHello1)) into the transcript
             */
            if (!create_synthetic_message_hash(s, s->dtls13_listen_ch1_hash,
                    s->dtls13_listen_ch1_hash_len, NULL, 0)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                ret = -1;
                goto end;
            }

            /*
             * Now add the HRR to the transcript.
             * The HRR was saved in DTLS format (12-byte header + body).
             */
            if (!ssl3_finish_mac(s, s->dtls13_listen_saved_hrr, s->dtls13_listen_saved_hrr_len)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                ret = -1;
                goto end;
            }

            /* Clean up the saved transcript data - no longer needed */
            OPENSSL_free(s->dtls13_listen_saved_hrr);
            s->dtls13_listen_saved_hrr = NULL;
            s->dtls13_listen_saved_hrr_len = 0;
            s->dtls13_listen_ch1_hash_len = 0;
        }
    }

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
