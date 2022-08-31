/*
 * Copyright 2005-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <errno.h>
#include "../ssl_local.h"
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "record_local.h"
#include "internal/packet.h"
#include "internal/cryptlib.h"

int DTLS_RECORD_LAYER_new(RECORD_LAYER *rl)
{
    DTLS_RECORD_LAYER *d;

    if ((d = OPENSSL_malloc(sizeof(*d))) == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    rl->d = d;

    d->buffered_app_data.q = pqueue_new();

    if (d->buffered_app_data.q == NULL) {
        OPENSSL_free(d);
        rl->d = NULL;
        return 0;
    }

    return 1;
}

void DTLS_RECORD_LAYER_free(RECORD_LAYER *rl)
{
    if (rl->d == NULL)
        return;

    DTLS_RECORD_LAYER_clear(rl);
    pqueue_free(rl->d->buffered_app_data.q);
    OPENSSL_free(rl->d);
    rl->d = NULL;
}

void DTLS_RECORD_LAYER_clear(RECORD_LAYER *rl)
{
    DTLS_RECORD_LAYER *d;
    pitem *item = NULL;
    TLS_RECORD *rec;
    pqueue *buffered_app_data;

    d = rl->d;

    while ((item = pqueue_pop(d->buffered_app_data.q)) != NULL) {
        rec = (TLS_RECORD *)item->data;
        if (rl->s->options & SSL_OP_CLEANSE_PLAINTEXT)
            OPENSSL_cleanse(rec->data, rec->length);
        OPENSSL_free(rec->data);
        OPENSSL_free(item->data);
        pitem_free(item);
    }

    buffered_app_data = d->buffered_app_data.q;
    memset(d, 0, sizeof(*d));
    d->buffered_app_data.q = buffered_app_data;
}

void DTLS_RECORD_LAYER_set_saved_w_epoch(RECORD_LAYER *rl, unsigned short e)
{
    if (e == rl->d->w_epoch - 1) {
        memcpy(rl->d->curr_write_sequence,
               rl->write_sequence, sizeof(rl->write_sequence));
        memcpy(rl->write_sequence,
               rl->d->last_write_sequence, sizeof(rl->write_sequence));
    } else if (e == rl->d->w_epoch + 1) {
        memcpy(rl->d->last_write_sequence,
               rl->write_sequence, sizeof(unsigned char[8]));
        memcpy(rl->write_sequence,
               rl->d->curr_write_sequence, sizeof(rl->write_sequence));
    }
    rl->d->w_epoch = e;
}

void DTLS_RECORD_LAYER_set_write_sequence(RECORD_LAYER *rl, unsigned char *seq)
{
    memcpy(rl->write_sequence, seq, SEQ_NUM_SIZE);
}

int dtls_buffer_record(SSL_CONNECTION *s, TLS_RECORD *rec)
{
    TLS_RECORD *rdata;
    pitem *item;
    record_pqueue *queue = &(s->rlayer.d->buffered_app_data);

    /* Limit the size of the queue to prevent DOS attacks */
    if (pqueue_size(queue->q) >= 100)
        return 0;

    /* We don't buffer partially read records */
    if (!ossl_assert(rec->off == 0))
        return -1;

    rdata = OPENSSL_malloc(sizeof(*rdata));
    item = pitem_new(rec->seq_num, rdata);
    if (rdata == NULL || item == NULL) {
        OPENSSL_free(rdata);
        pitem_free(item);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    *rdata = *rec;
    /*
     * We will release the record from the record layer soon, so we take a copy
     * now. Copying data isn't good - but this should be infrequent so we
     * accept it here.
     */
    rdata->data = OPENSSL_memdup(rec->data, rec->length);
    if (rdata->data == NULL) {
        OPENSSL_free(rdata);
        pitem_free(item);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    /*
     * We use a NULL rechandle to indicate that the data field has been
     * allocated by us.
     */
    rdata->rechandle = NULL;

    item->data = rdata;

#ifndef OPENSSL_NO_SCTP
    /* Store bio_dgram_sctp_rcvinfo struct */
    if (BIO_dgram_is_sctp(SSL_get_rbio(ssl)) &&
        (SSL_get_state(ssl) == TLS_ST_SR_FINISHED
         || SSL_get_state(ssl) == TLS_ST_CR_FINISHED)) {
        BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SCTP_GET_RCVINFO,
                 sizeof(rdata->recordinfo), &rdata->recordinfo);
    }
#endif

    if (pqueue_insert(queue->q, item) == NULL) {
        /* Must be a duplicate so ignore it */
        OPENSSL_free(rdata->data);
        OPENSSL_free(rdata);
        pitem_free(item);
    }

    return 1;
}

/* Unbuffer a previously buffered TLS_RECORD structure if any */
static void dtls_unbuffer_record(SSL_CONNECTION *s)
{
    TLS_RECORD *rdata;
    pitem *item;

    /* If we already have records to handle then do nothing */
    if (s->rlayer.curr_rec < s->rlayer.num_recs)
        return;

    item = pqueue_pop(s->rlayer.d->buffered_app_data.q);
    if (item != NULL) {
        rdata = (TLS_RECORD *)item->data;

        s->rlayer.tlsrecs[0] = *rdata;
        s->rlayer.num_recs = 1;
        s->rlayer.curr_rec = 0;

#ifndef OPENSSL_NO_SCTP
        /* Restore bio_dgram_sctp_rcvinfo struct */
        if (BIO_dgram_is_sctp(SSL_get_rbio(s))) {
            BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SCTP_SET_RCVINFO,
                        sizeof(rdata->recordinfo), &rdata->recordinfo);
        }
#endif

        OPENSSL_free(item->data);
        pitem_free(item);
    }
}

/*-
 * Return up to 'len' payload bytes received in 'type' records.
 * 'type' is one of the following:
 *
 *   -  SSL3_RT_HANDSHAKE (when ssl3_get_message calls us)
 *   -  SSL3_RT_APPLICATION_DATA (when ssl3_read calls us)
 *   -  0 (during a shutdown, no data has to be returned)
 *
 * If we don't have stored data to work from, read a SSL/TLS record first
 * (possibly multiple records if we still don't have anything to return).
 *
 * This function must handle any surprises the peer may have for us, such as
 * Alert records (e.g. close_notify) or renegotiation requests. ChangeCipherSpec
 * messages are treated as if they were handshake messages *if* the |recd_type|
 * argument is non NULL.
 * Also if record payloads contain fragments too small to process, we store
 * them until there is enough for the respective protocol (the record protocol
 * may use arbitrary fragmentation and even interleaving):
 *     Change cipher spec protocol
 *             just 1 byte needed, no need for keeping anything stored
 *     Alert protocol
 *             2 bytes needed (AlertLevel, AlertDescription)
 *     Handshake protocol
 *             4 bytes needed (HandshakeType, uint24 length) -- we just have
 *             to detect unexpected Client Hello and Hello Request messages
 *             here, anything else is handled by higher layers
 *     Application data protocol
 *             none of our business
 */
int dtls1_read_bytes(SSL *s, int type, int *recvd_type, unsigned char *buf,
                     size_t len, int peek, size_t *readbytes)
{
    int i, j, ret;
    size_t n;
    TLS_RECORD *rr;
    void (*cb) (const SSL *ssl, int type2, int val) = NULL;
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    if (sc == NULL)
        return -1;

    if ((type && (type != SSL3_RT_APPLICATION_DATA) &&
         (type != SSL3_RT_HANDSHAKE)) ||
        (peek && (type != SSL3_RT_APPLICATION_DATA))) {
        SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    if (!ossl_statem_get_in_handshake(sc) && SSL_in_init(s)) {
        /* type == SSL3_RT_APPLICATION_DATA */
        i = sc->handshake_func(s);
        /* SSLfatal() already called if appropriate */
        if (i < 0)
            return i;
        if (i == 0)
            return -1;
    }

 start:
    sc->rwstate = SSL_NOTHING;

    /*
     * We are not handshaking and have no data yet, so process data buffered
     * during the last handshake in advance, if any.
     */
    if (SSL_is_init_finished(s))
        dtls_unbuffer_record(sc);

    /* Check for timeout */
    if (dtls1_handle_timeout(sc) > 0) {
        goto start;
    } else if (ossl_statem_in_error(sc)) {
        /* dtls1_handle_timeout() has failed with a fatal error */
        return -1;
    }

    /* get new packet if necessary */
    if (sc->rlayer.curr_rec >= sc->rlayer.num_recs) {
        sc->rlayer.curr_rec = sc->rlayer.num_recs = 0;
        do {
            rr = &sc->rlayer.tlsrecs[sc->rlayer.num_recs];

            ret = HANDLE_RLAYER_READ_RETURN(sc,
                    sc->rlayer.rrlmethod->read_record(sc->rlayer.rrl,
                                                      &rr->rechandle,
                                                      &rr->version, &rr->type,
                                                      &rr->data, &rr->length,
                                                      &rr->epoch, rr->seq_num));
            if (ret <= 0) {
                ret = dtls1_read_failed(sc, ret);
                /*
                * Anything other than a timeout is an error. SSLfatal() already
                * called if appropriate.
                */
                if (ret <= 0)
                    return ret;
                else
                    goto start;
            }
            rr->off = 0;
            sc->rlayer.num_recs++;
        } while (sc->rlayer.rrlmethod->processed_read_pending(sc->rlayer.rrl)
                 && sc->rlayer.num_recs < SSL_MAX_PIPELINES);
    }
    rr = &sc->rlayer.tlsrecs[sc->rlayer.curr_rec];

    /*
     * Reset the count of consecutive warning alerts if we've got a non-empty
     * record that isn't an alert.
     */
    if (rr->type != SSL3_RT_ALERT && rr->length != 0)
        sc->rlayer.alert_count = 0;

    /* we now have a packet which can be read and processed */

    if (sc->s3.change_cipher_spec /* set when we receive ChangeCipherSpec,
                                  * reset by ssl3_get_finished */
        && (rr->type != SSL3_RT_HANDSHAKE)) {
        /*
         * We now have application data between CCS and Finished. Most likely
         * the packets were reordered on their way, so buffer the application
         * data for later processing rather than dropping the connection.
         */
        if (dtls_buffer_record(sc, rr) < 0) {
            /* SSLfatal() already called */
            return -1;
        }
        ssl_release_record(sc, rr);
        goto start;
    }

    /*
     * If the other end has shut down, throw anything we read away (even in
     * 'peek' mode)
     */
    if (sc->shutdown & SSL_RECEIVED_SHUTDOWN) {
        ssl_release_record(sc, rr);
        sc->rwstate = SSL_NOTHING;
        return 0;
    }

    if (type == rr->type
        || (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC
            && type == SSL3_RT_HANDSHAKE && recvd_type != NULL)) {
        /*
         * SSL3_RT_APPLICATION_DATA or
         * SSL3_RT_HANDSHAKE or
         * SSL3_RT_CHANGE_CIPHER_SPEC
         */
        /*
         * make sure that we are not getting application data when we are
         * doing a handshake for the first time
         */
        if (SSL_in_init(s) && (type == SSL3_RT_APPLICATION_DATA) &&
            (sc->enc_read_ctx == NULL)) {
            SSLfatal(sc, SSL_AD_UNEXPECTED_MESSAGE,
                     SSL_R_APP_DATA_IN_HANDSHAKE);
            return -1;
        }

        if (recvd_type != NULL)
            *recvd_type = rr->type;

        if (len == 0) {
            /*
             * Release a zero length record. This ensures multiple calls to
             * SSL_read() with a zero length buffer will eventually cause
             * SSL_pending() to report data as being available.
             */
            if (rr->length == 0)
                ssl_release_record(sc, rr);
            return 0;
        }

        if (len > rr->length)
            n = rr->length;
        else
            n = len;

        memcpy(buf, &(rr->data[rr->off]), n);
        if (peek) {
            if (rr->length == 0)
                ssl_release_record(sc, rr);
        } else {
            if (sc->options & SSL_OP_CLEANSE_PLAINTEXT)
                OPENSSL_cleanse(&(rr->data[rr->off]), n);
            rr->length -= n;
            rr->off += n;
            if (rr->length == 0)
                ssl_release_record(sc, rr);
        }
#ifndef OPENSSL_NO_SCTP
        /*
         * We might had to delay a close_notify alert because of reordered
         * app data. If there was an alert and there is no message to read
         * anymore, finally set shutdown.
         */
        if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
            sc->d1->shutdown_received
            && BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s)) <= 0) {
            sc->shutdown |= SSL_RECEIVED_SHUTDOWN;
            return 0;
        }
#endif
        *readbytes = n;
        return 1;
    }

    /*
     * If we get here, then type != rr->type; if we have a handshake message,
     * then it was unexpected (Hello Request or Client Hello).
     */

    if (rr->type == SSL3_RT_ALERT) {
        unsigned int alert_level, alert_descr;
        unsigned char *alert_bytes = rr->data + rr->off;
        PACKET alert;

        if (!PACKET_buf_init(&alert, alert_bytes, rr->length)
                || !PACKET_get_1(&alert, &alert_level)
                || !PACKET_get_1(&alert, &alert_descr)
                || PACKET_remaining(&alert) != 0) {
            SSLfatal(sc, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_INVALID_ALERT);
            return -1;
        }

        if (sc->msg_callback)
            sc->msg_callback(0, sc->version, SSL3_RT_ALERT, alert_bytes, 2, s,
                             sc->msg_callback_arg);

        if (sc->info_callback != NULL)
            cb = sc->info_callback;
        else if (s->ctx->info_callback != NULL)
            cb = s->ctx->info_callback;

        if (cb != NULL) {
            j = (alert_level << 8) | alert_descr;
            cb(s, SSL_CB_READ_ALERT, j);
        }

        if (alert_level == SSL3_AL_WARNING) {
            sc->s3.warn_alert = alert_descr;
            ssl_release_record(sc, rr);

            sc->rlayer.alert_count++;
            if (sc->rlayer.alert_count == MAX_WARN_ALERT_COUNT) {
                SSLfatal(sc, SSL_AD_UNEXPECTED_MESSAGE,
                         SSL_R_TOO_MANY_WARN_ALERTS);
                return -1;
            }

            if (alert_descr == SSL_AD_CLOSE_NOTIFY) {
#ifndef OPENSSL_NO_SCTP
                /*
                 * With SCTP and streams the socket may deliver app data
                 * after a close_notify alert. We have to check this first so
                 * that nothing gets discarded.
                 */
                if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
                    BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s)) > 0) {
                    sc->d1->shutdown_received = 1;
                    sc->rwstate = SSL_READING;
                    BIO_clear_retry_flags(SSL_get_rbio(s));
                    BIO_set_retry_read(SSL_get_rbio(s));
                    return -1;
                }
#endif
                sc->shutdown |= SSL_RECEIVED_SHUTDOWN;
                return 0;
            }
        } else if (alert_level == SSL3_AL_FATAL) {
            sc->rwstate = SSL_NOTHING;
            sc->s3.fatal_alert = alert_descr;
            SSLfatal_data(sc, SSL_AD_NO_ALERT,
                          SSL_AD_REASON_OFFSET + alert_descr,
                          "SSL alert number %d", alert_descr);
            sc->shutdown |= SSL_RECEIVED_SHUTDOWN;
            ssl_release_record(sc, rr);
            SSL_CTX_remove_session(sc->session_ctx, sc->session);
            return 0;
        } else {
            SSLfatal(sc, SSL_AD_ILLEGAL_PARAMETER, SSL_R_UNKNOWN_ALERT_TYPE);
            return -1;
        }

        goto start;
    }

    if (sc->shutdown & SSL_SENT_SHUTDOWN) { /* but we have not received a
                                            * shutdown */
        sc->rwstate = SSL_NOTHING;
        ssl_release_record(sc, rr);
        return 0;
    }

    if (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC) {
        /*
         * We can't process a CCS now, because previous handshake messages
         * are still missing, so just drop it.
         */
        ssl_release_record(sc, rr);
        goto start;
    }

    /*
     * Unexpected handshake message (Client Hello, or protocol violation)
     */
    if (rr->type == SSL3_RT_HANDSHAKE && !ossl_statem_get_in_handshake(sc)) {
        struct hm_header_st msg_hdr;

        /*
         * This may just be a stale retransmit. Also sanity check that we have
         * at least enough record bytes for a message header
         */
        if (rr->epoch != sc->rlayer.d->r_epoch
                || rr->length < DTLS1_HM_HEADER_LENGTH) {
            ssl_release_record(sc, rr);
            goto start;
        }

        dtls1_get_message_header(rr->data, &msg_hdr);

        /*
         * If we are server, we may have a repeated FINISHED of the client
         * here, then retransmit our CCS and FINISHED.
         */
        if (msg_hdr.type == SSL3_MT_FINISHED) {
            if (dtls1_check_timeout_num(sc) < 0) {
                /* SSLfatal) already called */
                return -1;
            }

            if (dtls1_retransmit_buffered_messages(sc) <= 0) {
                /* Fail if we encountered a fatal error */
                if (ossl_statem_in_error(sc))
                    return -1;
            }
            ssl_release_record(sc, rr);
            if (!(sc->mode & SSL_MODE_AUTO_RETRY)) {
                if (!sc->rlayer.rrlmethod->unprocessed_read_pending(sc->rlayer.rrl)) {
                    /* no read-ahead left? */
                    BIO *bio;

                    sc->rwstate = SSL_READING;
                    bio = SSL_get_rbio(s);
                    BIO_clear_retry_flags(bio);
                    BIO_set_retry_read(bio);
                    return -1;
                }
            }
            goto start;
        }

        /*
         * To get here we must be trying to read app data but found handshake
         * data. But if we're trying to read app data, and we're not in init
         * (which is tested for at the top of this function) then init must be
         * finished
         */
        if (!ossl_assert(SSL_is_init_finished(s))) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return -1;
        }

        /* We found handshake data, so we're going back into init */
        ossl_statem_set_in_init(sc, 1);

        i = sc->handshake_func(s);
        /* SSLfatal() called if appropriate */
        if (i < 0)
            return i;
        if (i == 0)
            return -1;

        if (!(sc->mode & SSL_MODE_AUTO_RETRY)) {
            if (!sc->rlayer.rrlmethod->unprocessed_read_pending(sc->rlayer.rrl)) {
                /* no read-ahead left? */
                BIO *bio;
                /*
                 * In the case where we try to read application data, but we
                 * trigger an SSL handshake, we return -1 with the retry
                 * option set.  Otherwise renegotiation may cause nasty
                 * problems in the blocking world
                 */
                sc->rwstate = SSL_READING;
                bio = SSL_get_rbio(s);
                BIO_clear_retry_flags(bio);
                BIO_set_retry_read(bio);
                return -1;
            }
        }
        goto start;
    }

    switch (rr->type) {
    default:
        SSLfatal(sc, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_RECORD);
        return -1;
    case SSL3_RT_CHANGE_CIPHER_SPEC:
    case SSL3_RT_ALERT:
    case SSL3_RT_HANDSHAKE:
        /*
         * we already handled all of these, with the possible exception of
         * SSL3_RT_HANDSHAKE when ossl_statem_get_in_handshake(s) is true, but
         * that should not happen when type != rr->type
         */
        SSLfatal(sc, SSL_AD_UNEXPECTED_MESSAGE, ERR_R_INTERNAL_ERROR);
        return -1;
    case SSL3_RT_APPLICATION_DATA:
        /*
         * At this point, we were expecting handshake data, but have
         * application data.  If the library was running inside ssl3_read()
         * (i.e. in_read_app_data is set) and it makes sense to read
         * application data at this point (session renegotiation not yet
         * started), we will indulge it.
         */
        if (sc->s3.in_read_app_data &&
            (sc->s3.total_renegotiations != 0) &&
            ossl_statem_app_data_allowed(sc)) {
            sc->s3.in_read_app_data = 2;
            return -1;
        } else {
            SSLfatal(sc, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_RECORD);
            return -1;
        }
    }
    /* not reached */
}

/*
 * Call this to write data in records of type 'type' It will return <= 0 if
 * not all data has been sent or non-blocking IO.
 */
int dtls1_write_bytes(SSL_CONNECTION *s, int type, const void *buf,
                      size_t len, size_t *written)
{
    int i;

    if (!ossl_assert(len <= SSL3_RT_MAX_PLAIN_LENGTH)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return -1;
    }
    s->rwstate = SSL_NOTHING;
    i = do_dtls1_write(s, type, buf, len, 0, written);
    return i;
}

/*
 * TODO(RECLAYER): Temporary copy of the old ssl3_write_pending() function now
 * replaced by tls_retry_write_records(). Needs to be removed when the DTLS code
 * is converted
 */
/* if SSL3_BUFFER_get_left() != 0, we need to call this
 *
 * Return values are as per SSL_write()
 */
static int ssl3_write_pending(SSL_CONNECTION *s, int type,
                              const unsigned char *buf, size_t len,
                              size_t *written)
{
    int i;
    SSL3_BUFFER *wb = s->rlayer.wbuf;
    size_t currbuf = 0;
    size_t tmpwrit = 0;

    if ((s->rlayer.wpend_tot > len)
        || (!(s->mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
            && (s->rlayer.wpend_buf != buf))
        || (s->rlayer.wpend_type != type)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_WRITE_RETRY);
        return -1;
    }

    for (;;) {
        clear_sys_error();
        if (s->wbio != NULL) {
            s->rwstate = SSL_WRITING;

            /*
             * To prevent coalescing of control and data messages,
             * such as in buffer_write, we flush the BIO
             */
            if (BIO_get_ktls_send(s->wbio) && type != SSL3_RT_APPLICATION_DATA) {
                i = BIO_flush(s->wbio);
                if (i <= 0)
                    return i;
                BIO_set_ktls_ctrl_msg(s->wbio, type);
            }
            i = BIO_write(s->wbio, (char *)
                          &(SSL3_BUFFER_get_buf(&wb[currbuf])
                            [SSL3_BUFFER_get_offset(&wb[currbuf])]),
                          (unsigned int)SSL3_BUFFER_get_left(&wb[currbuf]));
            if (i >= 0)
                tmpwrit = i;
        } else {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_BIO_NOT_SET);
            i = -1;
        }

        /*
         * When an empty fragment is sent on a connection using KTLS,
         * it is sent as a write of zero bytes.  If this zero byte
         * write succeeds, i will be 0 rather than a non-zero value.
         * Treat i == 0 as success rather than an error for zero byte
         * writes to permit this case.
         */
        if (i >= 0 && tmpwrit == SSL3_BUFFER_get_left(&wb[currbuf])) {
            SSL3_BUFFER_set_left(&wb[currbuf], 0);
            SSL3_BUFFER_add_offset(&wb[currbuf], tmpwrit);
            s->rwstate = SSL_NOTHING;
            *written = s->rlayer.wpend_ret;
            return 1;
        } else if (i <= 0) {
            if (SSL_CONNECTION_IS_DTLS(s)) {
                /*
                 * For DTLS, just drop it. That's kind of the whole point in
                 * using a datagram service
                 */
                SSL3_BUFFER_set_left(&wb[currbuf], 0);
            }
            return i;
        }
        SSL3_BUFFER_add_offset(&wb[currbuf], tmpwrit);
        SSL3_BUFFER_sub_left(&wb[currbuf], tmpwrit);
    }
}

int do_dtls1_write(SSL_CONNECTION *sc, int type, const unsigned char *buf,
                   size_t len, int create_empty_fragment, size_t *written)
{
    unsigned char *p, *pseq;
    int i, mac_size, clear = 0;
    size_t prefix_len = 0;
    int eivlen;
    SSL3_RECORD wr;
    SSL3_BUFFER *wb;
    SSL_SESSION *sess;
    SSL *s = SSL_CONNECTION_GET_SSL(sc);

    wb = &sc->rlayer.wbuf[0];

    /*
     * DTLS writes whole datagrams, so there can't be anything left in
     * the buffer.
     */
    if (!ossl_assert(SSL3_BUFFER_get_left(wb) == 0)) {
        SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* If we have an alert to send, lets send it */
    if (sc->s3.alert_dispatch) {
        i = s->method->ssl_dispatch_alert(s);
        if (i <= 0)
            return i;
        /* if it went, fall through and send more stuff */
    }

    if (len == 0 && !create_empty_fragment)
        return 0;

    if (len > ssl_get_max_send_fragment(sc)) {
        SSLfatal(sc, SSL_AD_INTERNAL_ERROR, SSL_R_EXCEEDS_MAX_FRAGMENT_SIZE);
        return 0;
    }

    sess = sc->session;

    if ((sess == NULL)
            || (sc->enc_write_ctx == NULL)
            || (EVP_MD_CTX_get0_md(sc->write_hash) == NULL))
        clear = 1;

    if (clear)
        mac_size = 0;
    else {
        mac_size = EVP_MD_CTX_get_size(sc->write_hash);
        if (mac_size < 0) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR,
                     SSL_R_EXCEEDS_MAX_FRAGMENT_SIZE);
            return -1;
        }
    }

    p = SSL3_BUFFER_get_buf(wb) + prefix_len;

    /* write the header */

    *(p++) = type & 0xff;
    SSL3_RECORD_set_type(&wr, type);
    /*
     * Special case: for hello verify request, client version 1.0 and we
     * haven't decided which version to use yet send back using version 1.0
     * header: otherwise some clients will ignore it.
     */
    if (s->method->version == DTLS_ANY_VERSION &&
        sc->max_proto_version != DTLS1_BAD_VER) {
        *(p++) = DTLS1_VERSION >> 8;
        *(p++) = DTLS1_VERSION & 0xff;
    } else {
        *(p++) = sc->version >> 8;
        *(p++) = sc->version & 0xff;
    }

    /* field where we are to write out packet epoch, seq num and len */
    pseq = p;
    p += 10;

    /* Explicit IV length, block ciphers appropriate version flag */
    if (sc->enc_write_ctx) {
        int mode = EVP_CIPHER_CTX_get_mode(sc->enc_write_ctx);
        if (mode == EVP_CIPH_CBC_MODE) {
            eivlen = EVP_CIPHER_CTX_get_iv_length(sc->enc_write_ctx);
            if (eivlen < 0) {
                SSLfatal(sc, SSL_AD_INTERNAL_ERROR, SSL_R_LIBRARY_BUG);
                return -1;
            }
            if (eivlen <= 1)
                eivlen = 0;
        }
        /* Need explicit part of IV for GCM mode */
        else if (mode == EVP_CIPH_GCM_MODE)
            eivlen = EVP_GCM_TLS_EXPLICIT_IV_LEN;
        else if (mode == EVP_CIPH_CCM_MODE)
            eivlen = EVP_CCM_TLS_EXPLICIT_IV_LEN;
        else
            eivlen = 0;
    } else
        eivlen = 0;

    /* lets setup the record stuff. */
    SSL3_RECORD_set_data(&wr, p + eivlen); /* make room for IV in case of CBC */
    SSL3_RECORD_set_length(&wr, len);
    SSL3_RECORD_set_input(&wr, (unsigned char *)buf);

    /*
     * we now 'read' from wr.input, wr.length bytes into wr.data
     */

    /* first we compress */
    if (sc->compress != NULL) {
        if (!ssl3_do_compress(sc, &wr)) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, SSL_R_COMPRESSION_FAILURE);
            return -1;
        }
    } else {
        memcpy(SSL3_RECORD_get_data(&wr), SSL3_RECORD_get_input(&wr),
               SSL3_RECORD_get_length(&wr));
        SSL3_RECORD_reset_input(&wr);
    }

    /*
     * we should still have the output to wr.data and the input from
     * wr.input.  Length should be wr.length. wr.data still points in the
     * wb->buf
     */

    if (!SSL_WRITE_ETM(sc) && mac_size != 0) {
        if (!s->method->ssl3_enc->mac(sc, &wr,
                                      &(p[SSL3_RECORD_get_length(&wr) + eivlen]),
                                      1)) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        SSL3_RECORD_add_length(&wr, mac_size);
    }

    /* this is true regardless of mac size */
    SSL3_RECORD_set_data(&wr, p);
    SSL3_RECORD_reset_input(&wr);

    if (eivlen)
        SSL3_RECORD_add_length(&wr, eivlen);

    if (s->method->ssl3_enc->enc(sc, &wr, 1, 1, NULL, mac_size) < 1) {
        if (!ossl_statem_in_error(sc)) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        }
        return -1;
    }

    if (SSL_WRITE_ETM(sc) && mac_size != 0) {
        if (!s->method->ssl3_enc->mac(sc, &wr,
                                      &(p[SSL3_RECORD_get_length(&wr)]), 1)) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        SSL3_RECORD_add_length(&wr, mac_size);
    }

    /* record length after mac and block padding */

    /* there's only one epoch between handshake and app data */

    s2n(sc->rlayer.d->w_epoch, pseq);

    memcpy(pseq, &(sc->rlayer.write_sequence[2]), 6);
    pseq += 6;
    s2n(SSL3_RECORD_get_length(&wr), pseq);

    if (sc->msg_callback)
        sc->msg_callback(1, 0, SSL3_RT_HEADER, pseq - DTLS1_RT_HEADER_LENGTH,
                         DTLS1_RT_HEADER_LENGTH, s, sc->msg_callback_arg);

    /*
     * we should now have wr.data pointing to the encrypted data, which is
     * wr->length long
     */
    SSL3_RECORD_set_type(&wr, type); /* not needed but helps for debugging */
    SSL3_RECORD_add_length(&wr, DTLS1_RT_HEADER_LENGTH);

    ssl3_record_sequence_update(&(sc->rlayer.write_sequence[0]));

    if (create_empty_fragment) {
        /*
         * we are in a recursive call; just return the length, don't write
         * out anything here
         */
        *written = wr.length;
        return 1;
    }

    /* now let's set up wb */
    SSL3_BUFFER_set_left(wb, prefix_len + SSL3_RECORD_get_length(&wr));
    SSL3_BUFFER_set_offset(wb, 0);

    /*
     * memorize arguments so that ssl3_write_pending can detect bad write
     * retries later
     */
    sc->rlayer.wpend_tot = len;
    sc->rlayer.wpend_buf = buf;
    sc->rlayer.wpend_type = type;
    sc->rlayer.wpend_ret = len;

    /* we now just need to write the buffer. Calls SSLfatal() as required. */
    return ssl3_write_pending(sc, type, buf, len, written);
}

void dtls1_reset_seq_numbers(SSL_CONNECTION *s, int rw)
{
    unsigned char *seq;

    if (rw & SSL3_CC_READ) {
        s->rlayer.d->r_epoch++;

        /*
         * We must not use any buffered messages received from the previous
         * epoch
         */
        dtls1_clear_received_buffer(s);
    } else {
        seq = s->rlayer.write_sequence;
        memcpy(s->rlayer.d->last_write_sequence, seq,
               sizeof(s->rlayer.write_sequence));
        s->rlayer.d->w_epoch++;
        memset(seq, 0, sizeof(s->rlayer.write_sequence));
    }
}
