/*
 * Copyright 2018-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../../ssl_local.h"
#include "../record_local.h"
#include "recmethod_local.h"

/* mod 128 saturating subtract of two 64-bit values in big-endian order */
static int satsub64be(const unsigned char *v1, const unsigned char *v2)
{
    int64_t ret;
    uint64_t l1, l2;

    n2l8(v1, l1);
    n2l8(v2, l2);

    ret = l1 - l2;

    /* We do not permit wrap-around */
    if (l1 > l2 && ret < 0)
        return 128;
    else if (l2 > l1 && ret > 0)
        return -128;

    if (ret > 128)
        return 128;
    else if (ret < -128)
        return -128;
    else
        return (int)ret;
}

static int dtls1_record_replay_check(SSL_CONNECTION *s, DTLS1_BITMAP *bitmap)
{
    int cmp;
    unsigned int shift;
    const unsigned char *seq = s->rlayer.read_sequence;
    OSSL_RECORD_LAYER *rl = (OSSL_RECORD_LAYER *)s->rrl;

    cmp = satsub64be(seq, bitmap->max_seq_num);
    if (cmp > 0) {
        SSL3_RECORD_set_seq_num(&rl->rrec[0], seq);
        return 1;               /* this record in new */
    }
    shift = -cmp;
    if (shift >= sizeof(bitmap->map) * 8)
        return 0;               /* stale, outside the window */
    else if (bitmap->map & (1UL << shift))
        return 0;               /* record previously received */

    SSL3_RECORD_set_seq_num(&rl->rrec[0], seq);
    return 1;
}

static void dtls1_record_bitmap_update(SSL_CONNECTION *s, DTLS1_BITMAP *bitmap)
{
    int cmp;
    unsigned int shift;
    const unsigned char *seq = RECORD_LAYER_get_read_sequence(&s->rlayer);

    cmp = satsub64be(seq, bitmap->max_seq_num);
    if (cmp > 0) {
        shift = cmp;
        if (shift < sizeof(bitmap->map) * 8)
            bitmap->map <<= shift, bitmap->map |= 1UL;
        else
            bitmap->map = 1UL;
        memcpy(bitmap->max_seq_num, seq, SEQ_NUM_SIZE);
    } else {
        shift = -cmp;
        if (shift < sizeof(bitmap->map) * 8)
            bitmap->map |= 1UL << shift;
    }
}

static DTLS1_BITMAP *dtls1_get_bitmap(SSL_CONNECTION *s, SSL3_RECORD *rr,
                                      unsigned int *is_next_epoch)
{
    OSSL_RECORD_LAYER *rl = s->rrl;
    *is_next_epoch = 0;

    /* In current epoch, accept HM, CCS, DATA, & ALERT */
    if (rr->epoch == s->rlayer.d->r_epoch)
        return &s->rlayer.d->bitmap;

    /*
     * Only HM and ALERT messages can be from the next epoch and only if we
     * have already processed all of the unprocessed records from the last
     * epoch
     */
    else if (rr->epoch == (unsigned long)(s->rlayer.d->r_epoch + 1) &&
             rl->unprocessed_rcds.epoch != s->rlayer.d->r_epoch &&
             (rr->type == SSL3_RT_HANDSHAKE || rr->type == SSL3_RT_ALERT)) {
        *is_next_epoch = 1;
        return &s->rlayer.d->next_bitmap;
    }

    return NULL;
}

static int dtls1_process_record(SSL_CONNECTION *s, DTLS1_BITMAP *bitmap)
{
    int i;
    int enc_err;
    SSL_SESSION *sess;
    SSL3_RECORD *rr;
    int imac_size;
    size_t mac_size = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t max_plain_length = SSL3_RT_MAX_PLAIN_LENGTH;
    SSL_MAC_BUF macbuf = { NULL, 0 };
    int ret = 0;
    OSSL_RECORD_LAYER *rl = (OSSL_RECORD_LAYER *)s->rrl;
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);

    rr = &rl->rrec[0];
    sess = s->session;

    /*
     * At this point, s->rlayer.packet_length == SSL3_RT_HEADER_LNGTH + rr->length,
     * and we have that many bytes in s->rlayer.packet
     */
    rr->input = &(s->rrlmethod->get0_packet(s->rrl)[DTLS1_RT_HEADER_LENGTH]);

    /*
     * ok, we can now read from 's->rlayer.packet' data into 'rr'. rr->input
     * points at rr->length bytes, which need to be copied into rr->data by
     * either the decryption or by the decompression. When the data is 'copied'
     * into the rr->data buffer, rr->input will be pointed at the new buffer
     */

    /*
     * We now have - encrypted [ MAC [ compressed [ plain ] ] ] rr->length
     * bytes of encrypted compressed stuff.
     */

    /* check is not needed I believe */
    if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
        SSLfatal(s, SSL_AD_RECORD_OVERFLOW, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
        return 0;
    }

    /* decrypt in place in 'rr->input' */
    rr->data = rr->input;
    rr->orig_len = rr->length;

    if (s->read_hash != NULL) {
        const EVP_MD *tmpmd = EVP_MD_CTX_get0_md(s->read_hash);

        if (tmpmd != NULL) {
            imac_size = EVP_MD_get_size(tmpmd);
            if (!ossl_assert(imac_size >= 0 && imac_size <= EVP_MAX_MD_SIZE)) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
                    return 0;
            }
            mac_size = (size_t)imac_size;
        }
    }

    if (SSL_READ_ETM(s) && s->read_hash) {
        unsigned char *mac;

        if (rr->orig_len < mac_size) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
            return 0;
        }
        rr->length -= mac_size;
        mac = rr->data + rr->length;
        i = ssl->method->ssl3_enc->mac(s, rr, md, 0 /* not send */ );
        if (i == 0 || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0) {
            SSLfatal(s, SSL_AD_BAD_RECORD_MAC,
                     SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
            return 0;
        }
        /*
         * We've handled the mac now - there is no MAC inside the encrypted
         * record
         */
        mac_size = 0;
    }

    /*
     * Set a mark around the packet decryption attempt.  This is DTLS, so
     * bad packets are just ignored, and we don't want to leave stray
     * errors in the queue from processing bogus junk that we ignored.
     */
    ERR_set_mark();
    enc_err = ssl->method->ssl3_enc->enc(s, rr, 1, 0, &macbuf, mac_size);

    /*-
     * enc_err is:
     *    0: if the record is publicly invalid, or an internal error, or AEAD
     *       decryption failed, or ETM decryption failed.
     *    1: Success or MTE decryption failed (MAC will be randomised)
     */
    if (enc_err == 0) {
        ERR_pop_to_mark();
        if (ossl_statem_in_error(s)) {
            /* SSLfatal() got called */
            goto end;
        }
        /* For DTLS we simply ignore bad packets. */
        rr->length = 0;
        s->rrlmethod->reset_packet_length(s->rrl);
        goto end;
    }
    ERR_clear_last_mark();
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "dec %zd\n", rr->length);
        BIO_dump_indent(trc_out, rr->data, rr->length, 4);
    } OSSL_TRACE_END(TLS);

    /* r->length is now the compressed data plus mac */
    if ((sess != NULL)
            && !SSL_READ_ETM(s)
            && (s->enc_read_ctx != NULL)
            && (EVP_MD_CTX_get0_md(s->read_hash) != NULL)) {
        /* s->read_hash != NULL => mac_size != -1 */

        i = ssl->method->ssl3_enc->mac(s, rr, md, 0 /* not send */ );
        if (i == 0 || macbuf.mac == NULL
            || CRYPTO_memcmp(md, macbuf.mac, mac_size) != 0)
            enc_err = 0;
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH + mac_size)
            enc_err = 0;
    }

    if (enc_err == 0) {
        /* decryption failed, silently discard message */
        rr->length = 0;
        s->rrlmethod->reset_packet_length(s->rrl);
        goto end;
    }

    /* r->length is now just compressed */
    if (s->expand != NULL) {
        if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH) {
            SSLfatal(s, SSL_AD_RECORD_OVERFLOW,
                     SSL_R_COMPRESSED_LENGTH_TOO_LONG);
            goto end;
        }
        if (!ssl3_do_uncompress(s, rr)) {
            SSLfatal(s, SSL_AD_DECOMPRESSION_FAILURE, SSL_R_BAD_DECOMPRESSION);
            goto end;
        }
    }

    /* use current Max Fragment Length setting if applicable */
    if (s->session != NULL && USE_MAX_FRAGMENT_LENGTH_EXT(s->session))
        max_plain_length = GET_MAX_FRAGMENT_LENGTH(s->session);

    /* send overflow if the plaintext is too long now it has passed MAC */
    if (rr->length > max_plain_length) {
        SSLfatal(s, SSL_AD_RECORD_OVERFLOW, SSL_R_DATA_LENGTH_TOO_LONG);
        goto end;
    }

    rr->off = 0;
    /*-
     * So at this point the following is true
     * ssl->s3.rrec.type   is the type of record
     * ssl->s3.rrec.length == number of bytes in record
     * ssl->s3.rrec.off    == offset to first valid byte
     * ssl->s3.rrec.data   == where to take bytes from, increment
     *                        after use :-).
     */

    /* we have pulled in a full packet so zero things */
    s->rrlmethod->reset_packet_length(s->rrl);

    /* Mark receipt of record. */
    dtls1_record_bitmap_update(s, bitmap);

    ret = 1;
 end:
    if (macbuf.alloced)
        OPENSSL_free(macbuf.mac);
    return ret;
}

static int dtls_rlayer_buffer_record(SSL_CONNECTION *s, record_pqueue *queue,
                                     unsigned char *priority)
{
    DTLS_RLAYER_RECORD_DATA *rdata;
    pitem *item;
    OSSL_RECORD_LAYER *rl = (OSSL_RECORD_LAYER *)s->rrl;

    /* Limit the size of the queue to prevent DOS attacks */
    if (pqueue_size(queue->q) >= 100)
        return 0;

    rdata = OPENSSL_malloc(sizeof(*rdata));
    item = pitem_new(priority, rdata);
    if (rdata == NULL || item == NULL) {
        OPENSSL_free(rdata);
        pitem_free(item);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    rdata->packet = s->rrlmethod->get0_packet(s->rrl);
    rdata->packet_length = s->rrlmethod->get_packet_length(s->rrl);
    memcpy(&(rdata->rbuf), s->rrlmethod->get0_rbuf(s->rrl), sizeof(SSL3_BUFFER));
    memcpy(&(rdata->rrec), &rl->rrec[0], sizeof(SSL3_RECORD));

    item->data = rdata;

    s->rrlmethod->set0_packet(s->rrl, NULL, 0);
    memset(s->rrlmethod->get0_rbuf(s->rrl), 0, sizeof(SSL3_BUFFER));
    memset(&rl->rrec[0], 0, sizeof(rl->rrec[0]));

    if (!ssl3_setup_buffers(s)) {
        /* SSLfatal() already called */
        OPENSSL_free(rdata->rbuf.buf);
        OPENSSL_free(rdata);
        pitem_free(item);
        return -1;
    }

    if (pqueue_insert(queue->q, item) == NULL) {
        /* Must be a duplicate so ignore it */
        OPENSSL_free(rdata->rbuf.buf);
        OPENSSL_free(rdata);
        pitem_free(item);
    }

    return 1;
}

/* copy buffered record into SSL structure */
static int dtls_copy_rlayer_record(OSSL_RECORD_LAYER *rl, pitem *item)
{
    DTLS_RLAYER_RECORD_DATA *rdata;
    SSL_CONNECTION *s = (SSL_CONNECTION *)rl->cbarg;

    rdata = (DTLS_RLAYER_RECORD_DATA *)item->data;

    SSL3_BUFFER_release(s->rrlmethod->get0_rbuf(s->rrl));

    s->rrlmethod->set0_packet(s->rrl, rdata->packet, rdata->packet_length);
    memcpy(s->rrlmethod->get0_rbuf(s->rrl), &(rdata->rbuf), sizeof(SSL3_BUFFER));
    memcpy(&rl->rrec[0], &(rdata->rrec), sizeof(SSL3_RECORD));

    /* Set proper sequence number for mac calculation */
    memcpy(&(s->rlayer.read_sequence[2]), &(rdata->packet[5]), 6);

    return 1;
}

static int dtls_retrieve_rlayer_buffered_record(OSSL_RECORD_LAYER *rl,
                                                record_pqueue *queue)
{
    pitem *item;

    item = pqueue_pop(queue->q);
    if (item) {
        dtls_copy_rlayer_record(rl, item);

        OPENSSL_free(item->data);
        pitem_free(item);

        return 1;
    }

    return 0;
}

static int dtls_process_rlayer_buffered_records(SSL_CONNECTION *s)
{
    pitem *item;
    SSL3_BUFFER *rb;
    SSL3_RECORD *rr;
    DTLS1_BITMAP *bitmap;
    unsigned int is_next_epoch;
    int replayok = 1;
    OSSL_RECORD_LAYER *rl = s->rrl;

    item = pqueue_peek(rl->unprocessed_rcds.q);
    if (item) {
        /* Check if epoch is current. */
        if (rl->unprocessed_rcds.epoch != s->rlayer.d->r_epoch)
            return 1;         /* Nothing to do. */

        rr = rl->rrec;

        rb = s->rrlmethod->get0_rbuf(s->rrl);

        if (SSL3_BUFFER_get_left(rb) > 0) {
            /*
             * We've still got data from the current packet to read. There could
             * be a record from the new epoch in it - so don't overwrite it
             * with the unprocessed records yet (we'll do it when we've
             * finished reading the current packet).
             */
            return 1;
        }

        /* Process all the records. */
        while (pqueue_peek(rl->unprocessed_rcds.q)) {
            dtls_retrieve_rlayer_buffered_record(rl, &(rl->unprocessed_rcds));
            bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
            if (bitmap == NULL) {
                /*
                 * Should not happen. This will only ever be NULL when the
                 * current record is from a different epoch. But that cannot
                 * be the case because we already checked the epoch above
                 */
                 SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                 return 0;
            }
#ifndef OPENSSL_NO_SCTP
            /* Only do replay check if no SCTP bio */
            if (!BIO_dgram_is_sctp(SSL_get_rbio(s)))
#endif
            {
                /*
                 * Check whether this is a repeat, or aged record. We did this
                 * check once already when we first received the record - but
                 * we might have updated the window since then due to
                 * records we subsequently processed.
                 */
                replayok = dtls1_record_replay_check(s, bitmap);
            }

            if (!replayok || !dtls1_process_record(s, bitmap)) {
                if (ossl_statem_in_error(s)) {
                    /* dtls1_process_record called SSLfatal() */
                    return 0;
                }
                /* dump this record */
                rr->length = 0;
                s->rrlmethod->reset_packet_length(s->rrl);
                continue;
            }

            if (dtls_rlayer_buffer_record(s, &(rl->processed_rcds),
                    SSL3_RECORD_get_seq_num(&rl->rrec[0])) < 0) {
                /* SSLfatal() already called */
                return 0;
            }
        }
    }

    /*
     * sync epoch numbers once all the unprocessed records have been
     * processed
     */
    rl->processed_rcds.epoch = s->rlayer.d->r_epoch;
    rl->unprocessed_rcds.epoch = s->rlayer.d->r_epoch + 1;

    return 1;
}

int dtls_buffer_listen_record(SSL_CONNECTION *s, size_t len, unsigned char *seq, size_t off)
{
    SSL3_RECORD *rr;
    OSSL_RECORD_LAYER *rl = s->rrl;

    rr = &rl->rrec[0];
    memset(rr, 0, sizeof(SSL3_RECORD));

    rr->length = len;
    rr->type = SSL3_RT_HANDSHAKE;
    memcpy(rr->seq_num, seq, sizeof(rr->seq_num));
    rr->off = off;

    s->rrlmethod->set0_packet(s->rrl, s->rrlmethod->get0_rbuf(s->rrl)->buf,
                              DTLS1_RT_HEADER_LENGTH + len);
    rr->data = s->rrlmethod->get0_packet(s->rrl) + DTLS1_RT_HEADER_LENGTH;

    if (dtls_rlayer_buffer_record(s, &(rl->processed_rcds),
                                  SSL3_RECORD_get_seq_num(rr)) <= 0) {
        /* SSLfatal() already called */
        return 0;
    }

    return 1;
}

/*-
 * Call this to get a new input record.
 * It will return <= 0 if more data is needed, normally due to an error
 * or non-blocking IO.
 * When it finishes, one packet has been decoded and can be found in
 * ssl->s3.rrec.type    - is the type of record
 * ssl->s3.rrec.data    - data
 * ssl->s3.rrec.length  - number of bytes
 */
/* used only by dtls1_read_bytes */
static int dtls_get_more_records(OSSL_RECORD_LAYER *rl)
{
    int ssl_major, ssl_minor;
    int rret;
    size_t more, n;
    SSL3_RECORD *rr;
    unsigned char *p = NULL;
    unsigned short version;
    DTLS1_BITMAP *bitmap;
    unsigned int is_next_epoch;
    /* TODO(RECLAYER): Remove me */
    SSL_CONNECTION *s = (SSL_CONNECTION *)rl->cbarg;
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);

    rl->num_recs = 0;
    rl->curr_rec = 0;
    rl->num_released = 0;

    rr = rl->rrec;

 again:
    /*
     * The epoch may have changed.  If so, process all the pending records.
     * This is a non-blocking operation.
     */
    if (!dtls_process_rlayer_buffered_records(s)) {
        /* SSLfatal() already called */
        return OSSL_RECORD_RETURN_FATAL;
    }

    /* if we're renegotiating, then there may be buffered records */
    if (dtls_retrieve_rlayer_buffered_record(rl, &rl->processed_rcds)) {
        rl->num_recs = 1;
        return OSSL_RECORD_RETURN_SUCCESS;
    }

    /* get something from the wire */

    /* check if we have the header */
    if ((RECORD_LAYER_get_rstate(&s->rlayer) != SSL_ST_READ_BODY) ||
        (s->rrlmethod->get_packet_length(s->rrl) < DTLS1_RT_HEADER_LENGTH)) {
        rret = s->rrlmethod->read_n(s->rrl, DTLS1_RT_HEADER_LENGTH,
                                    SSL3_BUFFER_get_len(s->rrlmethod->get0_rbuf(s->rrl)),
                                    0, 1, &n);
        /* read timeout is handled by dtls1_read_bytes */
        if (rret < OSSL_RECORD_RETURN_SUCCESS) {
            /* SSLfatal() already called if appropriate */
            return rret;         /* error or non-blocking */
        }

        /* this packet contained a partial record, dump it */
        if (s->rrlmethod->get_packet_length(s->rrl) != DTLS1_RT_HEADER_LENGTH) {
            s->rrlmethod->reset_packet_length(s->rrl);
            goto again;
        }

        RECORD_LAYER_set_rstate(&s->rlayer, SSL_ST_READ_BODY);

        p = s->rrlmethod->get0_packet(s->rrl);

        if (s->msg_callback)
            s->msg_callback(0, 0, SSL3_RT_HEADER, p, DTLS1_RT_HEADER_LENGTH,
                            ssl, s->msg_callback_arg);

        /* Pull apart the header into the DTLS1_RECORD */
        rr->type = *(p++);
        ssl_major = *(p++);
        ssl_minor = *(p++);
        version = (ssl_major << 8) | ssl_minor;

        /* sequence number is 64 bits, with top 2 bytes = epoch */
        n2s(p, rr->epoch);

        memcpy(&(RECORD_LAYER_get_read_sequence(&s->rlayer)[2]), p, 6);
        p += 6;

        n2s(p, rr->length);
        rr->read = 0;

        /*
         * Lets check the version. We tolerate alerts that don't have the exact
         * version number (e.g. because of protocol version errors)
         */
        if (!s->first_packet && rr->type != SSL3_RT_ALERT) {
            if (version != s->version) {
                /* unexpected version, silently discard */
                rr->length = 0;
                rr->read = 1;
                s->rrlmethod->reset_packet_length(s->rrl);
                goto again;
            }
        }

        if ((version & 0xff00) != (s->version & 0xff00)) {
            /* wrong version, silently discard record */
            rr->length = 0;
            rr->read = 1;
            s->rrlmethod->reset_packet_length(s->rrl);
            goto again;
        }

        if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
            /* record too long, silently discard it */
            rr->length = 0;
            rr->read = 1;
            s->rrlmethod->reset_packet_length(s->rrl);
            goto again;
        }

        /* If received packet overflows own-client Max Fragment Length setting */
        if (s->session != NULL && USE_MAX_FRAGMENT_LENGTH_EXT(s->session)
                && rr->length > GET_MAX_FRAGMENT_LENGTH(s->session) + SSL3_RT_MAX_ENCRYPTED_OVERHEAD) {
            /* record too long, silently discard it */
            rr->length = 0;
            rr->read = 1;
            s->rrlmethod->reset_packet_length(s->rrl);
            goto again;
        }

        /* now s->rlayer.rstate == SSL_ST_READ_BODY */
    }

    /* s->rlayer.rstate == SSL_ST_READ_BODY, get and decode the data */

    if (rr->length >
        s->rrlmethod->get_packet_length(s->rrl) - DTLS1_RT_HEADER_LENGTH) {
        /* now s->rlayer.packet_length == DTLS1_RT_HEADER_LENGTH */
        more = rr->length;
        rret = s->rrlmethod->read_n(s->rrl, more, more, 1, 1, &n);
        /* this packet contained a partial record, dump it */
        if (rret < OSSL_RECORD_RETURN_SUCCESS || n != more) {
            if (ossl_statem_in_error(s)) {
                /* read_n() called SSLfatal() */
                return OSSL_RECORD_RETURN_FATAL;
            }
            rr->length = 0;
            rr->read = 1;
            s->rrlmethod->reset_packet_length(s->rrl);
            goto again;
        }

        /*
         * now n == rr->length, and s->rlayer.packet_length ==
         * DTLS1_RT_HEADER_LENGTH + rr->length
         */
    }
    /* set state for later operations */
    RECORD_LAYER_set_rstate(&s->rlayer, SSL_ST_READ_HEADER);

    /* match epochs.  NULL means the packet is dropped on the floor */
    bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
    if (bitmap == NULL) {
        rr->length = 0;
        s->rrlmethod->reset_packet_length(s->rrl); /* dump this record */
        goto again;             /* get another record */
    }
#ifndef OPENSSL_NO_SCTP
    /* Only do replay check if no SCTP bio */
    if (!BIO_dgram_is_sctp(SSL_get_rbio(s))) {
#endif
        /* Check whether this is a repeat, or aged record. */
        if (!dtls1_record_replay_check(s, bitmap)) {
            rr->length = 0;
            rr->read = 1;
            s->rrlmethod->reset_packet_length(s->rrl); /* dump this record */
            goto again;         /* get another record */
        }
#ifndef OPENSSL_NO_SCTP
    }
#endif

    /* just read a 0 length packet */
    if (rr->length == 0) {
        rr->read = 1;
        goto again;
    }

    /*
     * If this record is from the next epoch (either HM or ALERT), and a
     * handshake is currently in progress, buffer it since it cannot be
     * processed at this time.
     */
    if (is_next_epoch) {
        if ((SSL_in_init(ssl) || ossl_statem_get_in_handshake(s))) {
            if (dtls_rlayer_buffer_record (s,
                    &(rl->unprocessed_rcds),
                    rr->seq_num) < 0) {
                /* SSLfatal() already called */
                return OSSL_RECORD_RETURN_FATAL;
            }
        }
        rr->length = 0;
        rr->read = 1;
        s->rrlmethod->reset_packet_length(s->rrl);
        goto again;
    }

    if (!dtls1_process_record(s, bitmap)) {
        if (ossl_statem_in_error(s)) {
            /* dtls1_process_record() called SSLfatal */
            return OSSL_RECORD_RETURN_FATAL;
        }
        rr->length = 0;
        rr->read = 1;
        s->rrlmethod->reset_packet_length(s->rrl); /* dump this record */
        goto again;             /* get another record */
    }

    rl->num_recs = 1;
    return OSSL_RECORD_RETURN_SUCCESS;

}

static int dtls_set_protocol_version(OSSL_RECORD_LAYER *rl, int version)
{
    rl->version = version;
    return 1;
}

static struct record_functions_st dtls_funcs = {
    NULL,
    NULL,
    dtls_get_more_records,
    NULL,
    NULL,
    dtls_set_protocol_version,
    NULL
};

static int dtls_free(OSSL_RECORD_LAYER *rl)
{
    pitem *item;
    DTLS_RLAYER_RECORD_DATA *rdata;

    if (rl->unprocessed_rcds.q == NULL) {
        while ((item = pqueue_pop(rl->unprocessed_rcds.q)) != NULL) {
            rdata = (DTLS_RLAYER_RECORD_DATA *)item->data;
            OPENSSL_free(rdata->rbuf.buf);
            OPENSSL_free(item->data);
            pitem_free(item);
        }
        pqueue_free(rl->unprocessed_rcds.q);
    }

    if (rl->processed_rcds.q == NULL) {
        while ((item = pqueue_pop(rl->processed_rcds.q)) != NULL) {
            rdata = (DTLS_RLAYER_RECORD_DATA *)item->data;
            OPENSSL_free(rdata->rbuf.buf);
            OPENSSL_free(item->data);
            pitem_free(item);
        }
        pqueue_free(rl->processed_rcds.q);
    }

    return tls_free(rl);
}

static int
dtls_new_record_layer(OSSL_LIB_CTX *libctx, const char *propq, int vers,
                      int role, int direction, int level, unsigned char *key,
                      size_t keylen, unsigned char *iv, size_t ivlen,
                      unsigned char *mackey, size_t mackeylen,
                      const EVP_CIPHER *ciph, size_t taglen,
                      /* TODO(RECLAYER): This probably should not be an int */
                      int mactype,
                      const EVP_MD *md, const SSL_COMP *comp, BIO *prev,
                      BIO *transport, BIO *next, BIO_ADDR *local, BIO_ADDR *peer,
                      const OSSL_PARAM *settings, const OSSL_PARAM *options,
                      const OSSL_DISPATCH *fns, void *cbarg,
                      OSSL_RECORD_LAYER **retrl)
{
    int ret;


    ret = tls_int_new_record_layer(libctx, propq, vers, role, direction, level,
                                   key, keylen, iv, ivlen, mackey, mackeylen,
                                   ciph, taglen, mactype, md, comp, prev,
                                   transport, next, local, peer, settings,
                                   options, fns, cbarg, retrl);

    if (ret != OSSL_RECORD_RETURN_SUCCESS)
        return ret;

    (*retrl)->unprocessed_rcds.q = pqueue_new();
    (*retrl)->processed_rcds.q = pqueue_new();
    if ((*retrl)->unprocessed_rcds.q == NULL || (*retrl)->processed_rcds.q == NULL) {
        dtls_free(*retrl);
        *retrl = NULL;
        RLAYERfatal(*retrl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return OSSL_RECORD_RETURN_FATAL;
    }

    (*retrl)->isdtls = 1;
    (*retrl)->funcs = &dtls_funcs;

    return OSSL_RECORD_RETURN_SUCCESS;
}

const OSSL_RECORD_METHOD ossl_dtls_record_method = {
    dtls_new_record_layer,
    dtls_free,
    tls_reset,
    tls_unprocessed_read_pending,
    tls_processed_read_pending,
    tls_app_data_pending,
    tls_write_pending,
    tls_get_max_record_len,
    tls_get_max_records,
    tls_write_records,
    tls_retry_write_records,
    tls_read_record,
    tls_release_record,
    tls_get_alert_code,
    tls_set1_bio,
    tls_set_protocol_version,
    NULL,
    tls_set_first_handshake,
    tls_set_max_pipelines,

    /*
     * TODO(RECLAYER): Remove these. These function pointers are temporary hacks
     * during the record layer refactoring. They need to be removed before the
     * refactor is complete.
     */
    tls_default_read_n,
    tls_get0_rbuf,
    tls_get0_packet,
    tls_set0_packet,
    tls_get_packet_length,
    tls_reset_packet_length
};
