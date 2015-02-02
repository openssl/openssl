/* ssl/d1_pkt.c */
/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <errno.h>
#define USE_SOCKETS
#include "../ssl_locl.h"
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pqueue.h>
#include <openssl/rand.h>

/* mod 128 saturating subtract of two 64-bit values in big-endian order */
static int satsub64be(const unsigned char *v1, const unsigned char *v2)
{
    int ret, sat, brw, i;

    if (sizeof(long) == 8)
        do {
            const union {
                long one;
                char little;
            } is_endian = {
                1
            };
            long l;

            if (is_endian.little)
                break;
            /* not reached on little-endians */
            /*
             * following test is redundant, because input is always aligned,
             * but I take no chances...
             */
            if (((size_t)v1 | (size_t)v2) & 0x7)
                break;

            l = *((long *)v1);
            l -= *((long *)v2);
            if (l > 128)
                return 128;
            else if (l < -128)
                return -128;
            else
                return (int)l;
        } while (0);

    ret = (int)v1[7] - (int)v2[7];
    sat = 0;
    brw = ret >> 8;             /* brw is either 0 or -1 */
    if (ret & 0x80) {
        for (i = 6; i >= 0; i--) {
            brw += (int)v1[i] - (int)v2[i];
            sat |= ~brw;
            brw >>= 8;
        }
    } else {
        for (i = 6; i >= 0; i--) {
            brw += (int)v1[i] - (int)v2[i];
            sat |= brw;
            brw >>= 8;
        }
    }
    brw <<= 8;                  /* brw is either 0 or -256 */

    if (sat & 0xff)
        return brw | 0x80;
    else
        return brw + (ret & 0xFF);
}

static int have_handshake_fragment(SSL *s, int type, unsigned char *buf,
                                   int len, int peek);

/* copy buffered record into SSL structure */
static int dtls1_copy_record(SSL *s, pitem *item)
{
    DTLS1_RECORD_DATA *rdata;

    rdata = (DTLS1_RECORD_DATA *)item->data;

    SSL3_BUFFER_release(RECORD_LAYER_get_rbuf(&s->rlayer));

    s->packet = rdata->packet;
    s->packet_length = rdata->packet_length;
    memcpy(RECORD_LAYER_get_rbuf(&s->rlayer), &(rdata->rbuf),
        sizeof(SSL3_BUFFER));
    memcpy(RECORD_LAYER_get_rrec(&s->rlayer), &(rdata->rrec),
        sizeof(SSL3_RECORD));

    /* Set proper sequence number for mac calculation */
    memcpy(&(s->s3->read_sequence[2]), &(rdata->packet[5]), 6);

    return (1);
}

int
dtls1_buffer_record(SSL *s, record_pqueue *queue, unsigned char *priority)
{
    DTLS1_RECORD_DATA *rdata;
    pitem *item;

    /* Limit the size of the queue to prevent DOS attacks */
    if (pqueue_size(queue->q) >= 100)
        return 0;

    rdata = OPENSSL_malloc(sizeof(DTLS1_RECORD_DATA));
    item = pitem_new(priority, rdata);
    if (rdata == NULL || item == NULL) {
        if (rdata != NULL)
            OPENSSL_free(rdata);
        if (item != NULL)
            pitem_free(item);

        SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    rdata->packet = s->packet;
    rdata->packet_length = s->packet_length;
    memcpy(&(rdata->rbuf), RECORD_LAYER_get_rbuf(&s->rlayer),
        sizeof(SSL3_BUFFER));
    memcpy(&(rdata->rrec), RECORD_LAYER_get_rrec(&s->rlayer),
        sizeof(SSL3_RECORD));

    item->data = rdata;

#ifndef OPENSSL_NO_SCTP
    /* Store bio_dgram_sctp_rcvinfo struct */
    if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
        (s->state == SSL3_ST_SR_FINISHED_A
         || s->state == SSL3_ST_CR_FINISHED_A)) {
        BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SCTP_GET_RCVINFO,
                 sizeof(rdata->recordinfo), &rdata->recordinfo);
    }
#endif

    s->packet = NULL;
    s->packet_length = 0;
    memset(RECORD_LAYER_get_rbuf(&s->rlayer), 0, sizeof(SSL3_BUFFER));
    memset(RECORD_LAYER_get_rrec(&s->rlayer), 0, sizeof(SSL3_RECORD));

    if (!ssl3_setup_buffers(s)) {
        SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
        if (rdata->rbuf.buf != NULL)
            OPENSSL_free(rdata->rbuf.buf);
        OPENSSL_free(rdata);
        pitem_free(item);
        return (-1);
    }

    /* insert should not fail, since duplicates are dropped */
    if (pqueue_insert(queue->q, item) == NULL) {
        SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
        if (rdata->rbuf.buf != NULL)
            OPENSSL_free(rdata->rbuf.buf);
        OPENSSL_free(rdata);
        pitem_free(item);
        return (-1);
    }

    return (1);
}

int dtls1_retrieve_buffered_record(SSL *s, record_pqueue *queue)
{
    pitem *item;

    item = pqueue_pop(queue->q);
    if (item) {
        dtls1_copy_record(s, item);

        OPENSSL_free(item->data);
        pitem_free(item);

        return (1);
    }

    return (0);
}

/*
 * retrieve a buffered record that belongs to the new epoch, i.e., not
 * processed yet
 */
#define dtls1_get_unprocessed_record(s) \
                   dtls1_retrieve_buffered_record((s), \
                   &((s)->d1->unprocessed_rcds))


int dtls1_process_buffered_records(SSL *s)
{
    pitem *item;

    item = pqueue_peek(s->d1->unprocessed_rcds.q);
    if (item) {
        /* Check if epoch is current. */
        if (s->d1->unprocessed_rcds.epoch != s->d1->r_epoch)
            return (1);         /* Nothing to do. */

        /* Process all the records. */
        while (pqueue_peek(s->d1->unprocessed_rcds.q)) {
            dtls1_get_unprocessed_record(s);
            if (!dtls1_process_record(s))
                return (0);
            if (dtls1_buffer_record(s, &(s->d1->processed_rcds),
                SSL3_RECORD_get_seq_num(RECORD_LAYER_get_rrec(&s->rlayer))) < 0)
                return -1;
        }
    }

    /*
     * sync epoch numbers once all the unprocessed records have been
     * processed
     */
    s->d1->processed_rcds.epoch = s->d1->r_epoch;
    s->d1->unprocessed_rcds.epoch = s->d1->r_epoch + 1;

    return (1);
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
 * Alert records (e.g. close_notify), ChangeCipherSpec records (not really
 * a surprise, but handled as if it were), or renegotiation requests.
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
int dtls1_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek)
{
    int al, i, j, ret;
    unsigned int n;
    SSL3_RECORD *rr;
    void (*cb) (const SSL *ssl, int type2, int val) = NULL;

    if (!SSL3_BUFFER_is_initialised(RECORD_LAYER_get_rbuf(&s->rlayer))) {
        /* Not initialized yet */
        if (!ssl3_setup_buffers(s))
            return (-1);
    }

    if ((type && (type != SSL3_RT_APPLICATION_DATA) &&
         (type != SSL3_RT_HANDSHAKE)) ||
        (peek && (type != SSL3_RT_APPLICATION_DATA))) {
        SSLerr(SSL_F_DTLS1_READ_BYTES, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    /*
     * check whether there's a handshake message (client hello?) waiting
     */
    if ((ret = have_handshake_fragment(s, type, buf, len, peek)))
        return ret;

    /*
     * Now s->d1->handshake_fragment_len == 0 if type == SSL3_RT_HANDSHAKE.
     */

#ifndef OPENSSL_NO_SCTP
    /*
     * Continue handshake if it had to be interrupted to read app data with
     * SCTP.
     */
    if ((!s->in_handshake && SSL_in_init(s)) ||
        (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
         (s->state == DTLS1_SCTP_ST_SR_READ_SOCK
          || s->state == DTLS1_SCTP_ST_CR_READ_SOCK)
         && s->s3->in_read_app_data != 2))
#else
    if (!s->in_handshake && SSL_in_init(s))
#endif
    {
        /* type == SSL3_RT_APPLICATION_DATA */
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }
    }

 start:
    s->rwstate = SSL_NOTHING;

    /*-
     * s->s3->rrec.type         - is the type of record
     * s->s3->rrec.data,    - data
     * s->s3->rrec.off,     - offset into 'data' for next read
     * s->s3->rrec.length,  - number of bytes.
     */
    rr = RECORD_LAYER_get_rrec(&s->rlayer);

    /*
     * We are not handshaking and have no data yet, so process data buffered
     * during the last handshake in advance, if any.
     */
    if (s->state == SSL_ST_OK && rr->length == 0) {
        pitem *item;
        item = pqueue_pop(s->d1->buffered_app_data.q);
        if (item) {
#ifndef OPENSSL_NO_SCTP
            /* Restore bio_dgram_sctp_rcvinfo struct */
            if (BIO_dgram_is_sctp(SSL_get_rbio(s))) {
                DTLS1_RECORD_DATA *rdata = (DTLS1_RECORD_DATA *)item->data;
                BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SCTP_SET_RCVINFO,
                         sizeof(rdata->recordinfo), &rdata->recordinfo);
            }
#endif

            dtls1_copy_record(s, item);

            OPENSSL_free(item->data);
            pitem_free(item);
        }
    }

    /* Check for timeout */
    if (dtls1_handle_timeout(s) > 0)
        goto start;

    /* get new packet if necessary */
    if ((rr->length == 0) || (s->rstate == SSL_ST_READ_BODY)) {
        ret = dtls1_get_record(s);
        if (ret <= 0) {
            ret = dtls1_read_failed(s, ret);
            /* anything other than a timeout is an error */
            if (ret <= 0)
                return (ret);
            else
                goto start;
        }
    }

    if (s->d1->listen && rr->type != SSL3_RT_HANDSHAKE) {
        rr->length = 0;
        goto start;
    }

    /* we now have a packet which can be read and processed */

    if (s->s3->change_cipher_spec /* set when we receive ChangeCipherSpec,
                                   * reset by ssl3_get_finished */
        && (rr->type != SSL3_RT_HANDSHAKE)) {
        /*
         * We now have application data between CCS and Finished. Most likely
         * the packets were reordered on their way, so buffer the application
         * data for later processing rather than dropping the connection.
         */
        if (dtls1_buffer_record(s, &(s->d1->buffered_app_data), rr->seq_num) <
            0) {
            SSLerr(SSL_F_DTLS1_READ_BYTES, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        rr->length = 0;
        goto start;
    }

    /*
     * If the other end has shut down, throw anything we read away (even in
     * 'peek' mode)
     */
    if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
        rr->length = 0;
        s->rwstate = SSL_NOTHING;
        return (0);
    }

    if (type == rr->type) {     /* SSL3_RT_APPLICATION_DATA or
                                 * SSL3_RT_HANDSHAKE */
        /*
         * make sure that we are not getting application data when we are
         * doing a handshake for the first time
         */
        if (SSL_in_init(s) && (type == SSL3_RT_APPLICATION_DATA) &&
            (s->enc_read_ctx == NULL)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_APP_DATA_IN_HANDSHAKE);
            goto f_err;
        }

        if (len <= 0)
            return (len);

        if ((unsigned int)len > rr->length)
            n = rr->length;
        else
            n = (unsigned int)len;

        memcpy(buf, &(rr->data[rr->off]), n);
        if (!peek) {
            rr->length -= n;
            rr->off += n;
            if (rr->length == 0) {
                s->rstate = SSL_ST_READ_HEADER;
                rr->off = 0;
            }
        }
#ifndef OPENSSL_NO_SCTP
        /*
         * We were about to renegotiate but had to read belated application
         * data first, so retry.
         */
        if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
            rr->type == SSL3_RT_APPLICATION_DATA &&
            (s->state == DTLS1_SCTP_ST_SR_READ_SOCK
             || s->state == DTLS1_SCTP_ST_CR_READ_SOCK)) {
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
        }

        /*
         * We might had to delay a close_notify alert because of reordered
         * app data. If there was an alert and there is no message to read
         * anymore, finally set shutdown.
         */
        if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
            s->d1->shutdown_received
            && !BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
            s->shutdown |= SSL_RECEIVED_SHUTDOWN;
            return (0);
        }
#endif
        return (n);
    }

    /*
     * If we get here, then type != rr->type; if we have a handshake message,
     * then it was unexpected (Hello Request or Client Hello).
     */

    /*
     * In case of record types for which we have 'fragment' storage, fill
     * that so that we can process the data at a fixed place.
     */
    {
        unsigned int k, dest_maxlen = 0;
        unsigned char *dest = NULL;
        unsigned int *dest_len = NULL;

        if (rr->type == SSL3_RT_HANDSHAKE) {
            dest_maxlen = sizeof s->d1->handshake_fragment;
            dest = s->d1->handshake_fragment;
            dest_len = &s->d1->handshake_fragment_len;
        } else if (rr->type == SSL3_RT_ALERT) {
            dest_maxlen = sizeof(s->d1->alert_fragment);
            dest = s->d1->alert_fragment;
            dest_len = &s->d1->alert_fragment_len;
        }
#ifndef OPENSSL_NO_HEARTBEATS
        else if (rr->type == TLS1_RT_HEARTBEAT) {
            /* We allow a 0 return */
            if(dtls1_process_heartbeat(s, SSL3_RECORD_get_data(&s->rlayer.rrec),
                    SSL3_RECORD_get_length(&s->rlayer.rrec)) < 0) {
                return -1;
            }
            /* Exit and notify application to read again */
            rr->length = 0;
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
            return (-1);
        }
#endif
        /* else it's a CCS message, or application data or wrong */
        else if (rr->type != SSL3_RT_CHANGE_CIPHER_SPEC) {
            /*
             * Application data while renegotiating is allowed. Try again
             * reading.
             */
            if (rr->type == SSL3_RT_APPLICATION_DATA) {
                BIO *bio;
                s->s3->in_read_app_data = 2;
                bio = SSL_get_rbio(s);
                s->rwstate = SSL_READING;
                BIO_clear_retry_flags(bio);
                BIO_set_retry_read(bio);
                return (-1);
            }

            /* Not certain if this is the right error handling */
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
            goto f_err;
        }

        if (dest_maxlen > 0) {
            /*
             * XDTLS: In a pathalogical case, the Client Hello may be
             * fragmented--don't always expect dest_maxlen bytes
             */
            if (rr->length < dest_maxlen) {
#ifdef DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
                /*
                 * for normal alerts rr->length is 2, while
                 * dest_maxlen is 7 if we were to handle this
                 * non-existing alert...
                 */
                FIX ME
#endif
                 s->rstate = SSL_ST_READ_HEADER;
                rr->length = 0;
                goto start;
            }

            /* now move 'n' bytes: */
            for (k = 0; k < dest_maxlen; k++) {
                dest[k] = rr->data[rr->off++];
                rr->length--;
            }
            *dest_len = dest_maxlen;
        }
    }

    /*-
     * s->d1->handshake_fragment_len == 12  iff  rr->type == SSL3_RT_HANDSHAKE;
     * s->d1->alert_fragment_len == 7      iff  rr->type == SSL3_RT_ALERT.
     * (Possibly rr is 'empty' now, i.e. rr->length may be 0.)
     */

    /* If we are a client, check for an incoming 'Hello Request': */
    if ((!s->server) &&
        (s->d1->handshake_fragment_len >= DTLS1_HM_HEADER_LENGTH) &&
        (s->d1->handshake_fragment[0] == SSL3_MT_HELLO_REQUEST) &&
        (s->session != NULL) && (s->session->cipher != NULL)) {
        s->d1->handshake_fragment_len = 0;

        if ((s->d1->handshake_fragment[1] != 0) ||
            (s->d1->handshake_fragment[2] != 0) ||
            (s->d1->handshake_fragment[3] != 0)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_BAD_HELLO_REQUEST);
            goto err;
        }

        /*
         * no need to check sequence number on HELLO REQUEST messages
         */

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                            s->d1->handshake_fragment, 4, s,
                            s->msg_callback_arg);

        if (SSL_is_init_finished(s) &&
            !(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS) &&
            !s->s3->renegotiate) {
            s->d1->handshake_read_seq++;
            s->new_session = 1;
            ssl3_renegotiate(s);
            if (ssl3_renegotiate_check(s)) {
                i = s->handshake_func(s);
                if (i < 0)
                    return (i);
                if (i == 0) {
                    SSLerr(SSL_F_DTLS1_READ_BYTES,
                           SSL_R_SSL_HANDSHAKE_FAILURE);
                    return (-1);
                }

                if (!(s->mode & SSL_MODE_AUTO_RETRY)) {
                    if (SSL3_BUFFER_get_left(
                        RECORD_LAYER_get_rbuf(&s->rlayer)) == 0) {
                        /* no read-ahead left? */
                        BIO *bio;
                        /*
                         * In the case where we try to read application data,
                         * but we trigger an SSL handshake, we return -1 with
                         * the retry option set.  Otherwise renegotiation may
                         * cause nasty problems in the blocking world
                         */
                        s->rwstate = SSL_READING;
                        bio = SSL_get_rbio(s);
                        BIO_clear_retry_flags(bio);
                        BIO_set_retry_read(bio);
                        return (-1);
                    }
                }
            }
        }
        /*
         * we either finished a handshake or ignored the request, now try
         * again to obtain the (application) data we were asked for
         */
        goto start;
    }

    if (s->d1->alert_fragment_len >= DTLS1_AL_HEADER_LENGTH) {
        int alert_level = s->d1->alert_fragment[0];
        int alert_descr = s->d1->alert_fragment[1];

        s->d1->alert_fragment_len = 0;

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_ALERT,
                            s->d1->alert_fragment, 2, s, s->msg_callback_arg);

        if (s->info_callback != NULL)
            cb = s->info_callback;
        else if (s->ctx->info_callback != NULL)
            cb = s->ctx->info_callback;

        if (cb != NULL) {
            j = (alert_level << 8) | alert_descr;
            cb(s, SSL_CB_READ_ALERT, j);
        }

        if (alert_level == SSL3_AL_WARNING) {
            s->s3->warn_alert = alert_descr;
            if (alert_descr == SSL_AD_CLOSE_NOTIFY) {
#ifndef OPENSSL_NO_SCTP
                /*
                 * With SCTP and streams the socket may deliver app data
                 * after a close_notify alert. We have to check this first so
                 * that nothing gets discarded.
                 */
                if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
                    BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
                    s->d1->shutdown_received = 1;
                    s->rwstate = SSL_READING;
                    BIO_clear_retry_flags(SSL_get_rbio(s));
                    BIO_set_retry_read(SSL_get_rbio(s));
                    return -1;
                }
#endif
                s->shutdown |= SSL_RECEIVED_SHUTDOWN;
                return (0);
            }
#if 0
            /* XXX: this is a possible improvement in the future */
            /* now check if it's a missing record */
            if (alert_descr == DTLS1_AD_MISSING_HANDSHAKE_MESSAGE) {
                unsigned short seq;
                unsigned int frag_off;
                unsigned char *p = &(s->d1->alert_fragment[2]);

                n2s(p, seq);
                n2l3(p, frag_off);

                dtls1_retransmit_message(s,
                                         dtls1_get_queue_priority
                                         (frag->msg_header.seq, 0), frag_off,
                                         &found);
                if (!found && SSL_in_init(s)) {
                    /*
                     * fprintf( stderr,"in init = %d\n", SSL_in_init(s));
                     */
                    /*
                     * requested a message not yet sent, send an alert
                     * ourselves
                     */
                    ssl3_send_alert(s, SSL3_AL_WARNING,
                                    DTLS1_AD_MISSING_HANDSHAKE_MESSAGE);
                }
            }
#endif
        } else if (alert_level == SSL3_AL_FATAL) {
            char tmp[16];

            s->rwstate = SSL_NOTHING;
            s->s3->fatal_alert = alert_descr;
            SSLerr(SSL_F_DTLS1_READ_BYTES,
                   SSL_AD_REASON_OFFSET + alert_descr);
            BIO_snprintf(tmp, sizeof tmp, "%d", alert_descr);
            ERR_add_error_data(2, "SSL alert number ", tmp);
            s->shutdown |= SSL_RECEIVED_SHUTDOWN;
            SSL_CTX_remove_session(s->ctx, s->session);
            return (0);
        } else {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_UNKNOWN_ALERT_TYPE);
            goto f_err;
        }

        goto start;
    }

    if (s->shutdown & SSL_SENT_SHUTDOWN) { /* but we have not received a
                                            * shutdown */
        s->rwstate = SSL_NOTHING;
        rr->length = 0;
        return (0);
    }

    if (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC) {
        struct ccs_header_st ccs_hdr;
        unsigned int ccs_hdr_len = DTLS1_CCS_HEADER_LENGTH;

        dtls1_get_ccs_header(rr->data, &ccs_hdr);

        if (s->version == DTLS1_BAD_VER)
            ccs_hdr_len = 3;

        /*
         * 'Change Cipher Spec' is just a single byte, so we know exactly
         * what the record payload has to look like
         */
        /* XDTLS: check that epoch is consistent */
        if ((rr->length != ccs_hdr_len) ||
            (rr->off != 0) || (rr->data[0] != SSL3_MT_CCS)) {
            i = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_BAD_CHANGE_CIPHER_SPEC);
            goto err;
        }

        rr->length = 0;

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_CHANGE_CIPHER_SPEC,
                            rr->data, 1, s, s->msg_callback_arg);

        /*
         * We can't process a CCS now, because previous handshake messages
         * are still missing, so just drop it.
         */
        if (!s->d1->change_cipher_spec_ok) {
            goto start;
        }

        s->d1->change_cipher_spec_ok = 0;

        s->s3->change_cipher_spec = 1;
        if (!ssl3_do_change_cipher_spec(s))
            goto err;

        /* do this whenever CCS is processed */
        dtls1_reset_seq_numbers(s, SSL3_CC_READ);

        if (s->version == DTLS1_BAD_VER)
            s->d1->handshake_read_seq++;

#ifndef OPENSSL_NO_SCTP
        /*
         * Remember that a CCS has been received, so that an old key of
         * SCTP-Auth can be deleted when a CCS is sent. Will be ignored if no
         * SCTP is used
         */
        BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD, 1, NULL);
#endif

        goto start;
    }

    /*
     * Unexpected handshake message (Client Hello, or protocol violation)
     */
    if ((s->d1->handshake_fragment_len >= DTLS1_HM_HEADER_LENGTH) &&
        !s->in_handshake) {
        struct hm_header_st msg_hdr;

        /* this may just be a stale retransmit */
        dtls1_get_message_header(rr->data, &msg_hdr);
        if (rr->epoch != s->d1->r_epoch) {
            rr->length = 0;
            goto start;
        }

        /*
         * If we are server, we may have a repeated FINISHED of the client
         * here, then retransmit our CCS and FINISHED.
         */
        if (msg_hdr.type == SSL3_MT_FINISHED) {
            if (dtls1_check_timeout_num(s) < 0)
                return -1;

            dtls1_retransmit_buffered_messages(s);
            rr->length = 0;
            goto start;
        }

        if (((s->state & SSL_ST_MASK) == SSL_ST_OK) &&
            !(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)) {
            s->state = s->server ? SSL_ST_ACCEPT : SSL_ST_CONNECT;
            s->renegotiate = 1;
            s->new_session = 1;
        }
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }

        if (!(s->mode & SSL_MODE_AUTO_RETRY)) {
            if (SSL3_BUFFER_get_left(
                RECORD_LAYER_get_rbuf(&s->rlayer)) == 0) {
                /* no read-ahead left? */
                BIO *bio;
                /*
                 * In the case where we try to read application data, but we
                 * trigger an SSL handshake, we return -1 with the retry
                 * option set.  Otherwise renegotiation may cause nasty
                 * problems in the blocking world
                 */
                s->rwstate = SSL_READING;
                bio = SSL_get_rbio(s);
                BIO_clear_retry_flags(bio);
                BIO_set_retry_read(bio);
                return (-1);
            }
        }
        goto start;
    }

    switch (rr->type) {
    default:
        /* TLS just ignores unknown message types */
        if (s->version == TLS1_VERSION) {
            rr->length = 0;
            goto start;
        }
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
        goto f_err;
    case SSL3_RT_CHANGE_CIPHER_SPEC:
    case SSL3_RT_ALERT:
    case SSL3_RT_HANDSHAKE:
        /*
         * we already handled all of these, with the possible exception of
         * SSL3_RT_HANDSHAKE when s->in_handshake is set, but that should not
         * happen when type != rr->type
         */
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_DTLS1_READ_BYTES, ERR_R_INTERNAL_ERROR);
        goto f_err;
    case SSL3_RT_APPLICATION_DATA:
        /*
         * At this point, we were expecting handshake data, but have
         * application data.  If the library was running inside ssl3_read()
         * (i.e. in_read_app_data is set) and it makes sense to read
         * application data at this point (session renegotiation not yet
         * started), we will indulge it.
         */
        if (s->s3->in_read_app_data &&
            (s->s3->total_renegotiations != 0) &&
            (((s->state & SSL_ST_CONNECT) &&
              (s->state >= SSL3_ST_CW_CLNT_HELLO_A) &&
              (s->state <= SSL3_ST_CR_SRVR_HELLO_A)
             ) || ((s->state & SSL_ST_ACCEPT) &&
                   (s->state <= SSL3_ST_SW_HELLO_REQ_A) &&
                   (s->state >= SSL3_ST_SR_CLNT_HELLO_A)
             )
            )) {
            s->s3->in_read_app_data = 2;
            return (-1);
        } else {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_DTLS1_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
            goto f_err;
        }
    }
    /* not reached */

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (-1);
}


        /*
         * this only happens when a client hello is received and a handshake
         * is started.
         */
static int
have_handshake_fragment(SSL *s, int type, unsigned char *buf,
                        int len, int peek)
{

    if ((type == SSL3_RT_HANDSHAKE) && (s->d1->handshake_fragment_len > 0))
        /* (partially) satisfy request from storage */
    {
        unsigned char *src = s->d1->handshake_fragment;
        unsigned char *dst = buf;
        unsigned int k, n;

        /* peek == 0 */
        n = 0;
        while ((len > 0) && (s->d1->handshake_fragment_len > 0)) {
            *dst++ = *src++;
            len--;
            s->d1->handshake_fragment_len--;
            n++;
        }
        /* move any remaining fragment bytes: */
        for (k = 0; k < s->d1->handshake_fragment_len; k++)
            s->d1->handshake_fragment[k] = *src++;
        return n;
    }

    return 0;
}

/*
 * Call this to write data in records of type 'type' It will return <= 0 if
 * not all data has been sent or non-blocking IO.
 */
int dtls1_write_bytes(SSL *s, int type, const void *buf, int len)
{
    int i;

    OPENSSL_assert(len <= SSL3_RT_MAX_PLAIN_LENGTH);
    s->rwstate = SSL_NOTHING;
    i = do_dtls1_write(s, type, buf, len, 0);
    return i;
}

int do_dtls1_write(SSL *s, int type, const unsigned char *buf,
                   unsigned int len, int create_empty_fragment)
{
    unsigned char *p, *pseq;
    int i, mac_size, clear = 0;
    int prefix_len = 0;
    int eivlen;
    SSL3_RECORD *wr;
    SSL3_BUFFER *wb;
    SSL_SESSION *sess;

    wb = RECORD_LAYER_get_wbuf(&s->rlayer);

    /*
     * first check if there is a SSL3_BUFFER still being written out.  This
     * will happen with non blocking IO
     */
    if (SSL3_BUFFER_get_left(wb) != 0) {
        OPENSSL_assert(0);      /* XDTLS: want to see if we ever get here */
        return (ssl3_write_pending(s, type, buf, len));
    }

    /* If we have an alert to send, lets send it */
    if (s->s3->alert_dispatch) {
        i = s->method->ssl_dispatch_alert(s);
        if (i <= 0)
            return (i);
        /* if it went, fall through and send more stuff */
    }

    if (len == 0 && !create_empty_fragment)
        return 0;

    wr = RECORD_LAYER_get_wrec(&s->rlayer);
    sess = s->session;

    if ((sess == NULL) ||
        (s->enc_write_ctx == NULL) || (EVP_MD_CTX_md(s->write_hash) == NULL))
        clear = 1;

    if (clear)
        mac_size = 0;
    else {
        mac_size = EVP_MD_CTX_size(s->write_hash);
        if (mac_size < 0)
            goto err;
    }

    p = wb->buf + prefix_len;

    /* write the header */

    *(p++) = type & 0xff;
    wr->type = type;
    /*
     * Special case: for hello verify request, client version 1.0 and we
     * haven't decided which version to use yet send back using version 1.0
     * header: otherwise some clients will ignore it.
     */
    if (s->method->version == DTLS_ANY_VERSION) {
        *(p++) = DTLS1_VERSION >> 8;
        *(p++) = DTLS1_VERSION & 0xff;
    } else {
        *(p++) = s->version >> 8;
        *(p++) = s->version & 0xff;
    }

    /* field where we are to write out packet epoch, seq num and len */
    pseq = p;
    p += 10;

    /* Explicit IV length, block ciphers appropriate version flag */
    if (s->enc_write_ctx) {
        int mode = EVP_CIPHER_CTX_mode(s->enc_write_ctx);
        if (mode == EVP_CIPH_CBC_MODE) {
            eivlen = EVP_CIPHER_CTX_iv_length(s->enc_write_ctx);
            if (eivlen <= 1)
                eivlen = 0;
        }
        /* Need explicit part of IV for GCM mode */
        else if (mode == EVP_CIPH_GCM_MODE)
            eivlen = EVP_GCM_TLS_EXPLICIT_IV_LEN;
        else
            eivlen = 0;
    } else
        eivlen = 0;

    /* lets setup the record stuff. */
    wr->data = p + eivlen;      /* make room for IV in case of CBC */
    wr->length = (int)len;
    wr->input = (unsigned char *)buf;

    /*
     * we now 'read' from wr->input, wr->length bytes into wr->data
     */

    /* first we compress */
    if (s->compress != NULL) {
        if (!ssl3_do_compress(s)) {
            SSLerr(SSL_F_DO_DTLS1_WRITE, SSL_R_COMPRESSION_FAILURE);
            goto err;
        }
    } else {
        memcpy(wr->data, wr->input, wr->length);
        wr->input = wr->data;
    }

    /*
     * we should still have the output to wr->data and the input from
     * wr->input.  Length should be wr->length. wr->data still points in the
     * wb->buf
     */

    if (mac_size != 0) {
        if (s->method->ssl3_enc->mac(s, &(p[wr->length + eivlen]), 1) < 0)
            goto err;
        wr->length += mac_size;
    }

    /* this is true regardless of mac size */
    wr->input = p;
    wr->data = p;

    if (eivlen)
        wr->length += eivlen;

    if (s->method->ssl3_enc->enc(s, 1) < 1)
        goto err;

    /* record length after mac and block padding */
    /*
     * if (type == SSL3_RT_APPLICATION_DATA || (type == SSL3_RT_ALERT && !
     * SSL_in_init(s)))
     */

    /* there's only one epoch between handshake and app data */

    s2n(s->d1->w_epoch, pseq);

    /* XDTLS: ?? */
    /*
     * else s2n(s->d1->handshake_epoch, pseq);
     */

    memcpy(pseq, &(s->s3->write_sequence[2]), 6);
    pseq += 6;
    s2n(wr->length, pseq);

    if (s->msg_callback)
        s->msg_callback(1, 0, SSL3_RT_HEADER, pseq - DTLS1_RT_HEADER_LENGTH,
                        DTLS1_RT_HEADER_LENGTH, s, s->msg_callback_arg);

    /*
     * we should now have wr->data pointing to the encrypted data, which is
     * wr->length long
     */
    wr->type = type;            /* not needed but helps for debugging */
    wr->length += DTLS1_RT_HEADER_LENGTH;

    ssl3_record_sequence_update(&(s->s3->write_sequence[0]));

    if (create_empty_fragment) {
        /*
         * we are in a recursive call; just return the length, don't write
         * out anything here
         */
        return wr->length;
    }

    /* now let's set up wb */
    wb->left = prefix_len + wr->length;
    wb->offset = 0;

    /*
     * memorize arguments so that ssl3_write_pending can detect bad write
     * retries later
     */
    s->s3->wpend_tot = len;
    s->s3->wpend_buf = buf;
    s->s3->wpend_type = type;
    s->s3->wpend_ret = len;

    /* we now just need to write the buffer */
    return ssl3_write_pending(s, type, buf, len);
 err:
    return -1;
}

int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap)
{
    int cmp;
    unsigned int shift;
    const unsigned char *seq = s->s3->read_sequence;

    cmp = satsub64be(seq, bitmap->max_seq_num);
    if (cmp > 0) {
        SSL3_RECORD_set_seq_num(RECORD_LAYER_get_rrec(&s->rlayer), seq);
        return 1;               /* this record in new */
    }
    shift = -cmp;
    if (shift >= sizeof(bitmap->map) * 8)
        return 0;               /* stale, outside the window */
    else if (bitmap->map & (1UL << shift))
        return 0;               /* record previously received */

    SSL3_RECORD_set_seq_num(RECORD_LAYER_get_rrec(&s->rlayer), seq);
    return 1;
}

void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap)
{
    int cmp;
    unsigned int shift;
    const unsigned char *seq = s->s3->read_sequence;

    cmp = satsub64be(seq, bitmap->max_seq_num);
    if (cmp > 0) {
        shift = cmp;
        if (shift < sizeof(bitmap->map) * 8)
            bitmap->map <<= shift, bitmap->map |= 1UL;
        else
            bitmap->map = 1UL;
        memcpy(bitmap->max_seq_num, seq, 8);
    } else {
        shift = -cmp;
        if (shift < sizeof(bitmap->map) * 8)
            bitmap->map |= 1UL << shift;
    }
}

DTLS1_BITMAP *dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr,
                                      unsigned int *is_next_epoch)
{

    *is_next_epoch = 0;

    /* In current epoch, accept HM, CCS, DATA, & ALERT */
    if (rr->epoch == s->d1->r_epoch)
        return &s->d1->bitmap;

    /* Only HM and ALERT messages can be from the next epoch */
    else if (rr->epoch == (unsigned long)(s->d1->r_epoch + 1) &&
             (rr->type == SSL3_RT_HANDSHAKE || rr->type == SSL3_RT_ALERT)) {
        *is_next_epoch = 1;
        return &s->d1->next_bitmap;
    }

    return NULL;
}

void dtls1_reset_seq_numbers(SSL *s, int rw)
{
    unsigned char *seq;
    unsigned int seq_bytes = sizeof(s->s3->read_sequence);

    if (rw & SSL3_CC_READ) {
        seq = s->s3->read_sequence;
        s->d1->r_epoch++;
        memcpy(&(s->d1->bitmap), &(s->d1->next_bitmap), sizeof(DTLS1_BITMAP));
        memset(&(s->d1->next_bitmap), 0x00, sizeof(DTLS1_BITMAP));
    } else {
        seq = s->s3->write_sequence;
        memcpy(s->d1->last_write_sequence, seq,
               sizeof(s->s3->write_sequence));
        s->d1->w_epoch++;
    }

    memset(seq, 0x00, seq_bytes);
}
