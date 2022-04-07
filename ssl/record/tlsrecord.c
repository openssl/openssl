/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include "internal/e_os.h"
#include "record.h"
#include "recordmethod.h"

struct ossl_record_layer_st
{
    int isdtls;
    int version;
    int role;
    int direction;
    BIO *bio;
    /* Types match the equivalent structures in the SSL object */
    uint64_t options;
    /*
     * TODO(RECLAYER): Should we take the opportunity to make this uint64_t
     * even though upper layer continue to use uint32_t?
     */
    uint32_t mode;

    /* read IO goes into here */
    SSL3_BUFFER rbuf;

    /* used internally to point at a raw packet */
    unsigned char *packet;
    size_t packet_length;

    int alert;

    /*
     * Read as many input bytes as possible (for
     * non-blocking reads)
     * TODO(RECLAYER): Why isn't this just an option?
     */
    int read_ahead;
};

static int tls_set1_bio(OSSL_RECORD_LAYER *rl, BIO *bio);

# define SSL_AD_NO_ALERT    -1

static void rlayer_fatal(OSSL_RECORD_LAYER *rl, int al, int reason,
                         const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    ERR_vset_error(ERR_LIB_SSL, reason, fmt, args);
    va_end(args);

    rl->alert = al;
}


# define RLAYERfatal(rl, al, r) RLAYERfatal_data((rl), (al), (r), NULL)
# define RLAYERfatal_data                                          \
    (ERR_new(),                                                    \
     ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC),      \
     rlayer_fatal)

static int rlayer_allow_compression(OSSL_RECORD_LAYER *rl)
{
    if (rl->options & SSL_OP_NO_COMPRESSION)
        return 0;
#if 0
    /* TODO(RECLAYER): Implement ssl_security inside the record layer */
    return ssl_security(s, SSL_SECOP_COMPRESSION, 0, 0, NULL);
#else
    return 1;
#endif
}

static int rlayer_setup_read_buffer(OSSL_RECORD_LAYER *rl)
{
    unsigned char *p;
    size_t len, align = 0, headerlen;
    SSL3_BUFFER *b;

    b = &rl->rbuf;

    if (rl->isdtls)
        headerlen = DTLS1_RT_HEADER_LENGTH;
    else
        headerlen = SSL3_RT_HEADER_LENGTH;

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
    align = (-SSL3_RT_HEADER_LENGTH) & (SSL3_ALIGN_PAYLOAD - 1);
#endif

    if (b->buf == NULL) {
        len = SSL3_RT_MAX_PLAIN_LENGTH
            + SSL3_RT_MAX_ENCRYPTED_OVERHEAD + headerlen + align;
#ifndef OPENSSL_NO_COMP
        if (rlayer_allow_compression(rl))
            len += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
        if (b->default_len > len)
            len = b->default_len;
        if ((p = OPENSSL_malloc(len)) == NULL) {
            /*
             * We've got a malloc failure, and we're still initialising buffers.
             * We assume we're so doomed that we won't even be able to send an
             * alert.
             */
            RLAYERfatal(rl, SSL_AD_NO_ALERT, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        b->buf = p;
        b->len = len;
    }

    return 1;
}

static int rlayer_release_read_buffer(OSSL_RECORD_LAYER *rl)
{
    SSL3_BUFFER *b;

    b = &rl->rbuf;
    if (rl->options & SSL_OP_CLEANSE_PLAINTEXT)
        OPENSSL_cleanse(b->buf, b->len);
    OPENSSL_free(b->buf);
    b->buf = NULL;
    return 1;
}

/*
 * Return values are as per SSL_read()
 */
static int tls_read_n(OSSL_RECORD_LAYER *rl, size_t n, size_t max, int extend,
                      int clearold, size_t *readbytes)
{
    /*
     * If extend == 0, obtain new n-byte packet; if extend == 1, increase
     * packet by another n bytes. The packet will be in the sub-array of
     * s->rlayer.rbuf.buf specified by s->rlayer.packet and
     * s->rlayer.packet_length. (If s->rlayer.read_ahead is set, 'max' bytes may
     * be stored in rbuf [plus s->rlayer.packet_length bytes if extend == 1].)
     * if clearold == 1, move the packet to the start of the buffer; if
     * clearold == 0 then leave any old packets where they were
     */
    size_t len, left, align = 0;
    unsigned char *pkt;
    SSL3_BUFFER *rb;

    if (n == 0)
        return OSSL_RECORD_RETURN_NON_FATAL_ERR;

    rb = &rl->rbuf;
    if (rb->buf == NULL) {
        if (!rlayer_setup_read_buffer(rl)) {
            /* RLAYERfatal() already called */
            return OSSL_RECORD_RETURN_FATAL;
        }
    }

    left = rb->left;
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD != 0
    align = (size_t)rb->buf + SSL3_RT_HEADER_LENGTH;
    align = SSL3_ALIGN_PAYLOAD - 1 - ((align - 1) % SSL3_ALIGN_PAYLOAD);
#endif

    if (!extend) {
        /* start with empty packet ... */
        if (left == 0) {
            rb->offset = align;
        } else if (align != 0 && left >= SSL3_RT_HEADER_LENGTH) {
            /*
             * check if next packet length is large enough to justify payload
             * alignment...
             */
            pkt = rb->buf + rb->offset;
            if (pkt[0] == SSL3_RT_APPLICATION_DATA
                    && (pkt[3] << 8 | pkt[4]) >= 128) {
                /*
                 * Note that even if packet is corrupted and its length field
                 * is insane, we can only be led to wrong decision about
                 * whether memmove will occur or not. Header values has no
                 * effect on memmove arguments and therefore no buffer
                 * overrun can be triggered.
                 */
                memmove(rb->buf + align, pkt, left);
                rb->offset = align;
            }
        }
        rl->packet = rb->buf + rb->offset;
        rl->packet_length = 0;
        /* ... now we can act as if 'extend' was set */
    }

    len = rl->packet_length;
    pkt = rb->buf + align;
    /*
     * Move any available bytes to front of buffer: 'len' bytes already
     * pointed to by 'packet', 'left' extra ones at the end
     */
    if (rl->packet != pkt && clearold == 1) {
        memmove(pkt, rl->packet, len + left);
        rl->packet = pkt;
        rb->offset = len + align;
    }

    /*
     * For DTLS/UDP reads should not span multiple packets because the read
     * operation returns the whole packet at once (as long as it fits into
     * the buffer).
     */
    if (rl->isdtls) {
        if (left == 0 && extend)
            return 0;
        if (left > 0 && n > left)
            n = left;
    }

    /* if there is enough in the buffer from a previous read, take some */
    if (left >= n) {
        rl->packet_length += n;
        rb->left = left - n;
        rb->offset += n;
        *readbytes = n;
        return OSSL_RECORD_RETURN_SUCCESS;
    }

    /* else we need to read more data */

    if (n > rb->len - rb->offset) {
        /* does not happen */
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return OSSL_RECORD_RETURN_FATAL;
    }

    /*
     * Ktls always reads full records.
     * Also, we always act like read_ahead is set for DTLS.
     */
    if (!BIO_get_ktls_recv(s->rbio) && !rl->read_ahead
            && !rl->isdtls) {
        /* ignore max parameter */
        max = n;
    } else {
        if (max < n)
            max = n;
        if (max > rb->len - rb->offset)
            max = rb->len - rb->offset;
    }

    while (left < n) {
        size_t bioread = 0;
        int ret;

        /*
         * Now we have len+left bytes at the front of s->s3.rbuf.buf and
         * need to read in more until we have len+n (up to len+max if
         * possible)
         */

        clear_sys_error();
        if (rl->bio != NULL) {
            ret = BIO_read(rl->bio, pkt + len + left, max - left);
            if (ret > 0) {
                bioread = ret;
                ret = OSSL_RECORD_RETURN_SUCCESS;
            } else if (BIO_should_retry(rl->bio)) {
                ret = OSSL_RECORD_RETURN_RETRY;
            } else if (BIO_eof(rl->bio)) {
                ret = OSSL_RECORD_RETURN_EOF;
            } else {
                ret = OSSL_RECORD_RETURN_FATAL;
            }
        } else {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_READ_BIO_NOT_SET);
            ret = OSSL_RECORD_RETURN_FATAL;
        }

        if (ret <= OSSL_RECORD_RETURN_RETRY) {
            rb->left = left;
            if (rl->mode & SSL_MODE_RELEASE_BUFFERS && !rl->isdtls)
                if (len + left == 0)
                    rlayer_release_read_buffer(rl);
            return ret;
        }
        left += bioread;
        /*
         * reads should *never* span multiple packets for DTLS because the
         * underlying transport protocol is message oriented as opposed to
         * byte oriented as in the TLS case.
         */
        if (rl->isdtls) {
            if (n > left)
                n = left;       /* makes the while condition false */
        }
    }

    /* done reading, now the book-keeping */
    rb->offset += n;
    rb->left = left - n;
    rl->packet_length += n;
    *readbytes = n;
    return OSSL_RECORD_RETURN_SUCCESS;
}

static OSSL_RECORD_LAYER *tls_new_record_layer(int vers, int role, int direction,
                                               int level, unsigned char *secret,
                                               size_t secretlen, SSL_CIPHER *c,
                                               BIO *transport, BIO_ADDR *local,
                                               BIO_ADDR *peer,
                                               const OSSL_PARAM *settings,
                                               const OSSL_PARAM *options)
{
    OSSL_RECORD_LAYER *rl = OPENSSL_zalloc(sizeof(*rl));
    const OSSL_PARAM *p;

    if (rl == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (transport != NULL && !BIO_up_ref(transport)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    p = OSSL_PARAM_locate_const(options, OSSL_LIBSSL_RECORD_LAYER_PARAM_OPTIONS);
    if (p != NULL && !OSSL_PARAM_get_uint64(p, &rl->options)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_FAILED_TO_GET_PARAMETER);
        goto err;
    }

    p = OSSL_PARAM_locate_const(options, OSSL_LIBSSL_RECORD_LAYER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_get_uint32(p, &rl->mode)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_FAILED_TO_GET_PARAMETER);
        goto err;
    }


    p = OSSL_PARAM_locate_const(options, OSSL_LIBSSL_RECORD_LAYER_PARAM_READ_AHEAD);
    if (p != NULL && !OSSL_PARAM_get_int(p, &rl->read_ahead)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_FAILED_TO_GET_PARAMETER);
        goto err;
    }

    rl->version = vers;
    rl->role = role;
    rl->direction = direction;
    if (!tls_set1_bio(rl, transport))
        goto err;

    return rl;
 err:
    OPENSSL_free(rl);
    return NULL;
}

static OSSL_RECORD_LAYER *dtls_new_record_layer(int vers, int role, int direction,
                                                int level, unsigned char *secret,
                                                size_t secretlen, SSL_CIPHER *c,
                                                BIO *transport, BIO_ADDR *local,
                                                BIO_ADDR *peer,
                                                const OSSL_PARAM *settings,
                                                const OSSL_PARAM *options)
{
    OSSL_RECORD_LAYER *rl = tls_new_record_layer(vers, role, direction, level,
                                                 secret, secretlen, c, transport,
                                                 local, peer, settings, options);

    if (rl == NULL)
        return NULL;

    rl->isdtls = 1;

    return rl;
}

static void tls_free(OSSL_RECORD_LAYER *rl)
{
    BIO_free(rl->bio);
    OPENSSL_free(rl);
}

static int tls_reset(OSSL_RECORD_LAYER *rl)
{
    memset(rl, 0, sizeof(*rl));
    return 1;
}

static int tls_unprocessed_read_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static int tls_processed_read_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static size_t tls_app_data_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static int tls_write_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static size_t tls_get_max_record_len(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static size_t tls_get_max_records(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static int tls_write_records(OSSL_RECORD_LAYER *rl,
                             OSSL_RECORD_TEMPLATE **templates, size_t numtempl,
                             size_t allowance, size_t *sent)
{
    return 0;
}

static int tls_retry_write_records(OSSL_RECORD_LAYER *rl, size_t allowance,
                                   size_t *sent)
{
    return 0;
}

static int tls_read_record(OSSL_RECORD_LAYER *rl, void **rechandle,
                           int *rversion, int *type, unsigned char **data,
                           size_t *datalen, uint16_t *epoch,
                           unsigned char *seq_num)
{
    return 0;
}

static void tls_release_record(OSSL_RECORD_LAYER *rl, void *rechandle)
{
    return;
}

static int tls_get_alert_code(OSSL_RECORD_LAYER *rl)
{
    return rl->alert;
}

static int tls_set1_bio(OSSL_RECORD_LAYER *rl, BIO *bio)
{
    if (bio != NULL && !BIO_up_ref(bio))
        return 0;
    BIO_free(rl->bio);
    rl->bio = bio;

    return 1;
}

static SSL3_BUFFER *tls_get0_rbuf(OSSL_RECORD_LAYER *rl)
{
    return &rl->rbuf;
}

static unsigned char *tls_get0_packet(OSSL_RECORD_LAYER *rl)
{
    return rl->packet;
}

static void tls_set0_packet(OSSL_RECORD_LAYER *rl, unsigned char *packet,
                            size_t packetlen)
{
    rl->packet = packet;
    rl->packet_length = packetlen;
}

static size_t tls_get_packet_length(OSSL_RECORD_LAYER *rl)
{
    return rl->packet_length;
}

static void tls_reset_packet_length(OSSL_RECORD_LAYER *rl)
{
    rl->packet_length = 0;
}

const OSSL_RECORD_METHOD ossl_tls_record_method = {
    tls_new_record_layer,
    tls_free,
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

    /*
     * TODO(RECLAYER): Remove these. These function pointers are temporary hacks
     * during the record layer refactoring. They need to be removed before the
     * refactor is complete.
     */
    tls_read_n,
    tls_get0_rbuf,
    tls_get0_packet,
    tls_set0_packet,
    tls_get_packet_length,
    tls_reset_packet_length
};

const OSSL_RECORD_METHOD ossl_dtls_record_method = {
    dtls_new_record_layer,
    tls_free,
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

    /*
     * TODO(RECLAYER): Remove these. These function pointers are temporary hacks
     * during the record layer refactoring. They need to be removed before the
     * refactor is complete.
     */
    tls_read_n,
    tls_get0_rbuf,
    tls_get0_packet,
    tls_set0_packet,
    tls_get_packet_length,
    tls_reset_packet_length
};
