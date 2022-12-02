/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include "quictestlib.h"
#include "../testutil.h"
#include "internal/quic_wire_pkt.h"
#include "internal/quic_record_tx.h"
#include "internal/packet.h"

#define GROWTH_ALLOWANCE 1024

struct ossl_quic_fault {
    QUIC_TSERVER *qtserv;

    /* Plain packet mutations */
    /* Header for the plaintext packet */
    QUIC_PKT_HDR pplainhdr;
    /* iovec for the plaintext packet data buffer */
    OSSL_QTX_IOVEC pplainio;
    /* Allocted size of the plaintext packet data buffer */
    size_t pplainbuf_alloc;
    ossl_quic_fault_on_packet_plain_cb pplaincb;
    void *pplaincbarg;

    /* Handshake message mutations */
    /* Handshake message buffer */
    unsigned char *handbuf;
    /* Allocated size of the handshake message buffer */
    size_t handbufalloc;
    /* Actual length of the handshake message */
    size_t handbuflen;
    ossl_quic_fault_on_handshake_cb handshakecb;
    void *handshakecbarg;
    ossl_quic_fault_on_enc_ext_cb encextcb;
    void *encextcbarg;
};

static void packet_plain_finish(void *arg);
static void handshake_finish(void *arg);

int qtest_create_quic_objects(SSL_CTX *clientctx, char *certfile, char *keyfile,
                              QUIC_TSERVER **qtserv, SSL **cssl,
                              OSSL_QUIC_FAULT **fault)
{
    /* ALPN value as recognised by QUIC_TSERVER */
    unsigned char alpn[] = { 8, 'o', 's', 's', 'l', 't', 'e', 's', 't' };
    QUIC_TSERVER_ARGS tserver_args = {0};
    BIO *bio1 = NULL, *bio2 = NULL;
    BIO_ADDR *peeraddr = NULL;
    struct in_addr ina = {0};

    *qtserv = NULL;
    if (fault != NULL)
        *fault = NULL;
    *cssl = SSL_new(clientctx);
    if (!TEST_ptr(*cssl))
        return 0;

    if (!TEST_true(SSL_set_blocking_mode(*cssl, 0)))
        goto err;

    /* SSL_set_alpn_protos returns 0 for success! */
    if (!TEST_false(SSL_set_alpn_protos(*cssl, alpn, sizeof(alpn))))
        goto err;

    if (!TEST_true(BIO_new_bio_dgram_pair(&bio1, 0, &bio2, 0)))
        goto err;

    if (!TEST_true(BIO_dgram_set_caps(bio1, BIO_DGRAM_CAP_HANDLES_DST_ADDR))
            || !TEST_true(BIO_dgram_set_caps(bio2, BIO_DGRAM_CAP_HANDLES_DST_ADDR)))
        goto err;

    SSL_set_bio(*cssl, bio1, bio1);

    if (!TEST_ptr(peeraddr = BIO_ADDR_new()))
        goto err;

    /* Dummy server address */
    if (!TEST_true(BIO_ADDR_rawmake(peeraddr, AF_INET, &ina, sizeof(ina),
                                    htons(0))))
        goto err;

    if (!TEST_true(SSL_set_initial_peer_addr(*cssl, peeraddr)))
        goto err;

    /* 2 refs are passed for bio2 */
    if (!BIO_up_ref(bio2))
        goto err;
    tserver_args.net_rbio = bio2;
    tserver_args.net_wbio = bio2;

    if (!TEST_ptr(*qtserv = ossl_quic_tserver_new(&tserver_args, certfile,
                                                  keyfile))) {
        /* We hold 2 refs to bio2 at the moment */
        BIO_free(bio2);
        goto err;
    }
    /* Ownership of bio2 is now held by *qtserv */
    bio2 = NULL;

    if (fault != NULL) {
        *fault = OPENSSL_zalloc(sizeof(**fault));
        if (*fault == NULL)
            goto err;

        (*fault)->qtserv = *qtserv;
    }

    BIO_ADDR_free(peeraddr);

    return 1;
 err:
    BIO_ADDR_free(peeraddr);
    BIO_free(bio1);
    BIO_free(bio2);
    SSL_free(*cssl);
    ossl_quic_tserver_free(*qtserv);
    if (fault != NULL)
        OPENSSL_free(*fault);

    return 0;
}

#define MAXLOOPS    1000

int qtest_create_quic_connection(QUIC_TSERVER *qtserv, SSL *clientssl)
{
    int retc = -1, rets = 0, err, abortctr = 0, ret = 0;
    int clienterr = 0, servererr = 0;

    do {
        err = SSL_ERROR_WANT_WRITE;
        while (!clienterr && retc <= 0 && err == SSL_ERROR_WANT_WRITE) {
            retc = SSL_connect(clientssl);
            if (retc <= 0)
                err = SSL_get_error(clientssl, retc);
        }

        if (!clienterr && retc <= 0 && err != SSL_ERROR_WANT_READ) {
            TEST_info("SSL_connect() failed %d, %d", retc, err);
            TEST_openssl_errors();
            clienterr = 1;
        }

        /*
         * We're cheating. We don't take any notice of SSL_get_tick_timeout()
         * and tick everytime around the loop anyway. This is inefficient. We
         * can get away with it in test code because we control both ends of
         * the communications and don't expect network delays. This shouldn't
         * be done in a real application.
         */
        if (!clienterr)
            SSL_tick(clientssl);
        if (!servererr) {
            ossl_quic_tserver_tick(qtserv);
            servererr = ossl_quic_tserver_is_term_any(qtserv, NULL);
            if (!servererr && !rets)
                rets = ossl_quic_tserver_is_connected(qtserv);
        }

        if (clienterr && servererr)
            goto err;

        if (++abortctr == MAXLOOPS) {
            TEST_info("No progress made");
            goto err;
        }
    } while (retc <=0 || rets <= 0);

    ret = 1;
 err:
    return ret;
}

void ossl_quic_fault_free(OSSL_QUIC_FAULT *fault)
{
    if (fault == NULL)
        return;

    packet_plain_finish(fault);
    handshake_finish(fault);

    OPENSSL_free(fault);
}

static int packet_plain_mutate(const QUIC_PKT_HDR *hdrin,
                               const OSSL_QTX_IOVEC *iovecin, size_t numin,
                               QUIC_PKT_HDR **hdrout,
                               const OSSL_QTX_IOVEC **iovecout,
                               size_t *numout,
                               void *arg)
{
    OSSL_QUIC_FAULT *fault = arg;
    size_t i, bufsz = 0;
    unsigned char *cur;

    /* Coalesce our data into a single buffer */

    /* First calculate required buffer size */
    for (i = 0; i < numin; i++)
        bufsz += iovecin[i].buf_len;

    fault->pplainio.buf_len = bufsz;

    /* Add an allowance for possible growth */
    bufsz += GROWTH_ALLOWANCE;

    fault->pplainio.buf = cur = OPENSSL_malloc(bufsz);
    if (cur == NULL) {
        fault->pplainio.buf_len = 0;
        return 0;
    }

    fault->pplainbuf_alloc = bufsz;

    /* Copy in the data from the input buffers */
    for (i = 0; i < numin; i++) {
        memcpy(cur, iovecin[i].buf, iovecin[i].buf_len);
        cur += iovecin[i].buf_len;
    }

    fault->pplainhdr = *hdrin;

    /* Cast below is safe because we allocated the buffer */
    if (fault->pplaincb != NULL
            && !fault->pplaincb(fault, &fault->pplainhdr,
                                (unsigned char *)fault->pplainio.buf,
                                fault->pplainio.buf_len, fault->pplaincbarg))
        return 0;

    *hdrout = &fault->pplainhdr;
    *iovecout = &fault->pplainio;
    *numout = 1;

    return 1;
}

static void packet_plain_finish(void *arg)
{
    OSSL_QUIC_FAULT *fault = arg;

    /* Cast below is safe because we allocated the buffer */
    OPENSSL_free((unsigned char *)fault->pplainio.buf);
    fault->pplainio.buf_len = 0;
    fault->pplainbuf_alloc = 0;
    fault->pplainio.buf = NULL;
}

int ossl_quic_fault_set_packet_plain_listener(OSSL_QUIC_FAULT *fault,
                                              ossl_quic_fault_on_packet_plain_cb pplaincb,
                                              void *pplaincbarg)
{
    fault->pplaincb = pplaincb;
    fault->pplaincbarg = pplaincbarg;

    return ossl_quic_tserver_set_plain_packet_mutator(fault->qtserv,
                                                      packet_plain_mutate,
                                                      packet_plain_finish,
                                                      fault);
}

/* To be called from a packet_plain_listener callback */
int ossl_quic_fault_resize_plain_packet(OSSL_QUIC_FAULT *fault, size_t newlen)
{
    unsigned char *buf;
    size_t oldlen = fault->pplainio.buf_len;

    /*
     * Alloc'd size should always be non-zero, so if this fails we've been
     * incorrectly called
     */
    if (fault->pplainbuf_alloc == 0)
        return 0;

    if (newlen > fault->pplainbuf_alloc) {
        /* This exceeds our growth allowance. Fail */
        return 0;
    }

    /* Cast below is safe because we allocated the buffer */
    buf = (unsigned char *)fault->pplainio.buf;

    if (newlen > oldlen) {
        /* Extend packet with 0 bytes */
        memset(buf + oldlen, 0, newlen - oldlen);
    } /* else we're truncating or staying the same */

    fault->pplainio.buf_len = newlen;
    fault->pplainhdr.len = newlen;

    return 1;
}

static int handshake_mutate(const unsigned char *msgin, size_t msginlen,
                            unsigned char **msgout, size_t *msgoutlen,
                            void *arg)
{
    OSSL_QUIC_FAULT *fault = arg;
    unsigned char *buf;
    unsigned long payloadlen;
    unsigned int msgtype;
    PACKET pkt;

    buf = OPENSSL_malloc(msginlen + GROWTH_ALLOWANCE);
    if (buf == NULL)
        return 0;

    fault->handbuf = buf;
    fault->handbuflen = msginlen;
    fault->handbufalloc = msginlen + GROWTH_ALLOWANCE;
    memcpy(buf, msgin, msginlen);

    if (!PACKET_buf_init(&pkt, buf, msginlen)
            || !PACKET_get_1(&pkt, &msgtype)
            || !PACKET_get_net_3(&pkt, &payloadlen)
            || PACKET_remaining(&pkt) != payloadlen)
        return 0;

    /* Parse specific message types */
    switch (msgtype) {
    case SSL3_MT_ENCRYPTED_EXTENSIONS:
    {
        OSSL_QF_ENCRYPTED_EXTENSIONS ee;

        if (fault->encextcb == NULL)
            break;

        /*
         * The EncryptedExtensions message is very simple. It just has an
         * extensions block in it and nothing else.
         */
        ee.extensions = (unsigned char *)PACKET_data(&pkt);
        ee.extensionslen = payloadlen;
        if (!fault->encextcb(fault, &ee, payloadlen, fault->encextcbarg))
            return 0;
    }

    default:
        /* No specific handlers for these message types yet */
        break;
    }

    if (fault->handshakecb != NULL
            && !fault->handshakecb(fault, buf, fault->handbuflen,
                                   fault->handshakecbarg))
        return 0;

    *msgout = buf;
    *msgoutlen = fault->handbuflen;

    return 1;
}

static void handshake_finish(void *arg)
{
    OSSL_QUIC_FAULT *fault = arg;

    OPENSSL_free(fault->handbuf);
    fault->handbuf = NULL;
}

int ossl_quic_fault_set_handshake_listener(OSSL_QUIC_FAULT *fault,
                                           ossl_quic_fault_on_handshake_cb handshakecb,
                                           void *handshakecbarg)
{
    fault->handshakecb = handshakecb;
    fault->handshakecbarg = handshakecbarg;

    return ossl_quic_tserver_set_handshake_mutator(fault->qtserv,
                                                   handshake_mutate,
                                                   handshake_finish,
                                                   fault);
}

int ossl_quic_fault_set_hand_enc_ext_listener(OSSL_QUIC_FAULT *fault,
                                              ossl_quic_fault_on_enc_ext_cb encextcb,
                                              void *encextcbarg)
{
    fault->encextcb = encextcb;
    fault->encextcbarg = encextcbarg;

    return ossl_quic_tserver_set_handshake_mutator(fault->qtserv,
                                                   handshake_mutate,
                                                   handshake_finish,
                                                   fault);
}

/* To be called from a handshake_listener callback */
int ossl_quic_fault_resize_handshake(OSSL_QUIC_FAULT *fault, size_t newlen)
{
    unsigned char *buf;
    size_t oldlen = fault->handbuflen;

    /*
     * Alloc'd size should always be non-zero, so if this fails we've been
     * incorrectly called
     */
    if (fault->handbufalloc == 0)
        return 0;

    if (newlen > fault->handbufalloc) {
        /* This exceeds our growth allowance. Fail */
        return 0;
    }

    buf = (unsigned char *)fault->handbuf;

    if (newlen > oldlen) {
        /* Extend packet with 0 bytes */
        memset(buf + oldlen, 0, newlen - oldlen);
    } /* else we're truncating or staying the same */

    fault->handbuflen = newlen;
    return 1;
}

/* To be called from message specific listener callbacks */
int ossl_quic_fault_resize_message(OSSL_QUIC_FAULT *fault, size_t newlen)
{
    /* First resize the underlying message */
    if (!ossl_quic_fault_resize_handshake(fault, newlen + SSL3_HM_HEADER_LENGTH))
        return 0;

    /* Fixup the handshake message header */
    fault->handbuf[1] = (unsigned char)((newlen >> 16) & 0xff);
    fault->handbuf[2] = (unsigned char)((newlen >>  8) & 0xff);
    fault->handbuf[3] = (unsigned char)((newlen      ) & 0xff);

    return 1;
}

int ossl_quic_fault_delete_extension(OSSL_QUIC_FAULT *fault,
                                     unsigned int exttype, unsigned char *ext,
                                     size_t *extlen, size_t *msglen)
{
    PACKET pkt, sub, subext;
    unsigned int type;
    const unsigned char *start, *end;
    size_t newlen;

    if (!PACKET_buf_init(&pkt, ext, *extlen))
        return 0;

    /* Extension block starts with 2 bytes for extension block length */
    if (!PACKET_as_length_prefixed_2(&pkt, &sub))
        return 0;

    do {
        start = PACKET_data(&sub);
        if (!PACKET_get_net_2(&sub, &type)
                || !PACKET_as_length_prefixed_2(&sub, &subext))
            return 0;
    } while (type != exttype);

    /* Found it */
    end = PACKET_data(&sub);

    /*
     * If we're not the last extension we need to move the rest earlier. The
     * cast below is safe because we own the underlying buffer and we're no
     * longer making PACKET calls.
     */
    if (end < ext + *extlen)
        memmove((unsigned char *)start, end, end - start);

    /*
     * Calculate new extensions payload length =
     * Original length
     * - 2 extension block length bytes
     * - length of removed extension
     */
    newlen = *extlen - 2 - (end - start);

    /* Fixup the length bytes for the extension block */
    ext[0] = (unsigned char)((newlen >> 8) & 0xff);
    ext[1] = (unsigned char)((newlen     ) & 0xff);

    /*
     * Length of the whole extension block is the new payload length plus the
     * 2 bytes for the length
     */
    *extlen = newlen + 2;

    /* We can now resize the message */
    *msglen -= (end - start);
    if (!ossl_quic_fault_resize_message(fault, *msglen))
        return 0;

    return 1;
}
