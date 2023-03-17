/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <openssl/configuration.h>
#include <openssl/bio.h>
#include "quictestlib.h"
#include "ssltestlib.h"
#include "../testutil.h"
#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
# include "../threadstest.h"
#endif
#include "internal/quic_wire_pkt.h"
#include "internal/quic_record_tx.h"
#include "internal/quic_error.h"
#include "internal/packet.h"

#define GROWTH_ALLOWANCE 1024

struct qtest_fault {
    QUIC_TSERVER *qtserv;

    /* Plain packet mutations */
    /* Header for the plaintext packet */
    QUIC_PKT_HDR pplainhdr;
    /* iovec for the plaintext packet data buffer */
    OSSL_QTX_IOVEC pplainio;
    /* Allocted size of the plaintext packet data buffer */
    size_t pplainbuf_alloc;
    qtest_fault_on_packet_plain_cb pplaincb;
    void *pplaincbarg;

    /* Handshake message mutations */
    /* Handshake message buffer */
    unsigned char *handbuf;
    /* Allocated size of the handshake message buffer */
    size_t handbufalloc;
    /* Actual length of the handshake message */
    size_t handbuflen;
    qtest_fault_on_handshake_cb handshakecb;
    void *handshakecbarg;
    qtest_fault_on_enc_ext_cb encextcb;
    void *encextcbarg;

    /* Cipher packet mutations */
    qtest_fault_on_packet_cipher_cb pciphercb;
    void *pciphercbarg;

    /* Datagram mutations */
    qtest_fault_on_datagram_cb datagramcb;
    void *datagramcbarg;
    /* The currently processed message */
    BIO_MSG msg;
    /* Allocated size of msg data buffer */
    size_t msgalloc;
};

static void packet_plain_finish(void *arg);
static void handshake_finish(void *arg);

static BIO_METHOD *get_bio_method(void);

int qtest_create_quic_objects(OSSL_LIB_CTX *libctx, SSL_CTX *clientctx,
                              char *certfile, char *keyfile,
                              int block, QUIC_TSERVER **qtserv, SSL **cssl,
                              QTEST_FAULT **fault)
{
    /* ALPN value as recognised by QUIC_TSERVER */
    unsigned char alpn[] = { 8, 'o', 's', 's', 'l', 't', 'e', 's', 't' };
    QUIC_TSERVER_ARGS tserver_args = {0};
    BIO *cbio = NULL, *sbio = NULL, *fisbio = NULL;
    BIO_ADDR *peeraddr = NULL;
    struct in_addr ina = {0};

    *qtserv = NULL;
    if (fault != NULL)
        *fault = NULL;
    *cssl = SSL_new(clientctx);
    if (!TEST_ptr(*cssl))
        return 0;

    /* SSL_set_alpn_protos returns 0 for success! */
    if (!TEST_false(SSL_set_alpn_protos(*cssl, alpn, sizeof(alpn))))
        goto err;

    if (!TEST_ptr(peeraddr = BIO_ADDR_new()))
        goto err;

    if (block) {
#if !defined(OPENSSL_NO_POSIX_IO)
        int cfd, sfd;

        /*
         * For blocking mode we need to create actual sockets rather than doing
         * everything in memory
         */
        if (!TEST_true(create_test_sockets(&cfd, &sfd, SOCK_DGRAM, peeraddr)))
            goto err;
        cbio = BIO_new_dgram(cfd, 1);
        if (!TEST_ptr(cbio)) {
            close(cfd);
            close(sfd);
            goto err;
        }
        sbio = BIO_new_dgram(sfd, 1);
        if (!TEST_ptr(sbio)) {
            close(sfd);
            goto err;
        }
#else
        goto err;
#endif
    } else {
        if (!TEST_true(BIO_new_bio_dgram_pair(&cbio, 0, &sbio, 0)))
            goto err;

        if (!TEST_true(BIO_dgram_set_caps(cbio, BIO_DGRAM_CAP_HANDLES_DST_ADDR))
                || !TEST_true(BIO_dgram_set_caps(sbio, BIO_DGRAM_CAP_HANDLES_DST_ADDR)))
            goto err;

        /* Dummy server address */
        if (!TEST_true(BIO_ADDR_rawmake(peeraddr, AF_INET, &ina, sizeof(ina),
                                        htons(0))))
            goto err;
    }

    SSL_set_bio(*cssl, cbio, cbio);

    if (!TEST_true(SSL_set_blocking_mode(*cssl, block)))
        goto err;

    if (!TEST_true(SSL_set_initial_peer_addr(*cssl, peeraddr)))
        goto err;

    if (fault != NULL) {
        *fault = OPENSSL_zalloc(sizeof(**fault));
        if (*fault == NULL)
            goto err;
    }

    fisbio = BIO_new(get_bio_method());
    if (!TEST_ptr(fisbio))
        goto err;

    BIO_set_data(fisbio, fault == NULL ? NULL : *fault);

    if (!TEST_ptr(BIO_push(fisbio, sbio)))
        goto err;

    tserver_args.libctx = libctx;
    tserver_args.net_rbio = sbio;
    tserver_args.net_wbio = fisbio;

    if (!TEST_ptr(*qtserv = ossl_quic_tserver_new(&tserver_args, certfile,
                                                  keyfile)))
        goto err;

    /* Ownership of fisbio and sbio is now held by *qtserv */
    sbio = NULL;
    fisbio = NULL;

    if (fault != NULL)
        (*fault)->qtserv = *qtserv;

    BIO_ADDR_free(peeraddr);

    return 1;
 err:
    BIO_ADDR_free(peeraddr);
    BIO_free(cbio);
    BIO_free(fisbio);
    BIO_free(sbio);
    SSL_free(*cssl);
    *cssl = NULL;
    ossl_quic_tserver_free(*qtserv);
    if (fault != NULL)
        OPENSSL_free(*fault);

    return 0;
}

int qtest_supports_blocking(void)
{
#if !defined(OPENSSL_NO_POSIX_IO) && defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
    return 1;
#else
    return 0;
#endif
}

#define MAXLOOPS    1000

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
static int globserverret = 0;
static QUIC_TSERVER *globtserv;
static const thread_t thread_zero;

static void run_server_thread(void)
{
    /*
     * This will operate in a busy loop because the server does not block,
     * but should be acceptable because it is local and we expect this to be
     * fast
     */
    globserverret = qtest_create_quic_connection(globtserv, NULL);
}
#endif

int qtest_create_quic_connection(QUIC_TSERVER *qtserv, SSL *clientssl)
{
    int retc = -1, rets = 0, err, abortctr = 0, ret = 0;
    int clienterr = 0, servererr = 0;
#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
    /*
     * Pointless initialisation to avoid bogus compiler warnings about using
     * t uninitialised
     */
    thread_t t = thread_zero;
#endif

    if (!TEST_ptr(qtserv)) {
        goto err;
    } else if (clientssl == NULL) {
        retc = 1;
    } else if (SSL_get_blocking_mode(clientssl) > 0) {
#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
        /*
         * clientssl is blocking. We will need a thread to complete the
         * connection
         */
        globtserv = qtserv;
        if (!TEST_true(run_thread(&t, run_server_thread)))
            goto err;

        qtserv = NULL;
        rets = 1;
#else
        TEST_error("No thread support in this build");
        goto err;
#endif
    }

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
        if (!clienterr && retc <= 0)
            SSL_tick(clientssl);
        if (!servererr && rets <= 0) {
            ossl_quic_tserver_tick(qtserv);
            servererr = ossl_quic_tserver_is_term_any(qtserv);
            if (!servererr)
                rets = ossl_quic_tserver_is_handshake_confirmed(qtserv);
        }

        if (clienterr && servererr)
            goto err;

        if (clientssl != NULL && ++abortctr == MAXLOOPS) {
            TEST_info("No progress made");
            goto err;
        }
    } while ((retc <= 0 && !clienterr) || (rets <= 0 && !servererr));

    if (qtserv == NULL && rets > 0) {
#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
        if (!TEST_true(wait_for_thread(t)) || !TEST_true(globserverret))
            goto err;
#else
        TEST_error("Should not happen");
        goto err;
#endif
    }

    if (!clienterr && !servererr)
        ret = 1;
 err:
    return ret;
}

int qtest_shutdown(QUIC_TSERVER *qtserv, SSL *clientssl)
{
    /* Busy loop in non-blocking mode. It should be quick because its local */
    while (SSL_shutdown(clientssl) != 1)
        ossl_quic_tserver_tick(qtserv);

    return 1;
}

int qtest_check_server_transport_err(QUIC_TSERVER *qtserv, uint64_t code)
{
    QUIC_TERMINATE_CAUSE cause;

    ossl_quic_tserver_tick(qtserv);

    /*
     * Check that the server has closed with the specified code from the client
     */
    if (!TEST_true(ossl_quic_tserver_is_term_any(qtserv)))
        return 0;

    cause = ossl_quic_tserver_get_terminate_cause(qtserv);
    if  (!TEST_true(cause.remote)
            || !TEST_uint64_t_eq(cause.error_code, code))
        return 0;

    return 1;
}

int qtest_check_server_protocol_err(QUIC_TSERVER *qtserv)
{
    return qtest_check_server_transport_err(qtserv, QUIC_ERR_PROTOCOL_VIOLATION);
}

void qtest_fault_free(QTEST_FAULT *fault)
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
    QTEST_FAULT *fault = arg;
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
    QTEST_FAULT *fault = arg;

    /* Cast below is safe because we allocated the buffer */
    OPENSSL_free((unsigned char *)fault->pplainio.buf);
    fault->pplainio.buf_len = 0;
    fault->pplainbuf_alloc = 0;
    fault->pplainio.buf = NULL;
}

int qtest_fault_set_packet_plain_listener(QTEST_FAULT *fault,
                                          qtest_fault_on_packet_plain_cb pplaincb,
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
int qtest_fault_resize_plain_packet(QTEST_FAULT *fault, size_t newlen)
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

/*
 * Prepend frame data into a packet. To be called from a packet_plain_listener
 * callback
 */
int qtest_fault_prepend_frame(QTEST_FAULT *fault, unsigned char *frame,
                              size_t frame_len)
{
    unsigned char *buf;
    size_t old_len;

    /*
     * Alloc'd size should always be non-zero, so if this fails we've been
     * incorrectly called
     */
    if (fault->pplainbuf_alloc == 0)
        return 0;

    /* Cast below is safe because we allocated the buffer */
    buf = (unsigned char *)fault->pplainio.buf;
    old_len = fault->pplainio.buf_len;

    /* Extend the size of the packet by the size of the new frame */
    if (!TEST_true(qtest_fault_resize_plain_packet(fault,
                                                   old_len + frame_len)))
        return 0;

    memmove(buf + frame_len, buf, old_len);
    memcpy(buf, frame, frame_len);

    return 1;
}

static int handshake_mutate(const unsigned char *msgin, size_t msginlen,
                            unsigned char **msgout, size_t *msgoutlen,
                            void *arg)
{
    QTEST_FAULT *fault = arg;
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
        QTEST_ENCRYPTED_EXTENSIONS ee;

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
    QTEST_FAULT *fault = arg;

    OPENSSL_free(fault->handbuf);
    fault->handbuf = NULL;
}

int qtest_fault_set_handshake_listener(QTEST_FAULT *fault,
                                       qtest_fault_on_handshake_cb handshakecb,
                                       void *handshakecbarg)
{
    fault->handshakecb = handshakecb;
    fault->handshakecbarg = handshakecbarg;

    return ossl_quic_tserver_set_handshake_mutator(fault->qtserv,
                                                   handshake_mutate,
                                                   handshake_finish,
                                                   fault);
}

int qtest_fault_set_hand_enc_ext_listener(QTEST_FAULT *fault,
                                          qtest_fault_on_enc_ext_cb encextcb,
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
int qtest_fault_resize_handshake(QTEST_FAULT *fault, size_t newlen)
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
int qtest_fault_resize_message(QTEST_FAULT *fault, size_t newlen)
{
    /* First resize the underlying message */
    if (!qtest_fault_resize_handshake(fault, newlen + SSL3_HM_HEADER_LENGTH))
        return 0;

    /* Fixup the handshake message header */
    fault->handbuf[1] = (unsigned char)((newlen >> 16) & 0xff);
    fault->handbuf[2] = (unsigned char)((newlen >>  8) & 0xff);
    fault->handbuf[3] = (unsigned char)((newlen      ) & 0xff);

    return 1;
}

int qtest_fault_delete_extension(QTEST_FAULT *fault,
                                 unsigned int exttype, unsigned char *ext,
                                 size_t *extlen)
{
    PACKET pkt, sub, subext;
    unsigned int type;
    const unsigned char *start, *end;
    size_t newlen;
    size_t msglen = fault->handbuflen;

    if (!PACKET_buf_init(&pkt, ext, *extlen))
        return 0;

    /* Extension block starts with 2 bytes for extension block length */
    if (!PACKET_as_length_prefixed_2(&pkt, &sub))
        return 0;

    do {
        start = PACKET_data(&sub);
        if (!PACKET_get_net_2(&sub, &type)
                || !PACKET_get_length_prefixed_2(&sub, &subext))
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
    if ((size_t)(end - start) + SSL3_HM_HEADER_LENGTH > msglen)
        return 0; /* Should not happen */
    msglen -= (end - start) + SSL3_HM_HEADER_LENGTH;
    if (!qtest_fault_resize_message(fault, msglen))
        return 0;

    return 1;
}

#define BIO_TYPE_CIPHER_PACKET_FILTER  (0x80 | BIO_TYPE_FILTER)

static BIO_METHOD *pcipherbiometh = NULL;

# define BIO_MSG_N(array, stride, n) (*(BIO_MSG *)((char *)(array) + (n)*(stride)))

static int pcipher_sendmmsg(BIO *b, BIO_MSG *msg, size_t stride,
                            size_t num_msg, uint64_t flags,
                            size_t *num_processed)
{
    QTEST_FAULT *fault;
    BIO *next = BIO_next(b);
    ossl_ssize_t ret = 0;
    size_t i = 0, tmpnump;
    QUIC_PKT_HDR hdr;
    PACKET pkt;
    unsigned char *tmpdata;

    if (next == NULL)
        return 0;

    fault = BIO_get_data(b);
    if (fault == NULL
            || (fault->pciphercb == NULL && fault->datagramcb == NULL))
        return BIO_sendmmsg(next, msg, stride, num_msg, flags, num_processed);

    if (num_msg == 0) {
        *num_processed = 0;
        return 1;
    }

    for (i = 0; i < num_msg; ++i) {
        fault->msg = BIO_MSG_N(msg, stride, i);

        /* Take a copy of the data so that callbacks can modify it */
        tmpdata = OPENSSL_malloc(fault->msg.data_len + GROWTH_ALLOWANCE);
        if (tmpdata == NULL)
            return 0;
        memcpy(tmpdata, fault->msg.data, fault->msg.data_len);
        fault->msg.data = tmpdata;
        fault->msgalloc = fault->msg.data_len + GROWTH_ALLOWANCE;

        if (fault->pciphercb != NULL) {
            if (!PACKET_buf_init(&pkt, fault->msg.data, fault->msg.data_len))
                return 0;

            do {
                if (!ossl_quic_wire_decode_pkt_hdr(&pkt,
                        0 /* TODO(QUIC): Not sure how this should be set*/, 1,
                        &hdr, NULL))
                    goto out;

                /*
                 * hdr.data is const - but its our buffer so casting away the
                 * const is safe
                 */
                if (!fault->pciphercb(fault, &hdr, (unsigned char *)hdr.data,
                                    hdr.len, fault->pciphercbarg))
                    goto out;

                /*
                 * TODO(QUIC): At the moment modifications to hdr by the callback
                 * are ignored. We might need to rewrite the QUIC header to
                 * enable tests to change this. We also don't yet have a
                 * mechanism for the callback to change the encrypted data
                 * length. It's not clear if that's needed or not.
                 */
            } while (PACKET_remaining(&pkt) > 0);
        }

        if (fault->datagramcb != NULL
                && !fault->datagramcb(fault, &fault->msg, stride,
                                      fault->datagramcbarg))
            goto out;

        if (!BIO_sendmmsg(next, &fault->msg, stride, 1, flags, &tmpnump)) {
            *num_processed = i;
            goto out;
        }

        OPENSSL_free(fault->msg.data);
        fault->msg.data = NULL;
        fault->msgalloc = 0;
    }

    *num_processed = i;
out:
    ret = i > 0;
    OPENSSL_free(fault->msg.data);
    fault->msg.data = NULL;
    return ret;
}

static long pcipher_ctrl(BIO *b, int cmd, long larg, void *parg)
{
    BIO *next = BIO_next(b);

    if (next == NULL)
        return -1;

    return BIO_ctrl(next, cmd, larg, parg);
}

static BIO_METHOD *get_bio_method(void)
{
    BIO_METHOD *tmp;

    if (pcipherbiometh != NULL)
        return pcipherbiometh;

    tmp = BIO_meth_new(BIO_TYPE_CIPHER_PACKET_FILTER, "Cipher Packet Filter");

    if (!TEST_ptr(tmp))
        return NULL;

    if (!TEST_true(BIO_meth_set_sendmmsg(tmp, pcipher_sendmmsg))
            || !TEST_true(BIO_meth_set_ctrl(tmp, pcipher_ctrl)))
        goto err;

    pcipherbiometh = tmp;
    tmp = NULL;
 err:
    BIO_meth_free(tmp);
    return pcipherbiometh;
}

int qtest_fault_set_packet_cipher_listener(QTEST_FAULT *fault,
                                           qtest_fault_on_packet_cipher_cb pciphercb,
                                           void *pciphercbarg)
{
    fault->pciphercb = pciphercb;
    fault->pciphercbarg = pciphercbarg;

    return 1;
}

int qtest_fault_set_datagram_listener(QTEST_FAULT *fault,
                                      qtest_fault_on_datagram_cb datagramcb,
                                      void *datagramcbarg)
{
    fault->datagramcb = datagramcb;
    fault->datagramcbarg = datagramcbarg;

    return 1;
}

/* To be called from a datagram_listener callback */
int qtest_fault_resize_datagram(QTEST_FAULT *fault, size_t newlen)
{
    if (newlen > fault->msgalloc)
            return 0;

    if (newlen > fault->msg.data_len)
        memset((unsigned char *)fault->msg.data + fault->msg.data_len, 0,
                newlen - fault->msg.data_len);

    fault->msg.data_len = newlen;

    return 1;
}
