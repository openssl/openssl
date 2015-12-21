/* ssl/record/rec_layer_s3.c */
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
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#define USE_SOCKETS
#include "../ssl_locl.h"
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include "record_locl.h"

#ifndef  EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
# define EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0
#endif

#if     defined(OPENSSL_SMALL_FOOTPRINT) || \
        !(      defined(AES_ASM) &&     ( \
                defined(__x86_64)       || defined(__x86_64__)  || \
                defined(_M_AMD64)       || defined(_M_X64)      || \
                defined(__INTEL__)      ) \
        )
# undef EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
# define EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0
#endif

void RECORD_LAYER_init(RECORD_LAYER *rl, SSL *s)
{
    rl->s = s;
    SSL3_RECORD_clear(&rl->rrec);
    SSL3_RECORD_clear(&rl->wrec);
}

void RECORD_LAYER_clear(RECORD_LAYER *rl)
{
    rl->rstate = SSL_ST_READ_HEADER;

    /* Do I need to clear read_ahead? As far as I can tell read_ahead did not
     * previously get reset by SSL_clear...so I'll keep it that way..but is
     * that right?
     */

    rl->packet = NULL;
    rl->packet_length = 0;
    rl->wnum = 0;
    memset(rl->alert_fragment, 0, sizeof(rl->alert_fragment));
    rl->alert_fragment_len = 0;
    memset(rl->handshake_fragment, 0, sizeof(rl->handshake_fragment));
    rl->handshake_fragment_len = 0;
    rl->wpend_tot = 0;
    rl->wpend_type = 0;
    rl->wpend_ret = 0;
    rl->wpend_buf = NULL;

    SSL3_BUFFER_clear(&rl->rbuf);
    SSL3_BUFFER_clear(&rl->wbuf);
    SSL3_RECORD_clear(&rl->rrec);
    SSL3_RECORD_clear(&rl->wrec);

    RECORD_LAYER_reset_read_sequence(rl);
    RECORD_LAYER_reset_write_sequence(rl);
    
    if (rl->d)
        DTLS_RECORD_LAYER_clear(rl);
}

void RECORD_LAYER_release(RECORD_LAYER *rl)
{
    if (SSL3_BUFFER_is_initialised(&rl->rbuf))
        ssl3_release_read_buffer(rl->s);
    if (SSL3_BUFFER_is_initialised(&rl->wbuf))
        ssl3_release_write_buffer(rl->s);
    SSL3_RECORD_release(&rl->rrec);
}

int RECORD_LAYER_read_pending(RECORD_LAYER *rl)
{
    return SSL3_BUFFER_get_left(&rl->rbuf) != 0;
}

int RECORD_LAYER_write_pending(RECORD_LAYER *rl)
{
    return SSL3_BUFFER_get_left(&rl->wbuf) != 0;
}

int RECORD_LAYER_set_data(RECORD_LAYER *rl, const unsigned char *buf, int len)
{
    rl->packet_length = len;
    if (len != 0) {
        rl->rstate = SSL_ST_READ_HEADER;
        if (!SSL3_BUFFER_is_initialised(&rl->rbuf))
            if (!ssl3_setup_read_buffer(rl->s))
                return 0;
    }

    rl->packet = SSL3_BUFFER_get_buf(&rl->rbuf);
    SSL3_BUFFER_set_data(&rl->rbuf, buf, len);

    return 1;
}

void RECORD_LAYER_dup(RECORD_LAYER *dst, RECORD_LAYER *src)
{
    /*
     * Currently only called from SSL_dup...which only seems to expect the
     * rstate to be duplicated and nothing else from the RECORD_LAYER???
     */
    dst->rstate = src->rstate;
}

void RECORD_LAYER_reset_read_sequence(RECORD_LAYER *rl)
{
    memset(rl->read_sequence, 0, sizeof(rl->read_sequence));
}

void RECORD_LAYER_reset_write_sequence(RECORD_LAYER *rl)
{
    memset(rl->write_sequence, 0, sizeof(rl->write_sequence));
}

int RECORD_LAYER_setup_comp_buffer(RECORD_LAYER *rl)
{
    return SSL3_RECORD_setup(&(rl)->rrec);
}

int ssl3_pending(const SSL *s)
{
    if (s->rlayer.rstate == SSL_ST_READ_BODY)
        return 0;

    return (SSL3_RECORD_get_type(&s->rlayer.rrec) == SSL3_RT_APPLICATION_DATA)
           ? SSL3_RECORD_get_length(&s->rlayer.rrec) : 0;
}

const char *SSL_rstate_string_long(const SSL *s)
{
    const char *str;

    switch (s->rlayer.rstate) {
    case SSL_ST_READ_HEADER:
        str = "read header";
        break;
    case SSL_ST_READ_BODY:
        str = "read body";
        break;
    case SSL_ST_READ_DONE:
        str = "read done";
        break;
    default:
        str = "unknown";
        break;
    }
    return (str);
}

const char *SSL_rstate_string(const SSL *s)
{
    const char *str;

    switch (s->rlayer.rstate) {
    case SSL_ST_READ_HEADER:
        str = "RH";
        break;
    case SSL_ST_READ_BODY:
        str = "RB";
        break;
    case SSL_ST_READ_DONE:
        str = "RD";
        break;
    default:
        str = "unknown";
        break;
    }
    return (str);
}

int ssl3_read_n(SSL *s, int n, int max, int extend)
{
    /*
     * If extend == 0, obtain new n-byte packet; if extend == 1, increase
     * packet by another n bytes. The packet will be in the sub-array of
     * s->s3->rbuf.buf specified by s->packet and s->packet_length. (If
     * s->rlayer.read_ahead is set, 'max' bytes may be stored in rbuf [plus
     * s->packet_length bytes if extend == 1].)
     */
    int i, len, left;
    size_t align = 0;
    unsigned char *pkt;
    SSL3_BUFFER *rb;

    if (n <= 0)
        return n;

    rb = &s->rlayer.rbuf;
    if (rb->buf == NULL)
        if (!ssl3_setup_read_buffer(s))
            return -1;

    left = rb->left;
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
    align = (size_t)rb->buf + SSL3_RT_HEADER_LENGTH;
    align = (0-align) & (SSL3_ALIGN_PAYLOAD - 1);
#endif

    if (!extend) {
        /* start with empty packet ... */
        if (left == 0)
            rb->offset = align;
        else if (align != 0 && left >= SSL3_RT_HEADER_LENGTH) {
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
        s->rlayer.packet = rb->buf + rb->offset;
        s->rlayer.packet_length = 0;
        /* ... now we can act as if 'extend' was set */
    }

    /*
     * For DTLS/UDP reads should not span multiple packets because the read
     * operation returns the whole packet at once (as long as it fits into
     * the buffer).
     */
    if (SSL_IS_DTLS(s)) {
        if (left == 0 && extend)
            return 0;
        if (left > 0 && n > left)
            n = left;
    }

    /* if there is enough in the buffer from a previous read, take some */
    if (left >= n) {
        s->rlayer.packet_length += n;
        rb->left = left - n;
        rb->offset += n;
        return (n);
    }

    /* else we need to read more data */

    len = s->rlayer.packet_length;
    pkt = rb->buf + align;
    /*
     * Move any available bytes to front of buffer: 'len' bytes already
     * pointed to by 'packet', 'left' extra ones at the end
     */
    if (s->rlayer.packet != pkt) {     /* len > 0 */
        memmove(pkt, s->rlayer.packet, len + left);
        s->rlayer.packet = pkt;
        rb->offset = len + align;
    }

    if (n > (int)(rb->len - rb->offset)) { /* does not happen */
        SSLerr(SSL_F_SSL3_READ_N, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    /* We always act like read_ahead is set for DTLS */
    if (!s->rlayer.read_ahead && !SSL_IS_DTLS(s))
        /* ignore max parameter */
        max = n;
    else {
        if (max < n)
            max = n;
        if (max > (int)(rb->len - rb->offset))
            max = rb->len - rb->offset;
    }

    while (left < n) {
        /*
         * Now we have len+left bytes at the front of s->s3->rbuf.buf and
         * need to read in more until we have len+n (up to len+max if
         * possible)
         */

        clear_sys_error();
        if (s->rbio != NULL) {
            s->rwstate = SSL_READING;
            i = BIO_read(s->rbio, pkt + len + left, max - left);
        } else {
            SSLerr(SSL_F_SSL3_READ_N, SSL_R_READ_BIO_NOT_SET);
            i = -1;
        }

        if (i <= 0) {
            rb->left = left;
            if (s->mode & SSL_MODE_RELEASE_BUFFERS && !SSL_IS_DTLS(s))
                if (len + left == 0)
                    ssl3_release_read_buffer(s);
            return (i);
        }
        left += i;
        /*
         * reads should *never* span multiple packets for DTLS because the
         * underlying transport protocol is message oriented as opposed to
         * byte oriented as in the TLS case.
         */
        if (SSL_IS_DTLS(s)) {
            if (n > left)
                n = left;       /* makes the while condition false */
        }
    }

    /* done reading, now the book-keeping */
    rb->offset += n;
    rb->left = left - n;
    s->rlayer.packet_length += n;
    s->rwstate = SSL_NOTHING;
    return (n);
}


/*
 * Call this to write data in records of type 'type' It will return <= 0 if
 * not all data has been sent or non-blocking IO.
 */
int ssl3_write_bytes(SSL *s, int type, const void *buf_, int len)
{
    const unsigned char *buf = buf_;
    int tot;
    unsigned int n, nw;
#if !defined(OPENSSL_NO_MULTIBLOCK) && EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
    unsigned int max_send_fragment;
    unsigned int u_len = (unsigned int)len;
#endif
    SSL3_BUFFER *wb = &s->rlayer.wbuf;
    int i;

    if (len < 0) {
        SSLerr(SSL_F_SSL3_WRITE_BYTES, SSL_R_SSL_NEGATIVE_LENGTH);
        return -1;
    }

    s->rwstate = SSL_NOTHING;
    tot = s->rlayer.wnum;
    /*
     * ensure that if we end up with a smaller value of data to write out
     * than the the original len from a write which didn't complete for
     * non-blocking I/O and also somehow ended up avoiding the check for
     * this in ssl3_write_pending/SSL_R_BAD_WRITE_RETRY as it must never be
     * possible to end up with (len-tot) as a large number that will then
     * promptly send beyond the end of the users buffer ... so we trap and
     * report the error in a way the user will notice
     */
    if ((unsigned int)len < s->rlayer.wnum) {
        SSLerr(SSL_F_SSL3_WRITE_BYTES, SSL_R_BAD_LENGTH);
        return -1;
    }


    s->rlayer.wnum = 0;

    if (SSL_in_init(s) && !ossl_statem_get_in_handshake(s)) {
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_SSL3_WRITE_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
            return -1;
        }
    }

    /*
     * first check if there is a SSL3_BUFFER still being written out.  This
     * will happen with non blocking IO
     */
    if (wb->left != 0) {
        i = ssl3_write_pending(s, type, &buf[tot], s->rlayer.wpend_tot);
        if (i <= 0) {
            /* XXX should we ssl3_release_write_buffer if i<0? */
            s->rlayer.wnum = tot;
            return i;
        }
        tot += i;               /* this might be last fragment */
    }
#if !defined(OPENSSL_NO_MULTIBLOCK) && EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
    /*
     * Depending on platform multi-block can deliver several *times*
     * better performance. Downside is that it has to allocate
     * jumbo buffer to accomodate up to 8 records, but the
     * compromise is considered worthy.
     */
    if (type == SSL3_RT_APPLICATION_DATA &&
        u_len >= 4 * (max_send_fragment = s->max_send_fragment) &&
        s->compress == NULL && s->msg_callback == NULL &&
        !SSL_USE_ETM(s) && SSL_USE_EXPLICIT_IV(s) &&
        EVP_CIPHER_flags(s->enc_write_ctx->cipher) &
        EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK) {
        unsigned char aad[13];
        EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM mb_param;
        int packlen;

        /* minimize address aliasing conflicts */
        if ((max_send_fragment & 0xfff) == 0)
            max_send_fragment -= 512;

        if (tot == 0 || wb->buf == NULL) { /* allocate jumbo buffer */
            ssl3_release_write_buffer(s);

            packlen = EVP_CIPHER_CTX_ctrl(s->enc_write_ctx,
                                          EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE,
                                          max_send_fragment, NULL);

            if (u_len >= 8 * max_send_fragment)
                packlen *= 8;
            else
                packlen *= 4;

            wb->buf = OPENSSL_malloc(packlen);
            if (wb->buf == NULL) {
                SSLerr(SSL_F_SSL3_WRITE_BYTES, ERR_R_MALLOC_FAILURE);
                return -1;
            }
            wb->len = packlen;
        } else if (tot == len) { /* done? */
            OPENSSL_free(wb->buf); /* free jumbo buffer */
            wb->buf = NULL;
            return tot;
        }

        n = (len - tot);
        for (;;) {
            if (n < 4 * max_send_fragment) {
                OPENSSL_free(wb->buf); /* free jumbo buffer */
                wb->buf = NULL;
                break;
            }

            if (s->s3->alert_dispatch) {
                i = s->method->ssl_dispatch_alert(s);
                if (i <= 0) {
                    s->rlayer.wnum = tot;
                    return i;
                }
            }

            if (n >= 8 * max_send_fragment)
                nw = max_send_fragment * (mb_param.interleave = 8);
            else
                nw = max_send_fragment * (mb_param.interleave = 4);

            memcpy(aad, s->rlayer.write_sequence, 8);
            aad[8] = type;
            aad[9] = (unsigned char)(s->version >> 8);
            aad[10] = (unsigned char)(s->version);
            aad[11] = 0;
            aad[12] = 0;
            mb_param.out = NULL;
            mb_param.inp = aad;
            mb_param.len = nw;

            packlen = EVP_CIPHER_CTX_ctrl(s->enc_write_ctx,
                                          EVP_CTRL_TLS1_1_MULTIBLOCK_AAD,
                                          sizeof(mb_param), &mb_param);

            if (packlen <= 0 || packlen > (int)wb->len) { /* never happens */
                OPENSSL_free(wb->buf); /* free jumbo buffer */
                wb->buf = NULL;
                break;
            }

            mb_param.out = wb->buf;
            mb_param.inp = &buf[tot];
            mb_param.len = nw;

            if (EVP_CIPHER_CTX_ctrl(s->enc_write_ctx,
                                    EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT,
                                    sizeof(mb_param), &mb_param) <= 0)
                return -1;

            s->rlayer.write_sequence[7] += mb_param.interleave;
            if (s->rlayer.write_sequence[7] < mb_param.interleave) {
                int j = 6;
                while (j >= 0 && (++s->rlayer.write_sequence[j--]) == 0) ;
            }

            wb->offset = 0;
            wb->left = packlen;

            s->rlayer.wpend_tot = nw;
            s->rlayer.wpend_buf = &buf[tot];
            s->rlayer.wpend_type = type;
            s->rlayer.wpend_ret = nw;

            i = ssl3_write_pending(s, type, &buf[tot], nw);
            if (i <= 0) {
                if (i < 0 && (!s->wbio || !BIO_should_retry(s->wbio))) {
                    OPENSSL_free(wb->buf);
                    wb->buf = NULL;
                }
                s->rlayer.wnum = tot;
                return i;
            }
            if (i == (int)n) {
                OPENSSL_free(wb->buf); /* free jumbo buffer */
                wb->buf = NULL;
                return tot + i;
            }
            n -= i;
            tot += i;
        }
    } else
#endif
    if (tot == len) {           /* done? */
        if (s->mode & SSL_MODE_RELEASE_BUFFERS && !SSL_IS_DTLS(s))
            ssl3_release_write_buffer(s);

        return tot;
    }

    n = (len - tot);
    for (;;) {
        if (n > s->max_send_fragment)
            nw = s->max_send_fragment;
        else
            nw = n;

        i = do_ssl3_write(s, type, &(buf[tot]), nw, 0);
        if (i <= 0) {
            /* XXX should we ssl3_release_write_buffer if i<0? */
            s->rlayer.wnum = tot;
            return i;
        }

        if ((i == (int)n) ||
            (type == SSL3_RT_APPLICATION_DATA &&
             (s->mode & SSL_MODE_ENABLE_PARTIAL_WRITE))) {
            /*
             * next chunk of data should get another prepended empty fragment
             * in ciphersuites with known-IV weakness:
             */
            s->s3->empty_fragment_done = 0;

            if ((i == (int)n) && s->mode & SSL_MODE_RELEASE_BUFFERS &&
                !SSL_IS_DTLS(s))
                ssl3_release_write_buffer(s);

            return tot + i;
        }

        n -= i;
        tot += i;
    }
}

int do_ssl3_write(SSL *s, int type, const unsigned char *buf,
                  unsigned int len, int create_empty_fragment)
{
    unsigned char *p, *plen;
    int i, mac_size, clear = 0;
    int prefix_len = 0;
    int eivlen;
    size_t align = 0;
    SSL3_RECORD *wr;
    SSL3_BUFFER *wb = &s->rlayer.wbuf;
    SSL_SESSION *sess;

    /*
     * first check if there is a SSL3_BUFFER still being written out.  This
     * will happen with non blocking IO
     */
    if (SSL3_BUFFER_get_left(wb) != 0)
        return (ssl3_write_pending(s, type, buf, len));

    /* If we have an alert to send, lets send it */
    if (s->s3->alert_dispatch) {
        i = s->method->ssl_dispatch_alert(s);
        if (i <= 0)
            return (i);
        /* if it went, fall through and send more stuff */
    }

    if (!SSL3_BUFFER_is_initialised(wb))
        if (!ssl3_setup_write_buffer(s))
            return -1;

    if (len == 0 && !create_empty_fragment)
        return 0;

    wr = &s->rlayer.wrec;
    sess = s->session;

    if ((sess == NULL) ||
        (s->enc_write_ctx == NULL) ||
        (EVP_MD_CTX_md(s->write_hash) == NULL)) {
        clear = s->enc_write_ctx ? 0 : 1; /* must be AEAD cipher */
        mac_size = 0;
    } else {
        mac_size = EVP_MD_CTX_size(s->write_hash);
        if (mac_size < 0)
            goto err;
    }

    /*
     * 'create_empty_fragment' is true only when this function calls itself
     */
    if (!clear && !create_empty_fragment && !s->s3->empty_fragment_done) {
        /*
         * countermeasure against known-IV weakness in CBC ciphersuites (see
         * http://www.openssl.org/~bodo/tls-cbc.txt)
         */

        if (s->s3->need_empty_fragments && type == SSL3_RT_APPLICATION_DATA) {
            /*
             * recursive function call with 'create_empty_fragment' set; this
             * prepares and buffers the data for an empty fragment (these
             * 'prefix_len' bytes are sent out later together with the actual
             * payload)
             */
            prefix_len = do_ssl3_write(s, type, buf, 0, 1);
            if (prefix_len <= 0)
                goto err;

            if (prefix_len >
                (SSL3_RT_HEADER_LENGTH + SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD))
            {
                /* insufficient space */
                SSLerr(SSL_F_DO_SSL3_WRITE, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        s->s3->empty_fragment_done = 1;
    }

    if (create_empty_fragment) {
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
        /*
         * extra fragment would be couple of cipher blocks, which would be
         * multiple of SSL3_ALIGN_PAYLOAD, so if we want to align the real
         * payload, then we can just pretent we simply have two headers.
         */
        align = (size_t)SSL3_BUFFER_get_buf(wb) + 2 * SSL3_RT_HEADER_LENGTH;
        align = (0-align) & (SSL3_ALIGN_PAYLOAD - 1);
#endif
        p = SSL3_BUFFER_get_buf(wb) + align;
        SSL3_BUFFER_set_offset(wb, align);
    } else if (prefix_len) {
        p = SSL3_BUFFER_get_buf(wb) + SSL3_BUFFER_get_offset(wb) + prefix_len;
    } else {
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
        align = (size_t)SSL3_BUFFER_get_buf(wb) + SSL3_RT_HEADER_LENGTH;
        align = (0-align) & (SSL3_ALIGN_PAYLOAD - 1);
#endif
        p = SSL3_BUFFER_get_buf(wb) + align;
        SSL3_BUFFER_set_offset(wb, align);
    }

    /* write the header */

    *(p++) = type & 0xff;
    SSL3_RECORD_set_type(wr, type);

    *(p++) = (s->version >> 8);
    /*
     * Some servers hang if iniatial client hello is larger than 256 bytes
     * and record version number > TLS 1.0
     */
    if (SSL_get_state(s) == TLS_ST_CW_CLNT_HELLO
        && !s->renegotiate && TLS1_get_version(s) > TLS1_VERSION)
        *(p++) = 0x1;
    else
        *(p++) = s->version & 0xff;

    /* field where we are to write out packet length */
    plen = p;
    p += 2;
    /* Explicit IV length, block ciphers appropriate version flag */
    if (s->enc_write_ctx && SSL_USE_EXPLICIT_IV(s)) {
        int mode = EVP_CIPHER_CTX_mode(s->enc_write_ctx);
        if (mode == EVP_CIPH_CBC_MODE) {
            eivlen = EVP_CIPHER_CTX_iv_length(s->enc_write_ctx);
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
    SSL3_RECORD_set_data(wr, p + eivlen);
    SSL3_RECORD_set_length(wr, (int)len);
    SSL3_RECORD_set_input(wr, (unsigned char *)buf);


    /*
     * we now 'read' from wr->input, wr->length bytes into wr->data
     */

    /* first we compress */
    if (s->compress != NULL) {
        if (!ssl3_do_compress(s)) {
            SSLerr(SSL_F_DO_SSL3_WRITE, SSL_R_COMPRESSION_FAILURE);
            goto err;
        }
    } else {
        memcpy(wr->data, wr->input, wr->length);
        SSL3_RECORD_reset_input(wr);
    }

    /*
     * we should still have the output to wr->data and the input from
     * wr->input.  Length should be wr->length. wr->data still points in the
     * wb->buf
     */

    if (!SSL_USE_ETM(s) && mac_size != 0) {
        if (s->method->ssl3_enc->mac(s, &(p[wr->length + eivlen]), 1) < 0)
            goto err;
        SSL3_RECORD_add_length(wr, mac_size);
    }

    SSL3_RECORD_set_data(wr, p);
    SSL3_RECORD_reset_input(wr);

    if (eivlen) {
        /*
         * if (RAND_pseudo_bytes(p, eivlen) <= 0) goto err;
         */
        SSL3_RECORD_add_length(wr, eivlen);
    }

    if (s->method->ssl3_enc->enc(s, 1) < 1)
        goto err;

    if (SSL_USE_ETM(s) && mac_size != 0) {
        if (s->method->ssl3_enc->mac(s, p + wr->length, 1) < 0)
            goto err;
        SSL3_RECORD_add_length(wr, mac_size);
    }

    /* record length after mac and block padding */
    s2n(SSL3_RECORD_get_length(wr), plen);

    if (s->msg_callback)
        s->msg_callback(1, 0, SSL3_RT_HEADER, plen - 5, 5, s,
                        s->msg_callback_arg);

    /*
     * we should now have wr->data pointing to the encrypted data, which is
     * wr->length long
     */
    SSL3_RECORD_set_type(wr, type);  /* not needed but helps for debugging */
    SSL3_RECORD_add_length(wr, SSL3_RT_HEADER_LENGTH);

    if (create_empty_fragment) {
        /*
         * we are in a recursive call; just return the length, don't write
         * out anything here
         */
        return SSL3_RECORD_get_length(wr);
    }

    /* now let's set up wb */
    SSL3_BUFFER_set_left(wb, prefix_len + SSL3_RECORD_get_length(wr));

    /*
     * memorize arguments so that ssl3_write_pending can detect bad write
     * retries later
     */
    s->rlayer.wpend_tot = len;
    s->rlayer.wpend_buf = buf;
    s->rlayer.wpend_type = type;
    s->rlayer.wpend_ret = len;

    /* we now just need to write the buffer */
    return ssl3_write_pending(s, type, buf, len);
 err:
    return -1;
}

/* if s->s3->wbuf.left != 0, we need to call this */
int ssl3_write_pending(SSL *s, int type, const unsigned char *buf,
                       unsigned int len)
{
    int i;
    SSL3_BUFFER *wb = &s->rlayer.wbuf;

/* XXXX */
    if ((s->rlayer.wpend_tot > (int)len)
        || ((s->rlayer.wpend_buf != buf) &&
            !(s->mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER))
        || (s->rlayer.wpend_type != type)) {
        SSLerr(SSL_F_SSL3_WRITE_PENDING, SSL_R_BAD_WRITE_RETRY);
        return (-1);
    }

    for (;;) {
        clear_sys_error();
        if (s->wbio != NULL) {
            s->rwstate = SSL_WRITING;
            i = BIO_write(s->wbio,
                (char *)&(SSL3_BUFFER_get_buf(wb)[SSL3_BUFFER_get_offset(wb)]),
                (unsigned int)SSL3_BUFFER_get_left(wb));
        } else {
            SSLerr(SSL_F_SSL3_WRITE_PENDING, SSL_R_BIO_NOT_SET);
            i = -1;
        }
        if (i == SSL3_BUFFER_get_left(wb)) {
            SSL3_BUFFER_set_left(wb, 0);
            SSL3_BUFFER_add_offset(wb, i);
            s->rwstate = SSL_NOTHING;
            return (s->rlayer.wpend_ret);
        } else if (i <= 0) {
            if (SSL_IS_DTLS(s)) {
                /*
                 * For DTLS, just drop it. That's kind of the whole point in
                 * using a datagram service
                 */
                SSL3_BUFFER_set_left(wb, 0);
            }
            return (i);
        }
        SSL3_BUFFER_add_offset(wb, i);
        SSL3_BUFFER_add_left(wb, -i);
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
int ssl3_read_bytes(SSL *s, int type, int *recvd_type, unsigned char *buf,
                    int len, int peek)
{
    int al, i, j, ret;
    unsigned int n;
    SSL3_RECORD *rr;
    void (*cb) (const SSL *ssl, int type2, int val) = NULL;

    if (!SSL3_BUFFER_is_initialised(&s->rlayer.rbuf)) {
        /* Not initialized yet */
        if (!ssl3_setup_read_buffer(s))
            return (-1);
    }

    if ((type && (type != SSL3_RT_APPLICATION_DATA)
         && (type != SSL3_RT_HANDSHAKE)) || (peek
                                             && (type !=
                                                 SSL3_RT_APPLICATION_DATA))) {
        SSLerr(SSL_F_SSL3_READ_BYTES, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    if ((type == SSL3_RT_HANDSHAKE) && (s->rlayer.handshake_fragment_len > 0))
        /* (partially) satisfy request from storage */
    {
        unsigned char *src = s->rlayer.handshake_fragment;
        unsigned char *dst = buf;
        unsigned int k;

        /* peek == 0 */
        n = 0;
        while ((len > 0) && (s->rlayer.handshake_fragment_len > 0)) {
            *dst++ = *src++;
            len--;
            s->rlayer.handshake_fragment_len--;
            n++;
        }
        /* move any remaining fragment bytes: */
        for (k = 0; k < s->rlayer.handshake_fragment_len; k++)
            s->rlayer.handshake_fragment[k] = *src++;

        if (recvd_type != NULL)
            *recvd_type = SSL3_RT_HANDSHAKE;

        return n;
    }

    /*
     * Now s->rlayer.handshake_fragment_len == 0 if type == SSL3_RT_HANDSHAKE.
     */

    if (!ossl_statem_get_in_handshake(s) && SSL_in_init(s)) {
        /* type == SSL3_RT_APPLICATION_DATA */
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
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
    rr = &s->rlayer.rrec;

    /* get new packet if necessary */
    if ((SSL3_RECORD_get_length(rr) == 0)
            || (s->rlayer.rstate == SSL_ST_READ_BODY)) {
        ret = ssl3_get_record(s);
        if (ret <= 0)
            return (ret);
    }

    /* we now have a packet which can be read and processed */

    if (s->s3->change_cipher_spec /* set when we receive ChangeCipherSpec,
                                   * reset by ssl3_get_finished */
        && (SSL3_RECORD_get_type(rr) != SSL3_RT_HANDSHAKE)) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_DATA_BETWEEN_CCS_AND_FINISHED);
        goto f_err;
    }

    /*
     * If the other end has shut down, throw anything we read away (even in
     * 'peek' mode)
     */
    if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
        SSL3_RECORD_set_length(rr, 0);
        s->rwstate = SSL_NOTHING;
        return (0);
    }

    if (type == SSL3_RECORD_get_type(rr)
            || (SSL3_RECORD_get_type(rr) == SSL3_RT_CHANGE_CIPHER_SPEC
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
            (s->enc_read_ctx == NULL)) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_APP_DATA_IN_HANDSHAKE);
            goto f_err;
        }

        if (type == SSL3_RT_HANDSHAKE
                && SSL3_RECORD_get_type(rr) == SSL3_RT_CHANGE_CIPHER_SPEC
                && s->rlayer.handshake_fragment_len > 0) {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_CCS_RECEIVED_EARLY);
            goto f_err;
        }

        if (recvd_type != NULL)
            *recvd_type = SSL3_RECORD_get_type(rr);

        if (len <= 0)
            return (len);

        if ((unsigned int)len > SSL3_RECORD_get_length(rr))
            n = SSL3_RECORD_get_length(rr);
        else
            n = (unsigned int)len;

        memcpy(buf, &(rr->data[rr->off]), n);
        if (!peek) {
            SSL3_RECORD_add_length(rr, -n);
            SSL3_RECORD_add_off(rr, n);
            if (SSL3_RECORD_get_length(rr) == 0) {
                s->rlayer.rstate = SSL_ST_READ_HEADER;
                SSL3_RECORD_set_off(rr, 0);
                if (s->mode & SSL_MODE_RELEASE_BUFFERS
                    && SSL3_BUFFER_get_left(&s->rlayer.rbuf) == 0)
                    ssl3_release_read_buffer(s);
            }
        }
        return (n);
    }

    /*
     * If we get here, then type != rr->type; if we have a handshake message,
     * then it was unexpected (Hello Request or Client Hello) or invalid (we
     * were actually expecting a CCS).
     */

    if (rr->type == SSL3_RT_HANDSHAKE && type == SSL3_RT_CHANGE_CIPHER_SPEC) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_UNEXPECTED_MESSAGE);
        goto f_err;
    }

    /*
     * Lets just double check that we've not got an SSLv2 record
     */
    if (rr->rec_version == SSL2_VERSION) {
        /*
         * Should never happen. ssl3_get_record() should only give us an SSLv2
         * record back if this is the first packet and we are looking for an
         * initial ClientHello. Therefore |type| should always be equal to
         * |rr->type|. If not then something has gone horribly wrong
         */
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_READ_BYTES, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }

    if(s->method->version == TLS_ANY_VERSION
            && (s->server || rr->type != SSL3_RT_ALERT)) {
        /*
         * If we've got this far and still haven't decided on what version
         * we're using then this must be a client side alert we're dealing with
         * (we don't allow heartbeats yet). We shouldn't be receiving anything
         * other than a ClientHello if we are a server.
         */
        s->version = rr->rec_version;
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_UNEXPECTED_MESSAGE);
        goto f_err;
    }

    /*
     * In case of record types for which we have 'fragment' storage, fill
     * that so that we can process the data at a fixed place.
     */
    {
        unsigned int dest_maxlen = 0;
        unsigned char *dest = NULL;
        unsigned int *dest_len = NULL;

        if (SSL3_RECORD_get_type(rr) == SSL3_RT_HANDSHAKE) {
            dest_maxlen = sizeof s->rlayer.handshake_fragment;
            dest = s->rlayer.handshake_fragment;
            dest_len = &s->rlayer.handshake_fragment_len;
        } else if (SSL3_RECORD_get_type(rr) == SSL3_RT_ALERT) {
            dest_maxlen = sizeof s->rlayer.alert_fragment;
            dest = s->rlayer.alert_fragment;
            dest_len = &s->rlayer.alert_fragment_len;
        }
#ifndef OPENSSL_NO_HEARTBEATS
        else if (SSL3_RECORD_get_type(rr)== TLS1_RT_HEARTBEAT) {
            /* We can ignore 0 return values */
            if (tls1_process_heartbeat(s, SSL3_RECORD_get_data(rr),
                    SSL3_RECORD_get_length(rr)) < 0) {
                return -1;
            }

            /* Exit and notify application to read again */
            SSL3_RECORD_set_length(rr, 0);
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
            return (-1);
        }
#endif

        if (dest_maxlen > 0) {
            n = dest_maxlen - *dest_len; /* available space in 'dest' */
            if (SSL3_RECORD_get_length(rr) < n)
                n = SSL3_RECORD_get_length(rr); /* available bytes */

            /* now move 'n' bytes: */
            while (n-- > 0) {
                dest[(*dest_len)++] =
                    SSL3_RECORD_get_data(rr)[SSL3_RECORD_get_off(rr)];
                SSL3_RECORD_add_off(rr, 1);
                SSL3_RECORD_add_length(rr, -1);
            }

            if (*dest_len < dest_maxlen)
                goto start;     /* fragment was too small */
        }
    }

    /*-
     * s->rlayer.handshake_fragment_len == 4  iff  rr->type == SSL3_RT_HANDSHAKE;
     * s->rlayer.alert_fragment_len == 2      iff  rr->type == SSL3_RT_ALERT.
     * (Possibly rr is 'empty' now, i.e. rr->length may be 0.)
     */

    /* If we are a client, check for an incoming 'Hello Request': */
    if ((!s->server) &&
        (s->rlayer.handshake_fragment_len >= 4) &&
        (s->rlayer.handshake_fragment[0] == SSL3_MT_HELLO_REQUEST) &&
        (s->session != NULL) && (s->session->cipher != NULL)) {
        s->rlayer.handshake_fragment_len = 0;

        if ((s->rlayer.handshake_fragment[1] != 0) ||
            (s->rlayer.handshake_fragment[2] != 0) ||
            (s->rlayer.handshake_fragment[3] != 0)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_BAD_HELLO_REQUEST);
            goto f_err;
        }

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                            s->rlayer.handshake_fragment, 4, s,
                            s->msg_callback_arg);

        if (SSL_is_init_finished(s) &&
            !(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS) &&
            !s->s3->renegotiate) {
            ssl3_renegotiate(s);
            if (ssl3_renegotiate_check(s)) {
                i = s->handshake_func(s);
                if (i < 0)
                    return (i);
                if (i == 0) {
                    SSLerr(SSL_F_SSL3_READ_BYTES,
                           SSL_R_SSL_HANDSHAKE_FAILURE);
                    return (-1);
                }

                if (!(s->mode & SSL_MODE_AUTO_RETRY)) {
                    if (SSL3_BUFFER_get_left(&s->rlayer.rbuf) == 0) {
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
    /*
     * If we are a server and get a client hello when renegotiation isn't
     * allowed send back a no renegotiation alert and carry on. WARNING:
     * experimental code, needs reviewing (steve)
     */
    if (s->server &&
        SSL_is_init_finished(s) &&
        !s->s3->send_connection_binding &&
        (s->version > SSL3_VERSION) &&
        (s->rlayer.handshake_fragment_len >= 4) &&
        (s->rlayer.handshake_fragment[0] == SSL3_MT_CLIENT_HELLO) &&
        (s->session != NULL) && (s->session->cipher != NULL) &&
        !(s->ctx->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
        SSL3_RECORD_set_length(rr, 0);
        ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_RENEGOTIATION);
        goto start;
    }
    if (s->rlayer.alert_fragment_len >= 2) {
        int alert_level = s->rlayer.alert_fragment[0];
        int alert_descr = s->rlayer.alert_fragment[1];

        s->rlayer.alert_fragment_len = 0;

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_ALERT,
                            s->rlayer.alert_fragment, 2, s,
                            s->msg_callback_arg);

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
                s->shutdown |= SSL_RECEIVED_SHUTDOWN;
                return (0);
            }
            /*
             * This is a warning but we receive it if we requested
             * renegotiation and the peer denied it. Terminate with a fatal
             * alert because if application tried to renegotiatie it
             * presumably had a good reason and expects it to succeed. In
             * future we might have a renegotiation where we don't care if
             * the peer refused it where we carry on.
             */
            else if (alert_descr == SSL_AD_NO_RENEGOTIATION) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_NO_RENEGOTIATION);
                goto f_err;
            }
#ifdef SSL_AD_MISSING_SRP_USERNAME
            else if (alert_descr == SSL_AD_MISSING_SRP_USERNAME)
                return (0);
#endif
        } else if (alert_level == SSL3_AL_FATAL) {
            char tmp[16];

            s->rwstate = SSL_NOTHING;
            s->s3->fatal_alert = alert_descr;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_AD_REASON_OFFSET + alert_descr);
            BIO_snprintf(tmp, sizeof tmp, "%d", alert_descr);
            ERR_add_error_data(2, "SSL alert number ", tmp);
            s->shutdown |= SSL_RECEIVED_SHUTDOWN;
            SSL_CTX_remove_session(s->ctx, s->session);
            return (0);
        } else {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_UNKNOWN_ALERT_TYPE);
            goto f_err;
        }

        goto start;
    }

    if (s->shutdown & SSL_SENT_SHUTDOWN) { /* but we have not received a
                                            * shutdown */
        s->rwstate = SSL_NOTHING;
        SSL3_RECORD_set_length(rr, 0);
        return (0);
    }

    if (SSL3_RECORD_get_type(rr) == SSL3_RT_CHANGE_CIPHER_SPEC) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_CCS_RECEIVED_EARLY);
        goto f_err;
    }

    /*
     * Unexpected handshake message (Client Hello, or protocol violation)
     */
    if ((s->rlayer.handshake_fragment_len >= 4)
            && !ossl_statem_get_in_handshake(s)) {
        if (SSL_is_init_finished(s) &&
            !(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)) {
            ossl_statem_set_in_init(s, 1);
            s->renegotiate = 1;
            s->new_session = 1;
        }
        i = s->handshake_func(s);
        if (i < 0)
            return (i);
        if (i == 0) {
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }

        if (!(s->mode & SSL_MODE_AUTO_RETRY)) {
            if (SSL3_BUFFER_get_left(&s->rlayer.rbuf) == 0) {
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

    switch (SSL3_RECORD_get_type(rr)) {
    default:
        /*
         * TLS up to v1.1 just ignores unknown message types: TLS v1.2 give
         * an unexpected message alert.
         */
        if (s->version >= TLS1_VERSION && s->version <= TLS1_1_VERSION) {
            SSL3_RECORD_set_length(rr, 0);
            goto start;
        }
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
        goto f_err;
    case SSL3_RT_CHANGE_CIPHER_SPEC:
    case SSL3_RT_ALERT:
    case SSL3_RT_HANDSHAKE:
        /*
         * we already handled all of these, with the possible exception of
         * SSL3_RT_HANDSHAKE when ossl_statem_get_in_handshake(s) is true, but
         * that should not happen when type != rr->type
         */
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_READ_BYTES, ERR_R_INTERNAL_ERROR);
        goto f_err;
    case SSL3_RT_APPLICATION_DATA:
        /*
         * At this point, we were expecting handshake data, but have
         * application data.  If the library was running inside ssl3_read()
         * (i.e. in_read_app_data is set) and it makes sense to read
         * application data at this point (session renegotiation not yet
         * started), we will indulge it.
         */
        if (ossl_statem_app_data_allowed(s)) {
            s->s3->in_read_app_data = 2;
            return (-1);
        } else {
            al = SSL_AD_UNEXPECTED_MESSAGE;
            SSLerr(SSL_F_SSL3_READ_BYTES, SSL_R_UNEXPECTED_RECORD);
            goto f_err;
        }
    }
    /* not reached */

 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    return (-1);
}

void ssl3_record_sequence_update(unsigned char *seq)
{
    int i;

    for (i = 7; i >= 0; i--) {
        ++seq[i];
        if (seq[i] != 0)
            break;
    }
}

/*
 * Returns true if the current rrec was sent in SSLv2 backwards compatible
 * format and false otherwise.
 */
int RECORD_LAYER_is_sslv2_record(RECORD_LAYER *rl)
{
    return SSL3_RECORD_is_sslv2_record(&rl->rrec);
}

/*
 * Returns the length in bytes of the current rrec
 */
unsigned int RECORD_LAYER_get_rrec_length(RECORD_LAYER *rl)
{
    return SSL3_RECORD_get_length(&rl->rrec);
}
