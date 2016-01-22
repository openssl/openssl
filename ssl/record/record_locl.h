/* ssl/record/record_locl.h */
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
 * Copyright (c) 1998-2015 The OpenSSL Project.  All rights reserved.
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


/*****************************************************************************
 *                                                                           *
 * The following macros/functions are PRIVATE to the record layer. They      *
 * should NOT be used outside of the record layer.                           *
 *                                                                           *
 *****************************************************************************/

/* Functions/macros provided by the RECORD_LAYER component */

#define RECORD_LAYER_get_rbuf(rl)               (&(rl)->rbuf)
#define RECORD_LAYER_get_wbuf(rl)               (&(rl)->wbuf)
#define RECORD_LAYER_get_rrec(rl)               (&(rl)->rrec)
#define RECORD_LAYER_get_wrec(rl)               (&(rl)->wrec)
#define RECORD_LAYER_set_packet(rl, p)          ((rl)->packet = (p))
#define RECORD_LAYER_reset_packet_length(rl)    ((rl)->packet_length = 0)
#define RECORD_LAYER_get_rstate(rl)             ((rl)->rstate)
#define RECORD_LAYER_set_rstate(rl, st)         ((rl)->rstate = (st))
#define RECORD_LAYER_get_read_sequence(rl)      ((rl)->read_sequence)
#define RECORD_LAYER_get_write_sequence(rl)     ((rl)->write_sequence)
#define DTLS_RECORD_LAYER_get_r_epoch(rl)       ((rl)->d->r_epoch)

__owur int ssl3_read_n(SSL *s, int n, int max, int extend);

void RECORD_LAYER_set_write_sequence(RECORD_LAYER *rl, const unsigned char *ws);
DTLS1_BITMAP *dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr,
                                      unsigned int *is_next_epoch);
int dtls1_process_buffered_records(SSL *s);
int dtls1_retrieve_buffered_record(SSL *s, record_pqueue *queue);
int dtls1_buffer_record(SSL *s, record_pqueue *q,
                               unsigned char *priority);
void ssl3_record_sequence_update(unsigned char *seq);

/* Functions provided by the DTLS1_BITMAP component */

int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap);
void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap);


/* Macros/functions provided by the SSL3_BUFFER component */

#define SSL3_BUFFER_get_buf(b)              ((b)->buf)
#define SSL3_BUFFER_set_buf(b, n)           ((b)->buf = (n))
#define SSL3_BUFFER_get_len(b)              ((b)->len)
#define SSL3_BUFFER_set_len(b, l)           ((b)->len = (l))
#define SSL3_BUFFER_get_left(b)             ((b)->left)
#define SSL3_BUFFER_set_left(b, l)          ((b)->left = (l))
#define SSL3_BUFFER_add_left(b, l)          ((b)->left += (l))
#define SSL3_BUFFER_get_offset(b)           ((b)->offset)
#define SSL3_BUFFER_set_offset(b, o)        ((b)->offset = (o))
#define SSL3_BUFFER_add_offset(b, o)        ((b)->offset += (o))
#define SSL3_BUFFER_is_initialised(b)       ((b)->buf != NULL)

void SSL3_BUFFER_clear(SSL3_BUFFER *b);
void SSL3_BUFFER_set_data(SSL3_BUFFER *b, const unsigned char *d, int n);
void SSL3_BUFFER_release(SSL3_BUFFER *b);
__owur int ssl3_setup_read_buffer(SSL *s);
__owur int ssl3_setup_write_buffer(SSL *s);
int ssl3_release_read_buffer(SSL *s);
int ssl3_release_write_buffer(SSL *s);

/* Macros/functions provided by the SSL3_RECORD component */

#define SSL3_RECORD_get_type(r)                 ((r)->type)
#define SSL3_RECORD_set_type(r, t)              ((r)->type = (t))
#define SSL3_RECORD_get_length(r)               ((r)->length)
#define SSL3_RECORD_set_length(r, l)            ((r)->length = (l))
#define SSL3_RECORD_add_length(r, l)            ((r)->length += (l))
#define SSL3_RECORD_get_data(r)                 ((r)->data)
#define SSL3_RECORD_set_data(r, d)              ((r)->data = (d))
#define SSL3_RECORD_get_input(r)                ((r)->input)
#define SSL3_RECORD_set_input(r, i)             ((r)->input = (i))
#define SSL3_RECORD_reset_input(r)              ((r)->input = (r)->data)
#define SSL3_RECORD_get_seq_num(r)              ((r)->seq_num)
#define SSL3_RECORD_get_off(r)                  ((r)->off)
#define SSL3_RECORD_set_off(r, o)               ((r)->off = (o))
#define SSL3_RECORD_add_off(r, o)               ((r)->off += (o))
#define SSL3_RECORD_get_epoch(r)                ((r)->epoch)
#define SSL3_RECORD_is_sslv2_record(r) \
            ((r)->rec_version == SSL2_VERSION)

void SSL3_RECORD_clear(SSL3_RECORD *r);
void SSL3_RECORD_release(SSL3_RECORD *r);
int SSL3_RECORD_setup(SSL3_RECORD *r);
void SSL3_RECORD_set_seq_num(SSL3_RECORD *r, const unsigned char *seq_num);
int ssl3_get_record(SSL *s);
__owur int ssl3_do_compress(SSL *ssl);
__owur int ssl3_do_uncompress(SSL *ssl);
void ssl3_cbc_copy_mac(unsigned char *out,
                       const SSL3_RECORD *rec, unsigned md_size);
__owur int ssl3_cbc_remove_padding(const SSL *s,
                            SSL3_RECORD *rec,
                            unsigned block_size, unsigned mac_size);
__owur int tls1_cbc_remove_padding(const SSL *s,
                            SSL3_RECORD *rec,
                            unsigned block_size, unsigned mac_size);
int dtls1_process_record(SSL *s);
__owur int dtls1_get_record(SSL *s);
