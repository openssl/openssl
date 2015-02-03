/* ssl/record/rec_layer.h */
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

#include "../ssl_locl.h"

/*****************************************************************************
 *                                                                           *
 * These structures should be considered "opaque" to anything outside of the *
 * record layer. No non-record layer code should be accessing the members of *
 * these structures.                                                         *
 *                                                                           *
 *****************************************************************************/

typedef struct dtls1_bitmap_st {
    unsigned long map;          /* track 32 packets on 32-bit systems and 64
                                 * - on 64-bit systems */
    unsigned char max_seq_num[8]; /* max record number seen so far, 64-bit
                                   * value in big-endian encoding */
} DTLS1_BITMAP;


typedef struct record_pqueue_st {
    unsigned short epoch;
    pqueue q;
} record_pqueue;

typedef struct record_layer_st {
    /* The parent SSL structure */
    SSL *s;
    /*
     * Read as many input bytes as possible (for
     * non-blocking reads)
     */
    int read_ahead;
    /* where we are when reading */
    int rstate;
    /* read IO goes into here */
    SSL3_BUFFER rbuf;
    /* write IO goes into here */
    SSL3_BUFFER wbuf;
    /* each decoded record goes in here */
    SSL3_RECORD rrec;
    /* goes out from here */
    SSL3_RECORD wrec;

    /* used internally to point at a raw packet */
    unsigned char *packet;
    unsigned int packet_length;

    /* number of bytes sent so far */
    unsigned int wnum;

    /*
     * storage for Alert/Handshake protocol data received but not yet
     * processed by ssl3_read_bytes:
     */
    unsigned char alert_fragment[2];
    unsigned int alert_fragment_len;
    unsigned char handshake_fragment[4];
    unsigned int handshake_fragment_len;

    /* partial write - check the numbers match */
    /* number bytes written */
    int wpend_tot;
    int wpend_type;
    /* number of bytes submitted */
    int wpend_ret;
    const unsigned char *wpend_buf;

    unsigned char read_sequence[8];
    unsigned char write_sequence[8];
} RECORD_LAYER;


/*****************************************************************************
 *                                                                           *
 * The following macros/functions represent the libssl internal API to the   *
 * record layer.                                                             *
 *                                                                           *
 *****************************************************************************/

#define RECORD_LAYER_set_read_ahead(rl, ra)     ((rl)->read_ahead = (ra))
#define RECORD_LAYER_get_read_ahead(rl)         ((rl)->read_ahead)
#define RECORD_LAYER_setup_comp_buffer(rl)      (SSL3_RECORD_setup(&(rl)->rrec))
#define RECORD_LAYER_get_packet(rl)             ((rl)->packet)
#define RECORD_LAYER_get_packet_length(rl)      ((rl)->packet_length)
#define RECORD_LAYER_add_packet_length(rl, inc) ((rl)->packet_length += (inc))
#define RECORD_LAYER_get_read_sequence(rl)      ((rl)->read_sequence)
#define RECORD_LAYER_get_write_sequence(rl)     ((rl)->write_sequence)

void RECORD_LAYER_init(RECORD_LAYER *rl, SSL *s);
void RECORD_LAYER_clear(RECORD_LAYER *rl);
void RECORD_LAYER_release(RECORD_LAYER *rl);
int RECORD_LAYER_read_pending(RECORD_LAYER *rl);
int RECORD_LAYER_write_pending(RECORD_LAYER *rl);
int RECORD_LAYER_set_data(RECORD_LAYER *rl, const unsigned char *buf, int len);
void RECORD_LAYER_dup(RECORD_LAYER *dst, RECORD_LAYER *src);
void RECORD_LAYER_reset_read_sequence(RECORD_LAYER *rl);
void RECORD_LAYER_reset_write_sequence(RECORD_LAYER *rl);
void RECORD_LAYER_set_write_sequence(RECORD_LAYER *rl, const unsigned char *ws);
__owur int ssl3_pending(const SSL *s);
__owur int ssl23_read_bytes(SSL *s, int n);
__owur int ssl23_write_bytes(SSL *s);
__owur int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
__owur int do_ssl3_write(SSL *s, int type, const unsigned char *buf,
                         unsigned int len, int create_empty_fragment);
__owur int ssl3_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);
__owur int dtls1_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);
int dtls1_write_bytes(SSL *s, int type, const void *buf, int len);
__owur int do_dtls1_write(SSL *s, int type, const unsigned char *buf,
                   unsigned int len, int create_empty_fragement);
void dtls1_reset_seq_numbers(SSL *s, int rw);


/*****************************************************************************
 *                                                                           *
 * The following macros/functions are private to the record layer. They      *
 * should not be used outside of the record layer.                           *
 *                                                                           *
 *****************************************************************************/

#define RECORD_LAYER_get_rbuf(rl)               (&(rl)->rbuf)
#define RECORD_LAYER_get_wbuf(rl)               (&(rl)->wbuf)
#define RECORD_LAYER_get_rrec(rl)               (&(rl)->rrec)
#define RECORD_LAYER_get_wrec(rl)               (&(rl)->wrec)
#define RECORD_LAYER_set_packet(rl, p)          ((rl)->packet = (p))
#define RECORD_LAYER_reset_packet_length(rl)    ((rl)->packet_length = 0)
#define RECORD_LAYER_get_rstate(rl)             ((rl)->rstate)
#define RECORD_LAYER_set_rstate(rl, st)         ((rl)->rstate = (st))

__owur int ssl3_read_n(SSL *s, int n, int max, int extend);
__owur int ssl3_write_pending(SSL *s, int type, const unsigned char *buf,
                       unsigned int len);
int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap);
void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap);
DTLS1_BITMAP *dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr,
                                      unsigned int *is_next_epoch);
int dtls1_process_buffered_records(SSL *s);
int dtls1_retrieve_buffered_record(SSL *s, record_pqueue *queue);
int dtls1_buffer_record(SSL *s, record_pqueue *q,
                               unsigned char *priority);

