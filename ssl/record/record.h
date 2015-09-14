/* ssl/record/record.h */
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

#include <openssl/pqueue.h>

/*****************************************************************************
 *                                                                           *
 * These structures should be considered PRIVATE to the record layer. No     *
 * non-record layer code should be using these structures in any way.        *
 *                                                                           *
 *****************************************************************************/

typedef struct ssl3_buffer_st {
    /* at least SSL3_RT_MAX_PACKET_SIZE bytes, see ssl3_setup_buffers() */
    unsigned char *buf;
    /* buffer size */
    size_t len;
    /* where to 'copy from' */
    int offset;
    /* how many bytes left */
    int left;
} SSL3_BUFFER;

#define SEQ_NUM_SIZE                            8

typedef struct ssl3_record_st {
    /* Record layer version */
    /* r */
    int rec_version;

    /* type of record */
    /* r */
    int type;

    /* How many bytes available */
    /* rw */
    unsigned int length;

    /*
     * How many bytes were available before padding was removed? This is used
     * to implement the MAC check in constant time for CBC records.
     */
    /* rw */
    unsigned int orig_len;

    /* read/write offset into 'buf' */
    /* r */
    unsigned int off;

    /* pointer to the record data */
    /* rw */
    unsigned char *data;

    /* where the decode bytes are */
    /* rw */
    unsigned char *input;

    /* only used with decompression - malloc()ed */
    /* r */
    unsigned char *comp;

    /* epoch number, needed by DTLS1 */
    /* r */
    unsigned long epoch;

    /* sequence number, needed by DTLS1 */
    /* r */
    unsigned char seq_num[SEQ_NUM_SIZE];
} SSL3_RECORD;

typedef struct dtls1_bitmap_st {
    /* Track 32 packets on 32-bit systems and 64 - on 64-bit systems */
    unsigned long map;

    /* Max record number seen so far, 64-bit value in big-endian encoding */
    unsigned char max_seq_num[SEQ_NUM_SIZE];
} DTLS1_BITMAP;

typedef struct record_pqueue_st {
    unsigned short epoch;
    pqueue q;
} record_pqueue;

typedef struct dtls1_record_data_st {
    unsigned char *packet;
    unsigned int packet_length;
    SSL3_BUFFER rbuf;
    SSL3_RECORD rrec;
#  ifndef OPENSSL_NO_SCTP
    struct bio_dgram_sctp_rcvinfo recordinfo;
#  endif
} DTLS1_RECORD_DATA;


typedef struct dtls_record_layer_st {
    /*
     * The current data and handshake epoch.  This is initially
     * undefined, and starts at zero once the initial handshake is
     * completed
     */
    unsigned short r_epoch;
    unsigned short w_epoch;

    /* records being received in the current epoch */
    DTLS1_BITMAP bitmap;
    /* renegotiation starts a new set of sequence numbers */
    DTLS1_BITMAP next_bitmap;

    /* Received handshake records (processed and unprocessed) */
    record_pqueue unprocessed_rcds;
    record_pqueue processed_rcds;
    /*
     * Buffered application records. Only for records between CCS and
     * Finished to prevent either protocol violation or unnecessary message
     * loss.
     */
    record_pqueue buffered_app_data;
    /*
     * storage for Alert/Handshake protocol data received but not yet
     * processed by ssl3_read_bytes:
     */
    unsigned char alert_fragment[DTLS1_AL_HEADER_LENGTH];
    unsigned int alert_fragment_len;
    unsigned char handshake_fragment[DTLS1_HM_HEADER_LENGTH];
    unsigned int handshake_fragment_len;

    /* save last and current sequence numbers for retransmissions */
    unsigned char last_write_sequence[8];
    unsigned char curr_write_sequence[8];
} DTLS_RECORD_LAYER;

/*****************************************************************************
 *                                                                           *
 * This structure should be considered "opaque" to anything outside of the   *
 * record layer. No non-record layer code should be accessing the members of *
 * this structure.                                                           *
 *                                                                           *
 *****************************************************************************/

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

    unsigned char read_sequence[SEQ_NUM_SIZE];
    unsigned char write_sequence[SEQ_NUM_SIZE];
    
    DTLS_RECORD_LAYER *d;
} RECORD_LAYER;


/*****************************************************************************
 *                                                                           *
 * The following macros/functions represent the libssl internal API to the   *
 * record layer. Any libssl code may call these functions/macros             *
 *                                                                           *
 *****************************************************************************/

#define MIN_SSL2_RECORD_LEN     9

#define RECORD_LAYER_set_read_ahead(rl, ra)     ((rl)->read_ahead = (ra))
#define RECORD_LAYER_get_read_ahead(rl)         ((rl)->read_ahead)
#define RECORD_LAYER_get_packet(rl)             ((rl)->packet)
#define RECORD_LAYER_get_packet_length(rl)      ((rl)->packet_length)
#define RECORD_LAYER_add_packet_length(rl, inc) ((rl)->packet_length += (inc))
#define DTLS_RECORD_LAYER_get_w_epoch(rl)       ((rl)->d->w_epoch)
#define DTLS_RECORD_LAYER_get_processed_rcds(rl) \
                                                ((rl)->d->processed_rcds)
#define DTLS_RECORD_LAYER_get_unprocessed_rcds(rl) \
                                                ((rl)->d->unprocessed_rcds)

void RECORD_LAYER_init(RECORD_LAYER *rl, SSL *s);
void RECORD_LAYER_clear(RECORD_LAYER *rl);
void RECORD_LAYER_release(RECORD_LAYER *rl);
int RECORD_LAYER_read_pending(RECORD_LAYER *rl);
int RECORD_LAYER_write_pending(RECORD_LAYER *rl);
int RECORD_LAYER_set_data(RECORD_LAYER *rl, const unsigned char *buf, int len);
void RECORD_LAYER_dup(RECORD_LAYER *dst, RECORD_LAYER *src);
void RECORD_LAYER_reset_read_sequence(RECORD_LAYER *rl);
void RECORD_LAYER_reset_write_sequence(RECORD_LAYER *rl);
int RECORD_LAYER_setup_comp_buffer(RECORD_LAYER *rl);
int RECORD_LAYER_is_sslv2_record(RECORD_LAYER *rl);
unsigned int RECORD_LAYER_get_rrec_length(RECORD_LAYER *rl);
__owur int ssl3_pending(const SSL *s);
__owur int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
__owur int do_ssl3_write(SSL *s, int type, const unsigned char *buf,
                         unsigned int len, int create_empty_fragment);
__owur int ssl3_read_bytes(SSL *s, int type, int *recvd_type,
                           unsigned char *buf, int len, int peek);
__owur int ssl3_setup_buffers(SSL *s);
__owur int ssl3_enc(SSL *s, int send_data);
__owur int n_ssl3_mac(SSL *ssl, unsigned char *md, int send_data);
__owur int ssl3_write_pending(SSL *s, int type, const unsigned char *buf,
                       unsigned int len);
__owur int tls1_enc(SSL *s, int snd);
__owur int tls1_mac(SSL *ssl, unsigned char *md, int snd);
int DTLS_RECORD_LAYER_new(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_free(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_clear(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_set_saved_w_epoch(RECORD_LAYER *rl, unsigned short e);
void DTLS_RECORD_LAYER_clear(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_resync_write(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_set_write_sequence(RECORD_LAYER *rl, unsigned char *seq);
__owur int dtls1_read_bytes(SSL *s, int type, int *recvd_type,
                            unsigned char *buf, int len, int peek);
__owur int dtls1_write_bytes(SSL *s, int type, const void *buf, int len);
__owur int do_dtls1_write(SSL *s, int type, const unsigned char *buf,
                   unsigned int len, int create_empty_fragement);
void dtls1_reset_seq_numbers(SSL *s, int rw);

