/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

typedef struct ssl_connection_st SSL_CONNECTION;
typedef struct ssl3_buffer_st SSL3_BUFFER;

#include <openssl/core_dispatch.h>
#include "recordmethod.h"

/*****************************************************************************
 *                                                                           *
 * These structures should be considered PRIVATE to the record layer. No     *
 * non-record layer code should be using these structures in any way.        *
 *                                                                           *
 *****************************************************************************/

struct ssl3_buffer_st {
    /* at least SSL3_RT_MAX_PACKET_SIZE bytes, see ssl3_setup_buffers() */
    unsigned char *buf;
    /* default buffer size (or 0 if no default set) */
    size_t default_len;
    /* buffer size */
    size_t len;
    /* where to 'copy from' */
    size_t offset;
    /* how many bytes left */
    size_t left;
    /* 'buf' is from application for KTLS */
    int app_buffer;
    /* The type of data stored in this buffer. Only used for writing */
    int type;
};

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
    size_t length;
    /*
     * How many bytes were available before padding was removed? This is used
     * to implement the MAC check in constant time for CBC records.
     */
    /* rw */
    size_t orig_len;
    /* read/write offset into 'buf' */
    /* r */
    size_t off;
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
    uint16_t epoch;
    /* sequence number, needed by DTLS1 */
    /* r */
    unsigned char seq_num[SEQ_NUM_SIZE];
} SSL3_RECORD;

typedef struct tls_record_st {
    void *rechandle;
    int version;
    int type;
    /* The data buffer containing bytes from the record */
    unsigned char *data;
    /* Number of remaining to be read in the data buffer */
    size_t length;
    /* Offset into the data buffer where to start reading */
    size_t off;
    /* epoch number. DTLS only */
    uint16_t epoch;
    /* sequence number. DTLS only */
    unsigned char seq_num[SEQ_NUM_SIZE];
#ifndef OPENSSL_NO_SCTP
    struct bio_dgram_sctp_rcvinfo recordinfo;
#endif
} TLS_RECORD;

typedef struct record_pqueue_st {
    uint16_t epoch;
    struct pqueue_st *q;
} record_pqueue;

typedef struct dtls_record_layer_st {
    /*
     * The current data and handshake epoch.  This is initially
     * undefined, and starts at zero once the initial handshake is
     * completed
     */
    uint16_t r_epoch;
    uint16_t w_epoch;

    /*
     * Buffered application records. Only for records between CCS and
     * Finished to prevent either protocol violation or unnecessary message
     * loss.
     */
    record_pqueue buffered_app_data;
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
    /* The parent SSL_CONNECTION structure */
    SSL_CONNECTION *s;

    /* Method to use for the read record layer*/
    const OSSL_RECORD_METHOD *rrlmethod;
    /* Method to use for the write record layer*/
    const OSSL_RECORD_METHOD *wrlmethod;
    /* The read record layer object itself */
    OSSL_RECORD_LAYER *rrl;
    /* The write record layer object itself */
    OSSL_RECORD_LAYER *wrl;
    /* BIO to store data destined for the next read record layer epoch */
    BIO *rrlnext;
    /* Default read buffer length to be passed to the record layer */
    size_t default_read_buf_len;

    /*
     * Read as many input bytes as possible (for
     * non-blocking reads)
     */
    int read_ahead;
    /*
     * TODO(RECLAYER): These next 2 fields can be removed when DTLS is moved to
     * the new write record layer architecture.
     */
    /* How many pipelines can be used to write data */
    size_t numwpipes;
    /* write IO goes into here */
    SSL3_BUFFER wbuf[SSL_MAX_PIPELINES + 1];
    /* number of bytes sent so far */
    size_t wnum;
    unsigned char handshake_fragment[4];
    size_t handshake_fragment_len;
    /* partial write - check the numbers match */
    /* number bytes written */
    size_t wpend_tot;
    int wpend_type;
    /* number of bytes submitted */
    size_t wpend_ret;
    const unsigned char *wpend_buf;

    unsigned char write_sequence[SEQ_NUM_SIZE];
    /* Count of the number of consecutive warning alerts received */
    unsigned int alert_count;
    DTLS_RECORD_LAYER *d;

    /* TLS1.3 padding callback */
    size_t (*record_padding_cb)(SSL *s, int type, size_t len, void *arg);
    void *record_padding_arg;
    size_t block_padding;

    /* How many records we have read from the record layer */
    size_t num_recs;
    /* The next record from the record layer that we need to process */
    size_t curr_rec;
    /* Record layer data to be processed */
    TLS_RECORD tlsrecs[SSL_MAX_PIPELINES];

} RECORD_LAYER;

/*****************************************************************************
 *                                                                           *
 * The following macros/functions represent the libssl internal API to the   *
 * record layer. Any libssl code may call these functions/macros             *
 *                                                                           *
 *****************************************************************************/

struct ssl_mac_buf_st {
    unsigned char *mac;
    int alloced;
};
typedef struct ssl_mac_buf_st SSL_MAC_BUF;

#define MIN_SSL2_RECORD_LEN     9

#define RECORD_LAYER_set_read_ahead(rl, ra)     ((rl)->read_ahead = (ra))
#define RECORD_LAYER_get_read_ahead(rl)         ((rl)->read_ahead)
#define RECORD_LAYER_get_packet(rl)             ((rl)->packet)
#define RECORD_LAYER_add_packet_length(rl, inc) ((rl)->packet_length += (inc))
#define DTLS_RECORD_LAYER_get_w_epoch(rl)       ((rl)->d->w_epoch)
#define RECORD_LAYER_get_rbuf(rl)               (&(rl)->rbuf)
#define RECORD_LAYER_get_wbuf(rl)               ((rl)->wbuf)

void RECORD_LAYER_init(RECORD_LAYER *rl, SSL_CONNECTION *s);
void RECORD_LAYER_clear(RECORD_LAYER *rl);
void RECORD_LAYER_release(RECORD_LAYER *rl);
int RECORD_LAYER_read_pending(const RECORD_LAYER *rl);
int RECORD_LAYER_processed_read_pending(const RECORD_LAYER *rl);
int RECORD_LAYER_write_pending(const RECORD_LAYER *rl);
void RECORD_LAYER_reset_write_sequence(RECORD_LAYER *rl);
int RECORD_LAYER_is_sslv2_record(RECORD_LAYER *rl);
__owur size_t ssl3_pending(const SSL *s);
__owur int ssl3_write_bytes(SSL *s, int type, const void *buf, size_t len,
                            size_t *written);
__owur int ssl3_read_bytes(SSL *s, int type, int *recvd_type,
                           unsigned char *buf, size_t len, int peek,
                           size_t *readbytes);
__owur int ssl3_setup_buffers(SSL_CONNECTION *s);
__owur int ssl3_enc(SSL_CONNECTION *s, SSL3_RECORD *inrecs, size_t n_recs,
                    int send, SSL_MAC_BUF *mac, size_t macsize);
__owur int n_ssl3_mac(SSL_CONNECTION *s, SSL3_RECORD *rec, unsigned char *md,
                      int send);
__owur int tls1_enc(SSL_CONNECTION *s, SSL3_RECORD *recs, size_t n_recs,
                    int sending, SSL_MAC_BUF *mac, size_t macsize);
__owur int tls1_mac_old(SSL_CONNECTION *s, SSL3_RECORD *rec, unsigned char *md,
                        int send);
__owur int tls13_enc(SSL_CONNECTION *s, SSL3_RECORD *recs, size_t n_recs,
                     int send, SSL_MAC_BUF *mac, size_t macsize);
int DTLS_RECORD_LAYER_new(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_free(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_clear(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_set_saved_w_epoch(RECORD_LAYER *rl, unsigned short e);
void DTLS_RECORD_LAYER_clear(RECORD_LAYER *rl);
void DTLS_RECORD_LAYER_set_write_sequence(RECORD_LAYER *rl, unsigned char *seq);
__owur int dtls1_read_bytes(SSL *s, int type, int *recvd_type,
                            unsigned char *buf, size_t len, int peek,
                            size_t *readbytes);
__owur int dtls1_write_bytes(SSL_CONNECTION *s, int type, const void *buf,
                             size_t len, size_t *written);
int do_dtls1_write(SSL_CONNECTION *s, int type, const unsigned char *buf,
                   size_t len, int create_empty_fragment, size_t *written);
void dtls1_reset_seq_numbers(SSL_CONNECTION *s, int rw);
void ssl_release_record(SSL_CONNECTION *s, TLS_RECORD *rr);

# define HANDLE_RLAYER_READ_RETURN(s, ret) \
    ossl_tls_handle_rlayer_return(s, 0, ret, OPENSSL_FILE, OPENSSL_LINE)

# define HANDLE_RLAYER_WRITE_RETURN(s, ret) \
    ossl_tls_handle_rlayer_return(s, 1, ret, OPENSSL_FILE, OPENSSL_LINE)

int ossl_tls_handle_rlayer_return(SSL_CONNECTION *s, int writing, int ret,
                                  char *file, int line);

int ssl_set_new_record_layer(SSL_CONNECTION *s, int version, int direction,
                             int level, unsigned char *key, size_t keylen,
                             unsigned char *iv,  size_t ivlen,
                             unsigned char *mackey, size_t mackeylen,
                             const EVP_CIPHER *ciph, size_t taglen,
                             int mactype, const EVP_MD *md,
                             const SSL_COMP *comp);
int ssl_set_record_protocol_version(SSL_CONNECTION *s, int vers);

# define OSSL_FUNC_RLAYER_SKIP_EARLY_DATA        1
OSSL_CORE_MAKE_FUNC(int, rlayer_skip_early_data, (void *cbarg))
# define OSSL_FUNC_RLAYER_MSG_CALLBACK           2
OSSL_CORE_MAKE_FUNC(void, rlayer_msg_callback, (int write_p, int version,
                                                int content_type,
                                                const void *buf, size_t len,
                                                void *cbarg))
# define OSSL_FUNC_RLAYER_SECURITY               3
OSSL_CORE_MAKE_FUNC(int, rlayer_security, (void *cbarg, int op, int bits,
                                           int nid, void *other))
# define OSSL_FUNC_RLAYER_PADDING                4
OSSL_CORE_MAKE_FUNC(size_t, rlayer_padding, (void *cbarg, int type, size_t len))
