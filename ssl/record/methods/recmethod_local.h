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
#include "../../ssl_local.h"
#include "../record_local.h"

/* Protocol version specific function pointers */
struct record_functions_st
{
    /*
     * Returns either OSSL_RECORD_RETURN_SUCCESS, OSSL_RECORD_RETURN_FATAL or
     * OSSL_RECORD_RETURN_NON_FATAL_ERR if we can keep trying to find an
     * alternative record layer.
     */
    int (*set_crypto_state)(OSSL_RECORD_LAYER *rl, int level,
                            unsigned char *key, size_t keylen,
                            unsigned char *iv, size_t ivlen,
                            unsigned char *mackey, size_t mackeylen,
                            const EVP_CIPHER *ciph,
                            size_t taglen,
                            /* TODO(RECLAYER): This probably should not be an int */
                            int mactype,
                            const EVP_MD *md,
                            const SSL_COMP *comp,
                            /* TODO(RECLAYER): Remove me */
                            SSL_CONNECTION *s);

    int (*read_n)(OSSL_RECORD_LAYER *rl, size_t n, size_t max, int extend,
                  int clearold, size_t *readbytes);
    /*
     * Returns:
     *    0: if the record is publicly invalid, or an internal error, or AEAD
     *       decryption failed, or EtM decryption failed.
     *    1: Success or MtE decryption failed (MAC will be randomised)
     */
    int (*cipher)(OSSL_RECORD_LAYER *rl, SSL3_RECORD *recs, size_t n_recs,
                  int sending, SSL_MAC_BUF *macs, size_t macsize,
                  /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s);
    /* Returns 1 for success or 0 for error */
    int (*mac)(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec, unsigned char *md,
               int sending, /* TODO(RECLAYER): Remove me */SSL_CONNECTION *ssl);

    /* Return 1 for success or 0 for error */
    int (*set_protocol_version)(OSSL_RECORD_LAYER *rl, int version);

    /* Return 1 for success or 0 for error */
    int (*validate_record_header)(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec);

    /* Return 1 for success or 0 for error */
    int (*post_process_record)(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec,
                               /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s);
};

struct ossl_record_layer_st
{
    OSSL_LIB_CTX *libctx;
    const char *propq;
    int isdtls;
    int version;
    int role;
    int direction;

    /*
     * A BIO containing any data read in the previous epoch that was destined
     * for this epoch
     */
    BIO *prev;

    /* The transport BIO */
    BIO *bio;

    /*
     * A BIO where we will send any data read by us that is destined for the
     * next epoch.
     */
    BIO *next;

    /* Types match the equivalent structures in the SSL object */
    uint64_t options;
    /*
     * TODO(RECLAYER): Should we take the opportunity to make this uint64_t
     * even though upper layer continue to use uint32_t?
     */
    uint32_t mode;

    /* read IO goes into here */
    SSL3_BUFFER rbuf;
    /* each decoded record goes in here */
    SSL3_RECORD rrec[SSL_MAX_PIPELINES];

    /* How many records have we got available in the rrec bufer */
    size_t num_recs;

    /* The record number in the rrec buffer that can be read next */
    size_t curr_rec;

    /* The number of records that have been released via tls_release_record */
    size_t num_released;

    /* where we are when reading */
    int rstate;

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

    /* The number of consecutive empty records we have received */
    size_t empty_record_count;

    /* cryptographic state */
    EVP_CIPHER_CTX *enc_read_ctx;

    /* used for mac generation */
    EVP_MD_CTX *read_hash;
    /* uncompress */
    COMP_CTX *expand;

    /* Set to 1 if this is the first handshake. 0 otherwise */
    int is_first_handshake;

    /* The negotiated maximum fragment length */
    unsigned int max_frag_len;

    /* Only used by SSLv3 */
    unsigned char mac_secret[EVP_MAX_MD_SIZE];

    /* TLSv1.0/TLSv1.1/TLSv1.2 */
    int use_etm;

    /* TLSv1.3 fields */
    /* static IV */
    unsigned char iv[EVP_MAX_IV_LENGTH];
    /* static read IV */
    unsigned char read_iv[EVP_MAX_IV_LENGTH];
    int allow_plain_alerts;

    /* TLS "any" fields */
    /* Set to true if this is the first record in a connection */
    unsigned int is_first_record;

    size_t taglen;

    /* Function pointers for version specific functions */
    /* Function pointers for version specific functions */
    struct record_functions_st *funcs;
};

extern struct record_functions_st ssl_3_0_funcs;
extern struct record_functions_st tls_1_funcs;
extern struct record_functions_st tls_1_3_funcs;
extern struct record_functions_st tls_any_funcs;

void ossl_rlayer_fatal(OSSL_RECORD_LAYER *rl, int al, int reason,
                       const char *fmt, ...);

# define RLAYERfatal(rl, al, r) RLAYERfatal_data((rl), (al), (r), NULL)
# define RLAYERfatal_data                                          \
    (ERR_new(),                                                    \
     ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC),      \
     ossl_rlayer_fatal)

# define RLAYER_USE_EXPLICIT_IV(rl) ((rl)->version == TLS1_1_VERSION \
                                     || (rl)->version == TLS1_2_VERSION)

int ossl_set_tls_provider_parameters(OSSL_RECORD_LAYER *rl,
                                     EVP_CIPHER_CTX *ctx,
                                     const EVP_CIPHER *ciph,
                                     const EVP_MD *md);
/* ssl3_cbc.c */
__owur char ssl3_cbc_record_digest_supported(const EVP_MD_CTX *ctx);
__owur int ssl3_cbc_digest_record(const EVP_MD *md,
                                  unsigned char *md_out,
                                  size_t *md_out_size,
                                  const unsigned char *header,
                                  const unsigned char *data,
                                  size_t data_size,
                                  size_t data_plus_mac_plus_padding_size,
                                  const unsigned char *mac_secret,
                                  size_t mac_secret_length, char is_sslv3);

int tls_default_read_n(OSSL_RECORD_LAYER *rl, size_t n, size_t max, int extend,
                       int clearold, size_t *readbytes);

int tls_default_set_protocol_version(OSSL_RECORD_LAYER *rl, int version);
int tls_default_validate_record_header(OSSL_RECORD_LAYER *rl, SSL3_RECORD *re);
int tls_default_post_process_record(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec, SSL_CONNECTION *s);
int tls13_common_post_process_record(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec,
                                     SSL_CONNECTION *s);

int
tls_int_new_record_layer(OSSL_LIB_CTX *libctx, const char *propq, int vers,
                         int role, int direction, int level, unsigned char *key,
                         size_t keylen, unsigned char *iv, size_t ivlen,
                         unsigned char *mackey, size_t mackeylen,
                         const EVP_CIPHER *ciph, size_t taglen,
                         /* TODO(RECLAYER): This probably should not be an int */
                         int mactype,
                         const EVP_MD *md, const SSL_COMP *comp, BIO *prev,
                         BIO *transport, BIO *next,
                         BIO_ADDR *local, BIO_ADDR *peer,
                         const OSSL_PARAM *settings, const OSSL_PARAM *options,
                         OSSL_RECORD_LAYER **retrl,
                         /* TODO(RECLAYER): Remove me */
                         SSL_CONNECTION *s);
int tls_free(OSSL_RECORD_LAYER *rl);
int tls_reset(OSSL_RECORD_LAYER *rl);
int tls_unprocessed_read_pending(OSSL_RECORD_LAYER *rl);
int tls_processed_read_pending(OSSL_RECORD_LAYER *rl);
size_t tls_app_data_pending(OSSL_RECORD_LAYER *rl);
int tls_write_pending(OSSL_RECORD_LAYER *rl);
size_t tls_get_max_record_len(OSSL_RECORD_LAYER *rl);
size_t tls_get_max_records(OSSL_RECORD_LAYER *rl);
int tls_write_records(OSSL_RECORD_LAYER *rl, OSSL_RECORD_TEMPLATE **templates,
                      size_t numtempl,  size_t allowance, size_t *sent);
int tls_retry_write_records(OSSL_RECORD_LAYER *rl, size_t allowance,
                            size_t *sent);
int tls_get_alert_code(OSSL_RECORD_LAYER *rl);
int tls_set1_bio(OSSL_RECORD_LAYER *rl, BIO *bio);
int tls_read_record(OSSL_RECORD_LAYER *rl, void **rechandle,  int *rversion,
                    int *type, unsigned char **data, size_t *datalen,
                    uint16_t *epoch, unsigned char *seq_num,
                    /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s);
int tls_release_record(OSSL_RECORD_LAYER *rl, void *rechandle);
int tls_default_set_protocol_version(OSSL_RECORD_LAYER *rl, int version);
int tls_set_protocol_version(OSSL_RECORD_LAYER *rl, int version);
void tls_set_plain_alerts(OSSL_RECORD_LAYER *rl, int allow);
void tls_set_first_handshake(OSSL_RECORD_LAYER *rl, int first);
SSL3_BUFFER *tls_get0_rbuf(OSSL_RECORD_LAYER *rl);
unsigned char *tls_get0_packet(OSSL_RECORD_LAYER *rl);
void tls_set0_packet(OSSL_RECORD_LAYER *rl, unsigned char *packet,
                     size_t packetlen);
size_t tls_get_packet_length(OSSL_RECORD_LAYER *rl);
void tls_reset_packet_length(OSSL_RECORD_LAYER *rl);
