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
    int (*cipher)(OSSL_RECORD_LAYER *rl, SSL3_RECORD *recs, size_t n_recs,
                  int sending, SSL_MAC_BUF *macs, size_t macsize,
                  /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s);
    int (*mac)(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec, unsigned char *md,
               int sending, /* TODO(RECLAYER): Remove me */SSL_CONNECTION *ssl);
};

struct ossl_record_layer_st
{
    OSSL_LIB_CTX *libctx;
    const char *propq;
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
    /* each decoded record goes in here */
    SSL3_RECORD rrec[SSL_MAX_PIPELINES];

    /* How many records have we got available in the rrec bufer */
    size_t num_recs;

    /* The record number in the rrec buffer that can be read next */
    size_t curr_rec;

    /* The number of records that have been released via tls_release_record */
    size_t num_released;

    /* Set to true if this is the first record in a connection */
    unsigned int is_first_record;

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
    /* TLSv1.3 static read IV */
    unsigned char read_iv[EVP_MAX_IV_LENGTH];
    /* used for mac generation */
    EVP_MD_CTX *read_hash;
    /* uncompress */
    COMP_CTX *expand;

    /* Only used by SSLv3 */
    unsigned char mac_secret[EVP_MAX_MD_SIZE];

    /* TLSv1.3 static IV */
    unsigned char iv[EVP_MAX_IV_LENGTH];

    size_t taglen;

    /* Function pointers for version specific functions */
    /* Function pointers for version specific functions */
    struct record_functions_st *funcs;
};

extern struct record_functions_st ssl_3_0_funcs;
extern struct record_functions_st tls_1_funcs;
extern struct record_functions_st tls_1_3_funcs;
extern struct record_functions_st ossl_ktls_funcs;
extern struct record_functions_st tls_any_funcs;

void ossl_rlayer_fatal(OSSL_RECORD_LAYER *rl, int al, int reason,
                       const char *fmt, ...);

# define RLAYERfatal(rl, al, r) RLAYERfatal_data((rl), (al), (r), NULL)
# define RLAYERfatal_data                                          \
    (ERR_new(),                                                    \
     ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC),      \
     ossl_rlayer_fatal)

int ossl_set_tls_provider_parameters(OSSL_RECORD_LAYER *rl,
                                     EVP_CIPHER_CTX *ctx,
                                     const EVP_CIPHER *ciph,
                                     const EVP_MD *md,
                                     SSL_CONNECTION *s);
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
