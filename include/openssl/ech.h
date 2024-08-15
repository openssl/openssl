/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Externally-visible data structures and prototypes for handling
 * Encrypted ClientHello (ECH).
 */
#ifndef OPENSSL_ECH_H
# define OPENSSL_ECH_H
# pragma once

# include <openssl/ssl.h>
# include <openssl/hpke.h>

# ifndef OPENSSL_NO_ECH

/*
 * Some externally visible limits - most used for sanity checks that could be
 * bigger if needed, but that work for now
 */
#  define OSSL_ECH_MAX_PAYLOAD_LEN 1500 /* max ECH ciphertext to en/decode */
#  define OSSL_ECH_MIN_ECHCONFIG_LEN 32 /* min for all encodings */
#  define OSSL_ECH_MAX_ECHCONFIG_LEN 1500 /* max for all encodings */
#  define OSSL_ECH_MAX_ECHCONFIGEXT_LEN 512 /* ECHConfig extension max */
#  define OSSL_ECH_MAX_MAXNAMELEN 255 /* ECHConfig max for max name length */
#  define OSSL_ECH_MAX_PUBLICNAME 255 /* max ECHConfig public name length */
#  define OSSL_ECH_MAX_ALPNLEN 255 /* max alpn length */
#  define OSSL_ECH_OUTERS_MAX 20 /* max extensions we compress via outer-exts */
#  define OSSL_ECH_ALLEXTS_MAX 32 /* max total number of extension we allow */

/*
 * ECH version. We only support RFC XXXX as of now.  As/if new ECHConfig
 * versions are added, those will be noted here.
 * TODO(ECH): Replace XXXX with the actual RFC number once known.
 */
#  define OSSL_ECH_RFCXXXX_VERSION 0xfe0d /* official ECHConfig version */
/* latest version from an RFC */
#  define OSSL_ECH_CURRENT_VERSION OSSL_ECH_RFCXXXX_VERSION

/* Return codes from SSL_ech_get1_status */
#  define SSL_ECH_STATUS_BACKEND    4 /* ECH backend: saw an ech_is_inner */
#  define SSL_ECH_STATUS_GREASE_ECH 3 /* GREASEd and got an ECH in return */
#  define SSL_ECH_STATUS_GREASE     2 /* ECH GREASE happened  */
#  define SSL_ECH_STATUS_SUCCESS    1 /* Success */
#  define SSL_ECH_STATUS_FAILED     0 /* Some internal or protocol error */
#  define SSL_ECH_STATUS_BAD_CALL   -100 /* Some in/out arguments were NULL */
#  define SSL_ECH_STATUS_NOT_TRIED  -101 /* ECH wasn't attempted  */
#  define SSL_ECH_STATUS_BAD_NAME   -102 /* ECH ok but server cert bad */
#  define SSL_ECH_STATUS_NOT_CONFIGURED -103 /* ECH wasn't configured */
#  define SSL_ECH_STATUS_FAILED_ECH -105 /* We tried, failed and got an ECH, from a good name */
#  define SSL_ECH_STATUS_FAILED_ECH_BAD_NAME -106 /* We tried, failed and got an ECH, from a bad name */

/* if a caller wants to index the last entry in the store */
#  define OSSL_ECHSTORE_LAST -1

/*
 * Application-visible form of ECH information from the DNS, from config
 * files, or from earlier API calls. APIs produce/process an array of these.
 */
typedef struct ossl_ech_info_st {
    int index; /* externally re-usable reference to this value */
    time_t seconds_in_memory; /* number of seconds since this was loaded */
    char *public_name; /* public_name from API or ECHConfig */
    char *inner_name; /* server-name (for inner CH if doing ECH) */
    unsigned char *outer_alpns; /* outer ALPN string */
    size_t outer_alpns_len;
    unsigned char *inner_alpns; /* inner ALPN string */
    size_t inner_alpns_len;
    char *echconfig; /* a JSON-like version of the associated ECHConfig */
} OSSL_ECH_INFO;

/* Values for the for_retry inputs */
#  define SSL_ECH_USE_FOR_RETRY 1
#  define SSL_ECH_NOT_FOR_RETRY 0

/*
 * API calls built around OSSL_ECHSTORE
 */
OSSL_ECHSTORE *OSSL_ECHSTORE_new(OSSL_LIB_CTX *libctx, const char *propq);
void OSSL_ECHSTORE_free(OSSL_ECHSTORE *es);
int OSSL_ECHSTORE_new_config(OSSL_ECHSTORE *es,
                             uint16_t echversion, uint8_t max_name_length,
                             const char *public_name, OSSL_HPKE_SUITE suite);
int OSSL_ECHSTORE_write_pem(OSSL_ECHSTORE *es, int index, BIO *out);
int OSSL_ECHSTORE_read_echconfiglist(OSSL_ECHSTORE *es, BIO *in);
int OSSL_ECHSTORE_get1_info(OSSL_ECHSTORE *es, OSSL_ECH_INFO **info,
                            int *count);
int OSSL_ECHSTORE_downselect(OSSL_ECHSTORE *es, int index);
int OSSL_ECHSTORE_set1_key_and_read_pem(OSSL_ECHSTORE *es, EVP_PKEY *priv,
                                        BIO *in, int for_retry);
int OSSL_ECHSTORE_read_pem(OSSL_ECHSTORE *es, BIO *in, int for_retry);
int OSSL_ECHSTORE_num_keys(OSSL_ECHSTORE *es, int *numkeys);
int OSSL_ECHSTORE_flush_keys(OSSL_ECHSTORE *es, time_t age);

void OSSL_ECH_INFO_free(OSSL_ECH_INFO *info, int count);
int OSSL_ECH_INFO_print(BIO *out, OSSL_ECH_INFO *info, int count);

/*
 * APIs relating OSSL_ECHSTORE to SSL/SSL_CTX
 */
int SSL_CTX_set1_echstore(SSL_CTX *ctx, OSSL_ECHSTORE *es);
int SSL_set1_echstore(SSL *s, OSSL_ECHSTORE *es);

OSSL_ECHSTORE *SSL_CTX_get1_echstore(const SSL_CTX *ctx);
OSSL_ECHSTORE *SSL_get1_echstore(const SSL *s);

int SSL_ech_set_server_names(SSL *s, const char *inner_name,
                             const char *outer_name, int no_outer);
int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name, int no_outer);
int SSL_ech_set_outer_alpn_protos(SSL *s, const unsigned char *protos,
                                  const size_t protos_len);

int SSL_ech_get1_status(SSL *s, char **inner_sni, char **outer_sni);
int SSL_ech_set_grease_suite(SSL *s, const char *suite);
int SSL_ech_set_grease_type(SSL *s, uint16_t type);
typedef unsigned int (*SSL_ech_cb_func)(SSL *s, const char *str);
void SSL_ech_set_callback(SSL *s, SSL_ech_cb_func f);
int SSL_ech_get_retry_config(SSL *s, unsigned char **ec, size_t *eclen);

int SSL_CTX_ech_set_outer_alpn_protos(SSL_CTX *s, const unsigned char *protos,
                                      const size_t protos_len);
int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            int *decrypted_ok,
                            char **inner_sni, char **outer_sni,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len,
                            unsigned char **hrrtok, size_t *toklen);
void SSL_CTX_ech_set_callback(SSL_CTX *ctx, SSL_ech_cb_func f);

# endif
#endif
