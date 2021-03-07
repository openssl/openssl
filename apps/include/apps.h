/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_H
# define OSSL_APPS_H

# include "e_os.h" /* struct timeval for DTLS */
# include "internal/nelem.h"
# include "internal/sockets.h" /* for openssl_fdset() */
# include <assert.h>

# include <stdarg.h>
# include <sys/types.h>

# include <openssl/e_os2.h>
# include <openssl/types.h>
# include <openssl/bio.h>
# include <openssl/conf.h>
# include <openssl/txt_db.h>
# include <openssl/engine.h>
# include <openssl/ocsp.h>
# include <openssl/http.h>
# include <signal.h>
# include "apps_ui.h"
# include "opt.h"
# include "fmt.h"
# include "platform.h"
# include "engine_loader.h"
# include "apps_extracted.h"
# include "apps_os_specific.h"

/*
 * quick macro when you need to pass an unsigned char instead of a char.
 * this is true for some implementations of the is*() functions, for
 * example.
 */
# define _UC(c) ((unsigned char)(c))

void app_RAND_load_conf(CONF *c, const char *section);
void app_RAND_write(void);
int app_RAND_load(void);

extern char *default_config_file; /* may be "" */
extern BIO *bio_in;
extern BIO *bio_out;
extern BIO *bio_err;
extern const unsigned char tls13_aes128gcmsha256_id[];
extern const unsigned char tls13_aes256gcmsha384_id[];
extern BIO_ADDR *ourpeer;

CONF *app_load_config_modules(const char *configfile);
//void wait_for_async(SSL *s);
//# if defined(OPENSSL_SYS_MSDOS)
//int has_stdin_waiting(void);
//# endif

void corrupt_signature(const ASN1_STRING *signature);

typedef struct args_st {
    int size;
    int argc;
    char **argv;
} ARGS;

/* We need both wrap and the "real" function because libcrypto uses both. */
int wrap_password_callback(char *buf, int bufsiz, int verify, void *cb_data);

int chopup_args(ARGS *arg, char *buf);
int dump_cert_text(BIO *out, X509 *x);
void print_name(BIO *out, const char *title, const X509_NAME *nm);
void print_bignum_var(BIO *, const BIGNUM *, const char*,
                      int, unsigned char *);
void print_array(BIO *, const char *, int, const unsigned char *);
char *get_passwd(const char *pass, const char *desc);
#define load_cert(uri, desc) load_cert_pass(uri, 1, NULL, desc)
X509_CRL *load_crl(const char *uri, const char *desc);
void clear_free(char *str);
EVP_PKEY *load_pubkey(const char *uri, int format, int maybe_stdin,
                      const char *pass, ENGINE *e, const char *desc);
EVP_PKEY *load_keyparams(const char *uri, int maybe_stdin, const char *keytype,
                         const char *desc);
int load_certs(const char *uri, STACK_OF(X509) **certs,
               const char *pass, const char *desc);
int load_crls(const char *uri, STACK_OF(X509_CRL) **crls,
              const char *pass, const char *desc);
int load_key_cert_crl(const char *uri, int maybe_stdin,
                      const char *pass, const char *desc,
                      EVP_PKEY **ppkey, EVP_PKEY **ppubkey,
                      X509 **pcert, X509_CRL **pcrl);
X509_STORE *setup_verify(const char *CAfile, int noCAfile,
                         const char *CApath, int noCApath,
                         const char *CAstore, int noCAstore);
__owur int ctx_set_verify_locations(SSL_CTX *ctx,
                                    const char *CAfile, int noCAfile,
                                    const char *CApath, int noCApath,
                                    const char *CAstore, int noCAstore);

# ifndef OPENSSL_NO_CT

/*
 * Sets the file to load the Certificate Transparency log list from.
 * If path is NULL, loads from the default file path.
 * Returns 1 on success, 0 otherwise.
 */
__owur int ctx_set_ctlog_list_file(SSL_CTX *ctx, const char *path);

# endif

ENGINE *setup_engine_methods(const char *id, unsigned int methods, int debug);
# define setup_engine(e, debug) setup_engine_methods(e, (unsigned int)-1, debug)
int init_engine(ENGINE *e);
int finish_engine(ENGINE *e);
char *make_engine_uri(ENGINE *e, const char *key_id, const char *desc);

int get_legacy_pkey_id(OSSL_LIB_CTX *libctx, const char *algname, ENGINE *e);
const EVP_MD *get_digest_from_engine(const char *name);
const EVP_CIPHER *get_cipher_from_engine(const char *name);

# ifndef OPENSSL_NO_OCSP
OCSP_RESPONSE *process_responder(OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 STACK_OF(CONF_VALUE) *headers,
                                 int req_timeout);
# endif

/* Functions defined in ca.c and also used in ocsp.c */
int unpack_revinfo(ASN1_TIME **prevtm, int *preason, ASN1_OBJECT **phold,
                   ASN1_GENERALIZEDTIME **pinvtm, const char *str);

# define DB_type         0
# define DB_exp_date     1
# define DB_rev_date     2
# define DB_serial       3      /* index - unique */
# define DB_file         4
# define DB_name         5      /* index - unique when active and not
                                 * disabled */
# define DB_NUMBER       6

# define DB_TYPE_REV     'R'    /* Revoked  */
# define DB_TYPE_EXP     'E'    /* Expired  */
# define DB_TYPE_VAL     'V'    /* Valid ; inserted with: ca ... -valid */
# define DB_TYPE_SUSP    'S'    /* Suspended  */

void app_bail_out(char *fmt, ...);
void* app_malloc(int sz, const char *what);
void policies_print(X509_STORE_CTX *ctx);
int bio_to_mem(unsigned char **out, int maxlen, BIO *in);
int x509_ctrl_string(X509 *x, const char *value);
int init_gen_str(EVP_PKEY_CTX **pctx,
                 const char *algname, ENGINE *e, int do_param,
                 OSSL_LIB_CTX *libctx, const char *propq);
int do_X509_verify(X509 *x, EVP_PKEY *pkey, STACK_OF(OPENSSL_STRING) *vfyopts);
int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts);
int do_X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts);

extern char *psk_key;


unsigned char *next_protos_parse(size_t *outlen, const char *in);

void print_cert_checks(BIO *bio, X509 *x,
                       const char *checkhost,
                       const char *checkemail, const char *checkip);

void store_setup_crl_download(X509_STORE *st);

typedef struct app_http_tls_info_st {
    const char *server;
    const char *port;
    int use_proxy;
    long timeout;
    SSL_CTX *ssl_ctx;
} APP_HTTP_TLS_INFO;
BIO *app_http_tls_cb(BIO *hbio, /* APP_HTTP_TLS_INFO */ void *arg,
                     int connect, int detail);
# ifndef OPENSSL_NO_SOCK
ASN1_VALUE *app_http_get_asn1(const char *url, const char *proxy,
                              const char *no_proxy, SSL_CTX *ssl_ctx,
                              const STACK_OF(CONF_VALUE) *headers,
                              long timeout, const char *expected_content_type,
                              const ASN1_ITEM *it);
ASN1_VALUE *app_http_post_asn1(const char *host, const char *port,
                               const char *path, const char *proxy,
                               const char *no_proxy, SSL_CTX *ctx,
                               const STACK_OF(CONF_VALUE) *headers,
                               const char *content_type,
                               ASN1_VALUE *req, const ASN1_ITEM *req_it,
                               long timeout, const ASN1_ITEM *rsp_it);
# endif

# define EXT_COPY_NONE   0
# define EXT_COPY_ADD    1
# define EXT_COPY_ALL    2

# define NETSCAPE_CERT_HDR       "certificate"

# define APP_PASS_LEN    1024

/*
 * IETF RFC 5280 says serial number must be <= 20 bytes. Use 159 bits
 * so that the first bit will never be one, so that the DER encoding
 * rules won't force a leading octet.
 */
# define SERIAL_RAND_BITS        159

//int app_access(const char *, int flag);
//int fileno_stdin(void);
//int fileno_stdout(void);
//int raw_read_stdin(void *, int);
//int raw_write_stdout(const void *, int);

//# define TM_START        0
//# define TM_STOP         1
//double app_tminterval(int stop, int usertime);

void make_uppercase(char *string);

typedef struct verify_options_st {
    int depth;
    int quiet;
    int error;
    int return_error;
} VERIFY_CB_ARGS;

extern VERIFY_CB_ARGS verify_args;

OSSL_PARAM *app_params_new_from_opts(STACK_OF(OPENSSL_STRING) *opts,
                                     const OSSL_PARAM *paramdefs);
void app_params_free(OSSL_PARAM *params);
//void app_providers_cleanup(void);

//int app_set_propq(const char *arg);

#endif
