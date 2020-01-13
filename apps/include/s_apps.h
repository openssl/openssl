/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/opentlsconf.h>

#include <opentls/tls.h>

#define PORT            "4433"
#define PROTOCOL        "tcp"

typedef int (*do_server_cb)(int s, int stype, int prot, unsigned char *context);
int do_server(int *accept_sock, const char *host, const char *port,
              int family, int type, int protocol, do_server_cb cb,
              unsigned char *context, int naccept, BIO *bio_s_out);

int verify_callback(int ok, X509_STORE_CTX *ctx);

int set_cert_stuff(tls_CTX *ctx, char *cert_file, char *key_file);
int set_cert_key_stuff(tls_CTX *ctx, X509 *cert, EVP_PKEY *key,
                       STACK_OF(X509) *chain, int build_chain);
int tls_print_sigalgs(BIO *out, tls *s);
int tls_print_point_formats(BIO *out, tls *s);
int tls_print_groups(BIO *out, tls *s, int noshared);
int tls_print_tmp_key(BIO *out, tls *s);
int init_client(int *sock, const char *host, const char *port,
                const char *bindhost, const char *bindport,
                int family, int type, int protocol);
int should_retry(int i);

long bio_dump_callback(BIO *bio, int cmd, const char *argp,
                       int argi, long argl, long ret);

void apps_tls_info_callback(const tls *s, int where, int ret);
void msg_cb(int write_p, int version, int content_type, const void *buf,
            size_t len, tls *tls, void *arg);
void tlsext_cb(tls *s, int client_server, int type, const unsigned char *data,
               int len, void *arg);

int generate_cookie_callback(tls *tls, unsigned char *cookie,
                             unsigned int *cookie_len);
int verify_cookie_callback(tls *tls, const unsigned char *cookie,
                           unsigned int cookie_len);

#ifdef __VMS                     /* 31 char symbol name limit */
# define generate_stateless_cookie_callback      generate_stateless_cookie_cb
# define verify_stateless_cookie_callback        verify_stateless_cookie_cb
#endif

int generate_stateless_cookie_callback(tls *tls, unsigned char *cookie,
                                       size_t *cookie_len);
int verify_stateless_cookie_callback(tls *tls, const unsigned char *cookie,
                                     size_t cookie_len);

typedef struct tls_excert_st tls_EXCERT;

void tls_ctx_set_excert(tls_CTX *ctx, tls_EXCERT *exc);
void tls_excert_free(tls_EXCERT *exc);
int args_excert(int option, tls_EXCERT **pexc);
int load_excert(tls_EXCERT **pexc);
void print_verify_detail(tls *s, BIO *bio);
void print_tls_summary(tls *s);
int config_ctx(tls_CONF_CTX *cctx, STACK_OF(OPENtls_STRING) *str, tls_CTX *ctx);
int tls_ctx_add_crls(tls_CTX *ctx, STACK_OF(X509_CRL) *crls,
                     int crl_download);
int tls_load_stores(tls_CTX *ctx, const char *vfyCApath,
                    const char *vfyCAfile, const char *vfyCAstore,
                    const char *chCApath, const char *chCAfile,
                    const char *chCAstore, STACK_OF(X509_CRL) *crls,
                    int crl_download);
void tls_ctx_security_debug(tls_CTX *ctx, int verbose);
int set_keylog_file(tls_CTX *ctx, const char *keylog_file);
void print_ca_names(BIO *bio, tls *s);
