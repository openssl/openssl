/*
 * ! \file ssl/ssl_cert.c
 */
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
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <stdio.h>

#include "e_os.h"
#ifndef NO_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "internal/o_dir.h"
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#include <openssl/bn.h>
#include "ssl_locl.h"

static int ssl_security_default_callback(SSL *s, SSL_CTX *ctx, int op,
                                         int bits, int nid, void *other,
                                         void *ex);

int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    static volatile int ssl_x509_store_ctx_idx = -1;
    int got_write_lock = 0;

    CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);

    if (ssl_x509_store_ctx_idx < 0) {
        CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
        CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
        got_write_lock = 1;

        if (ssl_x509_store_ctx_idx < 0) {
            ssl_x509_store_ctx_idx =
                X509_STORE_CTX_get_ex_new_index(0, "SSL for verify callback",
                                                NULL, NULL, NULL);
        }
    }

    if (got_write_lock)
        CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
    else
        CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);

    return ssl_x509_store_ctx_idx;
}

CERT *ssl_cert_new(void)
{
    CERT *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        SSLerr(SSL_F_SSL_CERT_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    ret->key = &(ret->pkeys[SSL_PKEY_RSA_ENC]);
    ret->references = 1;
    ret->sec_cb = ssl_security_default_callback;
    ret->sec_level = OPENSSL_TLS_SECURITY_LEVEL;
    ret->sec_ex = NULL;
    return (ret);
}

CERT *ssl_cert_dup(CERT *cert)
{
    CERT *ret = OPENSSL_zalloc(sizeof(*ret));
    int i;

    if (ret == NULL) {
        SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    ret->references = 1;
    ret->key = &ret->pkeys[cert->key - cert->pkeys];

#ifndef OPENSSL_NO_RSA
    if (cert->rsa_tmp != NULL) {
        RSA_up_ref(cert->rsa_tmp);
        ret->rsa_tmp = cert->rsa_tmp;
    }
    ret->rsa_tmp_cb = cert->rsa_tmp_cb;
#endif

#ifndef OPENSSL_NO_DH
    if (cert->dh_tmp != NULL) {
        ret->dh_tmp = DHparams_dup(cert->dh_tmp);
        if (ret->dh_tmp == NULL) {
            SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_DH_LIB);
            goto err;
        }
        if (cert->dh_tmp->priv_key) {
            BIGNUM *b = BN_dup(cert->dh_tmp->priv_key);
            if (!b) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_BN_LIB);
                goto err;
            }
            ret->dh_tmp->priv_key = b;
        }
        if (cert->dh_tmp->pub_key) {
            BIGNUM *b = BN_dup(cert->dh_tmp->pub_key);
            if (!b) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_BN_LIB);
                goto err;
            }
            ret->dh_tmp->pub_key = b;
        }
    }
    ret->dh_tmp_cb = cert->dh_tmp_cb;
    ret->dh_tmp_auto = cert->dh_tmp_auto;
#endif

#ifndef OPENSSL_NO_EC
    if (cert->ecdh_tmp) {
        ret->ecdh_tmp = EC_KEY_dup(cert->ecdh_tmp);
        if (ret->ecdh_tmp == NULL) {
            SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_EC_LIB);
            goto err;
        }
    }
    ret->ecdh_tmp_cb = cert->ecdh_tmp_cb;
    ret->ecdh_tmp_auto = cert->ecdh_tmp_auto;
#endif

    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = cert->pkeys + i;
        CERT_PKEY *rpk = ret->pkeys + i;
        if (cpk->x509 != NULL) {
            rpk->x509 = cpk->x509;
            X509_up_ref(rpk->x509);
        }

        if (cpk->privatekey != NULL) {
            rpk->privatekey = cpk->privatekey;
            CRYPTO_add(&cpk->privatekey->references, 1, CRYPTO_LOCK_EVP_PKEY);
        }

        if (cpk->chain) {
            rpk->chain = X509_chain_up_ref(cpk->chain);
            if (!rpk->chain) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if (cert->pkeys[i].serverinfo != NULL) {
            /* Just copy everything. */
            ret->pkeys[i].serverinfo =
                OPENSSL_malloc(cert->pkeys[i].serverinfo_length);
            if (ret->pkeys[i].serverinfo == NULL) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            ret->pkeys[i].serverinfo_length =
                cert->pkeys[i].serverinfo_length;
            memcpy(ret->pkeys[i].serverinfo,
                   cert->pkeys[i].serverinfo,
                   cert->pkeys[i].serverinfo_length);
        }
    }

    /* Configured sigalgs copied across */
    if (cert->conf_sigalgs) {
        ret->conf_sigalgs = OPENSSL_malloc(cert->conf_sigalgslen);
        if (ret->conf_sigalgs == NULL)
            goto err;
        memcpy(ret->conf_sigalgs, cert->conf_sigalgs, cert->conf_sigalgslen);
        ret->conf_sigalgslen = cert->conf_sigalgslen;
    } else
        ret->conf_sigalgs = NULL;

    if (cert->client_sigalgs) {
        ret->client_sigalgs = OPENSSL_malloc(cert->client_sigalgslen);
        if (ret->client_sigalgs == NULL)
            goto err;
        memcpy(ret->client_sigalgs, cert->client_sigalgs,
               cert->client_sigalgslen);
        ret->client_sigalgslen = cert->client_sigalgslen;
    } else
        ret->client_sigalgs = NULL;
    /* Shared sigalgs also NULL */
    ret->shared_sigalgs = NULL;
    /* Copy any custom client certificate types */
    if (cert->ctypes) {
        ret->ctypes = OPENSSL_malloc(cert->ctype_num);
        if (ret->ctypes == NULL)
            goto err;
        memcpy(ret->ctypes, cert->ctypes, cert->ctype_num);
        ret->ctype_num = cert->ctype_num;
    }

    ret->cert_flags = cert->cert_flags;

    ret->cert_cb = cert->cert_cb;
    ret->cert_cb_arg = cert->cert_cb_arg;

    if (cert->verify_store) {
        CRYPTO_add(&cert->verify_store->references, 1,
                   CRYPTO_LOCK_X509_STORE);
        ret->verify_store = cert->verify_store;
    }

    if (cert->chain_store) {
        CRYPTO_add(&cert->chain_store->references, 1, CRYPTO_LOCK_X509_STORE);
        ret->chain_store = cert->chain_store;
    }

    ret->sec_cb = cert->sec_cb;
    ret->sec_level = cert->sec_level;
    ret->sec_ex = cert->sec_ex;

    if (!custom_exts_copy(&ret->cli_ext, &cert->cli_ext))
        goto err;
    if (!custom_exts_copy(&ret->srv_ext, &cert->srv_ext))
        goto err;
#ifndef OPENSSL_NO_PSK
    if (cert->psk_identity_hint) {
        ret->psk_identity_hint = BUF_strdup(cert->psk_identity_hint);
        if (ret->psk_identity_hint == NULL)
            goto err;
    }
#endif
    return (ret);

 err:
    ssl_cert_free(ret);

    return NULL;
}

/* Free up and clear all certificates and chains */

void ssl_cert_clear_certs(CERT *c)
{
    int i;
    if (c == NULL)
        return;
    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        X509_free(cpk->x509);
        cpk->x509 = NULL;
        EVP_PKEY_free(cpk->privatekey);
        cpk->privatekey = NULL;
        sk_X509_pop_free(cpk->chain, X509_free);
        cpk->chain = NULL;
        OPENSSL_free(cpk->serverinfo);
        cpk->serverinfo = NULL;
        cpk->serverinfo_length = 0;
    }
}

void ssl_cert_free(CERT *c)
{
    int i;

    if (c == NULL)
        return;

    i = CRYPTO_add(&c->references, -1, CRYPTO_LOCK_SSL_CERT);
#ifdef REF_PRINT
    REF_PRINT("CERT", c);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "ssl_cert_free, bad reference count\n");
        abort();                /* ok */
    }
#endif

#ifndef OPENSSL_NO_RSA
    RSA_free(c->rsa_tmp);
#endif
#ifndef OPENSSL_NO_DH
    DH_free(c->dh_tmp);
#endif
#ifndef OPENSSL_NO_EC
    EC_KEY_free(c->ecdh_tmp);
#endif

    ssl_cert_clear_certs(c);
    OPENSSL_free(c->conf_sigalgs);
    OPENSSL_free(c->client_sigalgs);
    OPENSSL_free(c->shared_sigalgs);
    OPENSSL_free(c->ctypes);
    X509_STORE_free(c->verify_store);
    X509_STORE_free(c->chain_store);
    custom_exts_free(&c->cli_ext);
    custom_exts_free(&c->srv_ext);
#ifndef OPENSSL_NO_PSK
    OPENSSL_free(c->psk_identity_hint);
#endif
    OPENSSL_free(c);
}

int ssl_cert_set0_chain(SSL *s, SSL_CTX *ctx, STACK_OF(X509) *chain)
{
    int i, r;
    CERT_PKEY *cpk = s ? s->cert->key : ctx->cert->key;
    if (!cpk)
        return 0;
    sk_X509_pop_free(cpk->chain, X509_free);
    for (i = 0; i < sk_X509_num(chain); i++) {
        r = ssl_security_cert(s, ctx, sk_X509_value(chain, i), 0, 0);
        if (r != 1) {
            SSLerr(SSL_F_SSL_CERT_SET0_CHAIN, r);
            return 0;
        }
    }
    cpk->chain = chain;
    return 1;
}

int ssl_cert_set1_chain(SSL *s, SSL_CTX *ctx, STACK_OF(X509) *chain)
{
    STACK_OF(X509) *dchain;
    if (!chain)
        return ssl_cert_set0_chain(s, ctx, NULL);
    dchain = X509_chain_up_ref(chain);
    if (!dchain)
        return 0;
    if (!ssl_cert_set0_chain(s, ctx, dchain)) {
        sk_X509_pop_free(dchain, X509_free);
        return 0;
    }
    return 1;
}

int ssl_cert_add0_chain_cert(SSL *s, SSL_CTX *ctx, X509 *x)
{
    int r;
    CERT_PKEY *cpk = s ? s->cert->key : ctx->cert->key;
    if (!cpk)
        return 0;
    r = ssl_security_cert(s, ctx, x, 0, 0);
    if (r != 1) {
        SSLerr(SSL_F_SSL_CERT_ADD0_CHAIN_CERT, r);
        return 0;
    }
    if (!cpk->chain)
        cpk->chain = sk_X509_new_null();
    if (!cpk->chain || !sk_X509_push(cpk->chain, x))
        return 0;
    return 1;
}

int ssl_cert_add1_chain_cert(SSL *s, SSL_CTX *ctx, X509 *x)
{
    if (!ssl_cert_add0_chain_cert(s, ctx, x))
        return 0;
    X509_up_ref(x);
    return 1;
}

int ssl_cert_select_current(CERT *c, X509 *x)
{
    int i;
    if (x == NULL)
        return 0;
    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->x509 == x && cpk->privatekey) {
            c->key = cpk;
            return 1;
        }
    }

    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->privatekey && cpk->x509 && !X509_cmp(cpk->x509, x)) {
            c->key = cpk;
            return 1;
        }
    }
    return 0;
}

int ssl_cert_set_current(CERT *c, long op)
{
    int i, idx;
    if (!c)
        return 0;
    if (op == SSL_CERT_SET_FIRST)
        idx = 0;
    else if (op == SSL_CERT_SET_NEXT) {
        idx = (int)(c->key - c->pkeys + 1);
        if (idx >= SSL_PKEY_NUM)
            return 0;
    } else
        return 0;
    for (i = idx; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->x509 && cpk->privatekey) {
            c->key = cpk;
            return 1;
        }
    }
    return 0;
}

void ssl_cert_set_cert_cb(CERT *c, int (*cb) (SSL *ssl, void *arg), void *arg)
{
    c->cert_cb = cb;
    c->cert_cb_arg = arg;
}

int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk)
{
    X509 *x;
    int i;
    X509_STORE *verify_store;
    X509_STORE_CTX ctx;

    if (s->cert->verify_store)
        verify_store = s->cert->verify_store;
    else
        verify_store = s->ctx->cert_store;

    if ((sk == NULL) || (sk_X509_num(sk) == 0))
        return (0);

    x = sk_X509_value(sk, 0);
    if (!X509_STORE_CTX_init(&ctx, verify_store, x, sk)) {
        SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, ERR_R_X509_LIB);
        return (0);
    }
    /* Set suite B flags if needed */
    X509_STORE_CTX_set_flags(&ctx, tls1_suiteb(s));
    X509_STORE_CTX_set_ex_data(&ctx, SSL_get_ex_data_X509_STORE_CTX_idx(), s);

    /*
     * We need to inherit the verify parameters. These can be determined by
     * the context: if its a server it will verify SSL client certificates or
     * vice versa.
     */

    X509_STORE_CTX_set_default(&ctx, s->server ? "ssl_client" : "ssl_server");
    /*
     * Anything non-default in "param" should overwrite anything in the ctx.
     */
    X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(&ctx), s->param);

    if (s->verify_callback)
        X509_STORE_CTX_set_verify_cb(&ctx, s->verify_callback);

    if (s->ctx->app_verify_callback != NULL)
        i = s->ctx->app_verify_callback(&ctx, s->ctx->app_verify_arg);
    else {
        i = X509_verify_cert(&ctx);
# if 0
        /* Dummy error calls so mkerr generates them */
        SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, SSL_R_EE_KEY_TOO_SMALL);
        SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, SSL_R_CA_KEY_TOO_SMALL);
        SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, SSL_R_CA_MD_TOO_WEAK);
# endif
        if (i > 0)
            i = ssl_security_cert_chain(s, ctx.chain, NULL, 1);
    }

    s->verify_result = ctx.error;
    X509_STORE_CTX_cleanup(&ctx);

    return (i);
}

static void set_client_CA_list(STACK_OF(X509_NAME) **ca_list,
                               STACK_OF(X509_NAME) *name_list)
{
    sk_X509_NAME_pop_free(*ca_list, X509_NAME_free);
    *ca_list = name_list;
}

STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk)
{
    int i;
    STACK_OF(X509_NAME) *ret;
    X509_NAME *name;

    ret = sk_X509_NAME_new_null();
    for (i = 0; i < sk_X509_NAME_num(sk); i++) {
        name = X509_NAME_dup(sk_X509_NAME_value(sk, i));
        if ((name == NULL) || !sk_X509_NAME_push(ret, name)) {
            sk_X509_NAME_pop_free(ret, X509_NAME_free);
            return (NULL);
        }
    }
    return (ret);
}

void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)
{
    set_client_CA_list(&(s->client_CA), name_list);
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)
{
    set_client_CA_list(&(ctx->client_CA), name_list);
}

STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)
{
    return (ctx->client_CA);
}

STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s)
{
    if (!s->server) { /* we are in the client */
        if (((s->version >> 8) == SSL3_VERSION_MAJOR) && (s->s3 != NULL))
            return (s->s3->tmp.ca_names);
        else
            return (NULL);
    } else {
        if (s->client_CA != NULL)
            return (s->client_CA);
        else
            return (s->ctx->client_CA);
    }
}

static int add_client_CA(STACK_OF(X509_NAME) **sk, X509 *x)
{
    X509_NAME *name;

    if (x == NULL)
        return (0);
    if ((*sk == NULL) && ((*sk = sk_X509_NAME_new_null()) == NULL))
        return (0);

    if ((name = X509_NAME_dup(X509_get_subject_name(x))) == NULL)
        return (0);

    if (!sk_X509_NAME_push(*sk, name)) {
        X509_NAME_free(name);
        return (0);
    }
    return (1);
}

int SSL_add_client_CA(SSL *ssl, X509 *x)
{
    return (add_client_CA(&(ssl->client_CA), x));
}

int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)
{
    return (add_client_CA(&(ctx->client_CA), x));
}

static int xname_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}

/**
 * Load CA certs from a file into a ::STACK. Note that it is somewhat misnamed;
 * it doesn't really have anything to do with clients (except that a common use
 * for a stack of CAs is to send it to the client). Actually, it doesn't have
 * much to do with CAs, either, since it will load any old cert.
 * \param file the file containing one or more certs.
 * \return a ::STACK containing the certs.
 */
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)
{
    BIO *in;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    STACK_OF(X509_NAME) *ret = NULL, *sk;

    sk = sk_X509_NAME_new(xname_cmp);

    in = BIO_new(BIO_s_file());

    if ((sk == NULL) || (in == NULL)) {
        SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!BIO_read_filename(in, file))
        goto err;

    for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        if (ret == NULL) {
            ret = sk_X509_NAME_new_null();
            if (ret == NULL) {
                SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if ((xn = X509_get_subject_name(x)) == NULL)
            goto err;
        /* check for duplicates */
        xn = X509_NAME_dup(xn);
        if (xn == NULL)
            goto err;
        if (sk_X509_NAME_find(sk, xn) >= 0)
            X509_NAME_free(xn);
        else {
            sk_X509_NAME_push(sk, xn);
            sk_X509_NAME_push(ret, xn);
        }
    }
    goto done;

 err:
    sk_X509_NAME_pop_free(ret, X509_NAME_free);
    ret = NULL;
 done:
    sk_X509_NAME_free(sk);
    BIO_free(in);
    X509_free(x);
    if (ret != NULL)
        ERR_clear_error();
    return (ret);
}

/**
 * Add a file of certs to a stack.
 * \param stack the stack to add to.
 * \param file the file to add from. All certs in this file that are not
 * already in the stack will be added.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 * certs may have been added to \c stack.
 */

int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                        const char *file)
{
    BIO *in;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    int ret = 1;
    int (*oldcmp) (const X509_NAME *const *a, const X509_NAME *const *b);

    oldcmp = sk_X509_NAME_set_cmp_func(stack, xname_cmp);

    in = BIO_new(BIO_s_file());

    if (in == NULL) {
        SSLerr(SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK,
               ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!BIO_read_filename(in, file))
        goto err;

    for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        if ((xn = X509_get_subject_name(x)) == NULL)
            goto err;
        xn = X509_NAME_dup(xn);
        if (xn == NULL)
            goto err;
        if (sk_X509_NAME_find(stack, xn) >= 0)
            X509_NAME_free(xn);
        else
            sk_X509_NAME_push(stack, xn);
    }

    ERR_clear_error();
    goto done;

 err:
        ret = 0;
 done:
    BIO_free(in);
    X509_free(x);
    (void)sk_X509_NAME_set_cmp_func(stack, oldcmp);
    return ret;
}

/**
 * Add a directory of certs to a stack.
 * \param stack the stack to append to.
 * \param dir the directory to append from. All files in this directory will be
 * examined as potential certs. Any that are acceptable to
 * SSL_add_dir_cert_subjects_to_stack() that are not already in the stack will be
 * included.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 * certs may have been added to \c stack.
 */

int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                       const char *dir)
{
    OPENSSL_DIR_CTX *d = NULL;
    const char *filename;
    int ret = 0;

    CRYPTO_w_lock(CRYPTO_LOCK_READDIR);

    /* Note that a side effect is that the CAs will be sorted by name */

    while ((filename = OPENSSL_DIR_read(&d, dir))) {
        char buf[1024];
        int r;

        if (strlen(dir) + strlen(filename) + 2 > sizeof buf) {
            SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK,
                   SSL_R_PATH_TOO_LONG);
            goto err;
        }
#ifdef OPENSSL_SYS_VMS
        r = BIO_snprintf(buf, sizeof buf, "%s%s", dir, filename);
#else
        r = BIO_snprintf(buf, sizeof buf, "%s/%s", dir, filename);
#endif
        if (r <= 0 || r >= (int)sizeof(buf))
            goto err;
        if (!SSL_add_file_cert_subjects_to_stack(stack, buf))
            goto err;
    }

    if (errno) {
        SYSerr(SYS_F_OPENDIR, get_last_sys_error());
        ERR_add_error_data(3, "OPENSSL_DIR_read(&ctx, '", dir, "')");
        SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK, ERR_R_SYS_LIB);
        goto err;
    }

    ret = 1;

 err:
    if (d)
        OPENSSL_DIR_end(&d);
    CRYPTO_w_unlock(CRYPTO_LOCK_READDIR);
    return ret;
}

/* Add a certificate to a BUF_MEM structure */

static int ssl_add_cert_to_buf(BUF_MEM *buf, unsigned long *l, X509 *x)
{
    int n;
    unsigned char *p;

    n = i2d_X509(x, NULL);
    if (!BUF_MEM_grow_clean(buf, (int)(n + (*l) + 3))) {
        SSLerr(SSL_F_SSL_ADD_CERT_TO_BUF, ERR_R_BUF_LIB);
        return 0;
    }
    p = (unsigned char *)&(buf->data[*l]);
    l2n3(n, p);
    i2d_X509(x, &p);
    *l += n + 3;

    return 1;
}

/* Add certificate chain to internal SSL BUF_MEM strcuture */
int ssl_add_cert_chain(SSL *s, CERT_PKEY *cpk, unsigned long *l)
{
    BUF_MEM *buf = s->init_buf;
    int i;

    X509 *x;
    STACK_OF(X509) *extra_certs;
    X509_STORE *chain_store;

    /* TLSv1 sends a chain with nothing in it, instead of an alert */
    if (!BUF_MEM_grow_clean(buf, 10)) {
        SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, ERR_R_BUF_LIB);
        return 0;
    }

    if (!cpk || !cpk->x509)
        return 1;

    x = cpk->x509;

    /*
     * If we have a certificate specific chain use it, else use parent ctx.
     */
    if (cpk->chain)
        extra_certs = cpk->chain;
    else
        extra_certs = s->ctx->extra_certs;

    if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || extra_certs)
        chain_store = NULL;
    else if (s->cert->chain_store)
        chain_store = s->cert->chain_store;
    else
        chain_store = s->ctx->cert_store;

    if (chain_store) {
        X509_STORE_CTX xs_ctx;

        if (!X509_STORE_CTX_init(&xs_ctx, chain_store, x, NULL)) {
            SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, ERR_R_X509_LIB);
            return (0);
        }
        /*
         * It is valid for the chain not to be complete (because normally we
         * don't include the root cert in the chain). Therefore we deliberately
         * ignore the error return from this call. We're not actually verifying
         * the cert - we're just building as much of the chain as we can
         */
        X509_verify_cert(&xs_ctx);
        /* Don't leave errors in the queue */
        ERR_clear_error();
        i = ssl_security_cert_chain(s, xs_ctx.chain, NULL, 0);
        if (i != 1) {
            X509_STORE_CTX_cleanup(&xs_ctx);
            SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, i);
            return 0;
        }
        for (i = 0; i < sk_X509_num(xs_ctx.chain); i++) {
            x = sk_X509_value(xs_ctx.chain, i);

            if (!ssl_add_cert_to_buf(buf, l, x)) {
                X509_STORE_CTX_cleanup(&xs_ctx);
                return 0;
            }
        }
        X509_STORE_CTX_cleanup(&xs_ctx);
    } else {
        i = ssl_security_cert_chain(s, extra_certs, x, 0);
        if (i != 1) {
            SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, i);
            return 0;
        }
        if (!ssl_add_cert_to_buf(buf, l, x))
            return 0;
        for (i = 0; i < sk_X509_num(extra_certs); i++) {
            x = sk_X509_value(extra_certs, i);
            if (!ssl_add_cert_to_buf(buf, l, x))
                return 0;
        }
    }
    return 1;
}

/* Build a certificate chain for current certificate */
int ssl_build_cert_chain(SSL *s, SSL_CTX *ctx, int flags)
{
    CERT *c = s ? s->cert : ctx->cert;
    CERT_PKEY *cpk = c->key;
    X509_STORE *chain_store = NULL;
    X509_STORE_CTX xs_ctx;
    STACK_OF(X509) *chain = NULL, *untrusted = NULL;
    X509 *x;
    int i, rv = 0;
    unsigned long error;

    if (!cpk->x509) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, SSL_R_NO_CERTIFICATE_SET);
        goto err;
    }
    /* Rearranging and check the chain: add everything to a store */
    if (flags & SSL_BUILD_CHAIN_FLAG_CHECK) {
        chain_store = X509_STORE_new();
        if (chain_store == NULL)
            goto err;
        for (i = 0; i < sk_X509_num(cpk->chain); i++) {
            x = sk_X509_value(cpk->chain, i);
            if (!X509_STORE_add_cert(chain_store, x)) {
                error = ERR_peek_last_error();
                if (ERR_GET_LIB(error) != ERR_LIB_X509 ||
                    ERR_GET_REASON(error) !=
                    X509_R_CERT_ALREADY_IN_HASH_TABLE)
                    goto err;
                ERR_clear_error();
            }
        }
        /* Add EE cert too: it might be self signed */
        if (!X509_STORE_add_cert(chain_store, cpk->x509)) {
            error = ERR_peek_last_error();
            if (ERR_GET_LIB(error) != ERR_LIB_X509 ||
                ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
                goto err;
            ERR_clear_error();
        }
    } else {
        if (c->chain_store)
            chain_store = c->chain_store;
        else if (s)
            chain_store = s->ctx->cert_store;
        else
            chain_store = ctx->cert_store;

        if (flags & SSL_BUILD_CHAIN_FLAG_UNTRUSTED)
            untrusted = cpk->chain;
    }

    if (!X509_STORE_CTX_init(&xs_ctx, chain_store, cpk->x509, untrusted)) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, ERR_R_X509_LIB);
        goto err;
    }
    /* Set suite B flags if needed */
    X509_STORE_CTX_set_flags(&xs_ctx,
                             c->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS);

    i = X509_verify_cert(&xs_ctx);
    if (i <= 0 && flags & SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR) {
        if (flags & SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR)
            ERR_clear_error();
        i = 1;
        rv = 2;
    }
    if (i > 0)
        chain = X509_STORE_CTX_get1_chain(&xs_ctx);
    if (i <= 0) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, SSL_R_CERTIFICATE_VERIFY_FAILED);
        i = X509_STORE_CTX_get_error(&xs_ctx);
        ERR_add_error_data(2, "Verify error:",
                           X509_verify_cert_error_string(i));

        X509_STORE_CTX_cleanup(&xs_ctx);
        goto err;
    }
    X509_STORE_CTX_cleanup(&xs_ctx);
    /* Remove EE certificate from chain */
    x = sk_X509_shift(chain);
    X509_free(x);
    if (flags & SSL_BUILD_CHAIN_FLAG_NO_ROOT) {
        if (sk_X509_num(chain) > 0) {
            /* See if last cert is self signed */
            x = sk_X509_value(chain, sk_X509_num(chain) - 1);
            if (X509_get_extension_flags(x) & EXFLAG_SS) {
                x = sk_X509_pop(chain);
                X509_free(x);
            }
        }
    }
    /*
     * Check security level of all CA certificates: EE will have been checked
     * already.
     */
    for (i = 0; i < sk_X509_num(chain); i++) {
        x = sk_X509_value(chain, i);
        rv = ssl_security_cert(s, ctx, x, 0, 0);
        if (rv != 1) {
            SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, rv);
            sk_X509_pop_free(chain, X509_free);
            rv = 0;
            goto err;
        }
    }
    sk_X509_pop_free(cpk->chain, X509_free);
    cpk->chain = chain;
    if (rv == 0)
        rv = 1;
 err:
    if (flags & SSL_BUILD_CHAIN_FLAG_CHECK)
        X509_STORE_free(chain_store);

    return rv;
}

int ssl_cert_set_cert_store(CERT *c, X509_STORE *store, int chain, int ref)
{
    X509_STORE **pstore;
    if (chain)
        pstore = &c->chain_store;
    else
        pstore = &c->verify_store;
    X509_STORE_free(*pstore);
    *pstore = store;
    if (ref && store)
        CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);
    return 1;
}

static int ssl_security_default_callback(SSL *s, SSL_CTX *ctx, int op,
                                         int bits, int nid, void *other,
                                         void *ex)
{
    int level, minbits;
    static const int minbits_table[5] = { 80, 112, 128, 192, 256 };
    if (ctx)
        level = SSL_CTX_get_security_level(ctx);
    else
        level = SSL_get_security_level(s);
    /* Level 0: anything goes */
    if (level <= 0)
        return 1;
    if (level > 5)
        level = 5;
    minbits = minbits_table[level - 1];
    switch (op) {
    case SSL_SECOP_CIPHER_SUPPORTED:
    case SSL_SECOP_CIPHER_SHARED:
    case SSL_SECOP_CIPHER_CHECK:
        {
            const SSL_CIPHER *c = other;
            /* No ciphers below security level */
            if (bits < minbits)
                return 0;
            /* No unauthenticated ciphersuites */
            if (c->algorithm_auth & SSL_aNULL)
                return 0;
            /* No MD5 mac ciphersuites */
            if (c->algorithm_mac & SSL_MD5)
                return 0;
            /* SHA1 HMAC is 160 bits of security */
            if (minbits > 160 && c->algorithm_mac & SSL_SHA1)
                return 0;
            /* Level 2: no RC4 */
            if (level >= 2 && c->algorithm_enc == SSL_RC4)
                return 0;
            /* Level 3: forward secure ciphersuites only */
            if (level >= 3 && !(c->algorithm_mkey & (SSL_kEDH | SSL_kEECDH)))
                return 0;
            break;
        }
    case SSL_SECOP_VERSION:
        /* SSLv3 not allowed on level 2 */
        if (nid <= SSL3_VERSION && level >= 2)
            return 0;
        /* TLS v1.1 and above only for level 3 */
        if (nid <= TLS1_VERSION && level >= 3)
            return 0;
        /* TLS v1.2 only for level 4 and above */
        if (nid <= TLS1_1_VERSION && level >= 4)
            return 0;
        break;

    case SSL_SECOP_COMPRESSION:
        if (level >= 2)
            return 0;
        break;
    case SSL_SECOP_TICKET:
        if (level >= 3)
            return 0;
        break;
    default:
        if (bits < minbits)
            return 0;
    }
    return 1;
}

int ssl_security(SSL *s, int op, int bits, int nid, void *other)
{
    return s->cert->sec_cb(s, NULL, op, bits, nid, other, s->cert->sec_ex);
}

int ssl_ctx_security(SSL_CTX *ctx, int op, int bits, int nid, void *other)
{
    return ctx->cert->sec_cb(NULL, ctx, op, bits, nid, other,
                             ctx->cert->sec_ex);
}
