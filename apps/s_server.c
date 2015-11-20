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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/async.h>

#include <openssl/e_os2.h>

/* conflicts with winsock2 stuff on netware */
#if !defined(OPENSSL_SYS_NETWARE)
# include <sys/types.h>
#endif

/*
 * With IPv6, it looks like Digital has mixed up the proper order of
 * recursive header file inclusion, resulting in the compiler complaining
 * that u_int isn't defined, but only if _POSIX_C_SOURCE is defined, which is
 * needed to have fileno() declared correctly...  So let's define u_int
 */
#if defined(OPENSSL_SYS_VMS_DECC) && !defined(__U_INT)
# define __U_INT
typedef unsigned int u_int;
#endif

#include <openssl/lhash.h>
#include <openssl/bn.h>
#define USE_SOCKETS
#include "apps.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_SRP
# include <openssl/srp.h>
#endif
#include "s_apps.h"
#include "timeouts.h"

#if (defined(OPENSSL_SYS_VMS) && __VMS_VER < 70000000)
/* FIONBIO used as a switch to enable ioctl, and that isn't in VMS < 7.0 */
# undef FIONBIO
#endif

#ifndef OPENSSL_NO_RSA
static RSA *tmp_rsa_cb(SSL *s, int is_export, int keylength);
#endif
static int not_resumable_sess_cb(SSL *s, int is_forward_secure);
static int sv_body(char *hostname, int s, int stype, unsigned char *context);
static int www_body(char *hostname, int s, int stype, unsigned char *context);
static int rev_body(char *hostname, int s, int stype, unsigned char *context);
static void close_accept_socket(void);
static int init_ssl_connection(SSL *s);
static void print_stats(BIO *bp, SSL_CTX *ctx);
static int generate_session_id(const SSL *ssl, unsigned char *id,
                               unsigned int *id_len);
static void init_session_cache_ctx(SSL_CTX *sctx);
static void free_sessions(void);
#ifndef OPENSSL_NO_DH
static DH *load_dh_param(const char *dhfile);
#endif

static void s_server_init(void);

/* static int load_CA(SSL_CTX *ctx, char *file);*/

#undef BUFSIZZ
#define BUFSIZZ 16*1024
static int bufsize = BUFSIZZ;
static int accept_socket = -1;

#define TEST_CERT       "server.pem"
#define TEST_CERT2      "server2.pem"

extern int verify_depth, verify_return_error, verify_quiet;

static int s_server_verify = SSL_VERIFY_NONE;
static int s_server_session_id_context = 1; /* anything will do */
static const char *s_cert_file = TEST_CERT, *s_key_file =
    NULL, *s_chain_file = NULL;

static const char *s_cert_file2 = TEST_CERT2, *s_key_file2 = NULL;
static char *s_dcert_file = NULL, *s_dkey_file = NULL, *s_dchain_file = NULL;
#ifdef FIONBIO
static int s_nbio = 0;
#endif
static int s_nbio_test = 0;
static int s_crlf = 0;
static SSL_CTX *ctx = NULL;
static SSL_CTX *ctx2 = NULL;
static int www = 0;

static BIO *bio_s_out = NULL;
static BIO *bio_s_msg = NULL;
static int s_debug = 0;
static int s_tlsextdebug = 0;
static int s_tlsextstatus = 0;
static int cert_status_cb(SSL *s, void *arg);
static int no_resume_ephemeral = 0;
static int s_msg = 0;
static int s_quiet = 0;
static int s_ign_eof = 0;
static int s_brief = 0;

static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;

static int async = 0;

#ifndef OPENSSL_NO_ENGINE
static char *engine_id = NULL;
#endif
static const char *session_id_prefix = NULL;

static int enable_timeouts = 0;
static long socket_mtu;
#ifndef OPENSSL_NO_DTLS1
static int cert_chain = 0;
#endif
static int dtlslisten = 0;

static BIO *serverinfo_in = NULL;
static const char *s_serverinfo_file = NULL;

#ifndef OPENSSL_NO_PSK
static char *psk_identity = "Client_identity";
char *psk_key = NULL;           /* by default PSK is not used */

static unsigned int psk_server_cb(SSL *ssl, const char *identity,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    unsigned int psk_len = 0;
    int ret;
    BIGNUM *bn = NULL;

    if (s_debug)
        BIO_printf(bio_s_out, "psk_server_cb\n");
    if (!identity) {
        BIO_printf(bio_err, "Error: client did not send PSK identity\n");
        goto out_err;
    }
    if (s_debug)
        BIO_printf(bio_s_out, "identity_len=%d identity=%s\n",
                   (int)strlen(identity), identity);

    /* here we could lookup the given identity e.g. from a database */
    if (strcmp(identity, psk_identity) != 0) {
        BIO_printf(bio_s_out, "PSK error: client identity not found"
                   " (got '%s' expected '%s')\n", identity, psk_identity);
        goto out_err;
    }
    if (s_debug)
        BIO_printf(bio_s_out, "PSK client identity found\n");

    /* convert the PSK key to binary */
    ret = BN_hex2bn(&bn, psk_key);
    if (!ret) {
        BIO_printf(bio_err, "Could not convert PSK key '%s' to BIGNUM\n",
                   psk_key);
        BN_free(bn);
        return 0;
    }
    if (BN_num_bytes(bn) > (int)max_psk_len) {
        BIO_printf(bio_err,
                   "psk buffer of callback is too small (%d) for key (%d)\n",
                   max_psk_len, BN_num_bytes(bn));
        BN_free(bn);
        return 0;
    }

    ret = BN_bn2bin(bn, psk);
    BN_free(bn);

    if (ret < 0)
        goto out_err;
    psk_len = (unsigned int)ret;

    if (s_debug)
        BIO_printf(bio_s_out, "fetched PSK len=%d\n", psk_len);
    return psk_len;
 out_err:
    if (s_debug)
        BIO_printf(bio_err, "Error in PSK server callback\n");
    (void)BIO_flush(bio_err);
    (void)BIO_flush(bio_s_out);
    return 0;
}
#endif

#ifndef OPENSSL_NO_SRP
/* This is a context that we pass to callbacks */
typedef struct srpsrvparm_st {
    char *login;
    SRP_VBASE *vb;
    SRP_user_pwd *user;
} srpsrvparm;

/*
 * This callback pretends to require some asynchronous logic in order to
 * obtain a verifier. When the callback is called for a new connection we
 * return with a negative value. This will provoke the accept etc to return
 * with an LOOKUP_X509. The main logic of the reinvokes the suspended call
 * (which would normally occur after a worker has finished) and we set the
 * user parameters.
 */
static int ssl_srp_server_param_cb(SSL *s, int *ad, void *arg)
{
    srpsrvparm *p = (srpsrvparm *) arg;
    if (p->login == NULL && p->user == NULL) {
        p->login = SSL_get_srp_username(s);
        BIO_printf(bio_err, "SRP username = \"%s\"\n", p->login);
        return (-1);
    }

    if (p->user == NULL) {
        BIO_printf(bio_err, "User %s doesn't exist\n", p->login);
        return SSL3_AL_FATAL;
    }
    if (SSL_set_srp_server_param
        (s, p->user->N, p->user->g, p->user->s, p->user->v,
         p->user->info) < 0) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL3_AL_FATAL;
    }
    BIO_printf(bio_err,
               "SRP parameters set: username = \"%s\" info=\"%s\" \n",
               p->login, p->user->info);
    /* need to check whether there are memory leaks */
    p->user = NULL;
    p->login = NULL;
    return SSL_ERROR_NONE;
}

#endif

static void s_server_init(void)
{
    accept_socket = -1;
    verify_depth = 0;
    s_server_verify = SSL_VERIFY_NONE;
    s_dcert_file = NULL;
    s_dkey_file = NULL;
    s_dchain_file = NULL;
    s_cert_file = TEST_CERT;
    s_key_file = NULL;
    s_chain_file = NULL;
    s_cert_file2 = TEST_CERT2;
    s_key_file2 = NULL;
    ctx2 = NULL;
    s_nbio = 0;
    s_nbio_test = 0;
    ctx = NULL;
    www = 0;
    bio_s_out = NULL;
    s_debug = 0;
    s_msg = 0;
    s_quiet = 0;
    s_brief = 0;
    async = 0;
#ifndef OPENSSL_NO_ENGINE
    engine_id = NULL;
#endif
}

static int local_argc = 0;
static char **local_argv;

#ifdef CHARSET_EBCDIC
static int ebcdic_new(BIO *bi);
static int ebcdic_free(BIO *a);
static int ebcdic_read(BIO *b, char *out, int outl);
static int ebcdic_write(BIO *b, const char *in, int inl);
static long ebcdic_ctrl(BIO *b, int cmd, long num, void *ptr);
static int ebcdic_gets(BIO *bp, char *buf, int size);
static int ebcdic_puts(BIO *bp, const char *str);

# define BIO_TYPE_EBCDIC_FILTER  (18|0x0200)
static BIO_METHOD methods_ebcdic = {
    BIO_TYPE_EBCDIC_FILTER,
    "EBCDIC/ASCII filter",
    ebcdic_write,
    ebcdic_read,
    ebcdic_puts,
    ebcdic_gets,
    ebcdic_ctrl,
    ebcdic_new,
    ebcdic_free,
};

/* This struct is "unwarranted chumminess with the compiler." */
typedef struct {
    size_t alloced;
    char buff[1];
} EBCDIC_OUTBUFF;

BIO_METHOD *BIO_f_ebcdic_filter()
{
    return (&methods_ebcdic);
}

static int ebcdic_new(BIO *bi)
{
    EBCDIC_OUTBUFF *wbuf;

    wbuf = app_malloc(sizeof(*wbuf) + 1024, "ebcdic wbuf");
    wbuf->alloced = 1024;
    wbuf->buff[0] = '\0';

    bi->ptr = (char *)wbuf;
    bi->init = 1;
    bi->flags = 0;
    return (1);
}

static int ebcdic_free(BIO *a)
{
    if (a == NULL)
        return (0);
    OPENSSL_free(a->ptr);
    a->ptr = NULL;
    a->init = 0;
    a->flags = 0;
    return (1);
}

static int ebcdic_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out == NULL || outl == 0)
        return (0);
    if (b->next_bio == NULL)
        return (0);

    ret = BIO_read(b->next_bio, out, outl);
    if (ret > 0)
        ascii2ebcdic(out, out, ret);
    return (ret);
}

static int ebcdic_write(BIO *b, const char *in, int inl)
{
    EBCDIC_OUTBUFF *wbuf;
    int ret = 0;
    int num;
    unsigned char n;

    if ((in == NULL) || (inl <= 0))
        return (0);
    if (b->next_bio == NULL)
        return (0);

    wbuf = (EBCDIC_OUTBUFF *) b->ptr;

    if (inl > (num = wbuf->alloced)) {
        num = num + num;        /* double the size */
        if (num < inl)
            num = inl;
        wbuf = app_malloc(sizeof(*wbuf) + num, "grow ebcdic wbuf");
        OPENSSL_free(b->ptr);

        wbuf->alloced = num;
        wbuf->buff[0] = '\0';

        b->ptr = (char *)wbuf;
    }

    ebcdic2ascii(wbuf->buff, in, inl);

    ret = BIO_write(b->next_bio, wbuf->buff, inl);

    return (ret);
}

static long ebcdic_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret;

    if (b->next_bio == NULL)
        return (0);
    switch (cmd) {
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
}

static int ebcdic_gets(BIO *bp, char *buf, int size)
{
    int i, ret = 0;
    if (bp->next_bio == NULL)
        return (0);
/*      return(BIO_gets(bp->next_bio,buf,size));*/
    for (i = 0; i < size - 1; ++i) {
        ret = ebcdic_read(bp, &buf[i], 1);
        if (ret <= 0)
            break;
        else if (buf[i] == '\n') {
            ++i;
            break;
        }
    }
    if (i < size)
        buf[i] = '\0';
    return (ret < 0 && i == 0) ? ret : i;
}

static int ebcdic_puts(BIO *bp, const char *str)
{
    if (bp->next_bio == NULL)
        return (0);
    return ebcdic_write(bp, str, strlen(str));
}
#endif

/* This is a context that we pass to callbacks */
typedef struct tlsextctx_st {
    char *servername;
    BIO *biodebug;
    int extension_error;
} tlsextctx;

static int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    tlsextctx *p = (tlsextctx *) arg;
    const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (servername && p->biodebug)
        BIO_printf(p->biodebug, "Hostname in TLS extension: \"%s\"\n",
                   servername);

    if (!p->servername)
        return SSL_TLSEXT_ERR_NOACK;

    if (servername) {
        if (strcasecmp(servername, p->servername))
            return p->extension_error;
        if (ctx2) {
            BIO_printf(p->biodebug, "Switching server context.\n");
            SSL_set_SSL_CTX(s, ctx2);
        }
    }
    return SSL_TLSEXT_ERR_OK;
}

/* Structure passed to cert status callback */

typedef struct tlsextstatusctx_st {
    /* Default responder to use */
    char *host, *path, *port;
    int use_ssl;
    int timeout;
    int verbose;
} tlsextstatusctx;

static tlsextstatusctx tlscstatp = { NULL, NULL, NULL, 0, -1, 0 };

/*
 * Certificate Status callback. This is called when a client includes a
 * certificate status request extension. This is a simplified version. It
 * examines certificates each time and makes one OCSP responder query for
 * each request. A full version would store details such as the OCSP
 * certificate IDs and minimise the number of OCSP responses by caching them
 * until they were considered "expired".
 */

static int cert_status_cb(SSL *s, void *arg)
{
    tlsextstatusctx *srctx = arg;
    char *host = NULL, *port = NULL, *path = NULL;
    int use_ssl;
    unsigned char *rspder = NULL;
    int rspderlen;
    STACK_OF(OPENSSL_STRING) *aia = NULL;
    X509 *x = NULL;
    X509_STORE_CTX inctx;
    X509_OBJECT obj;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_CERTID *id = NULL;
    STACK_OF(X509_EXTENSION) *exts;
    int ret = SSL_TLSEXT_ERR_NOACK;
    int i;

    if (srctx->verbose)
        BIO_puts(bio_err, "cert_status: callback called\n");
    /* Build up OCSP query from server certificate */
    x = SSL_get_certificate(s);
    aia = X509_get1_ocsp(x);
    if (aia) {
        if (!OCSP_parse_url(sk_OPENSSL_STRING_value(aia, 0),
                            &host, &port, &path, &use_ssl)) {
            BIO_puts(bio_err, "cert_status: can't parse AIA URL\n");
            goto err;
        }
        if (srctx->verbose)
            BIO_printf(bio_err, "cert_status: AIA URL: %s\n",
                       sk_OPENSSL_STRING_value(aia, 0));
    } else {
        if (!srctx->host) {
            BIO_puts(bio_err,
                     "cert_status: no AIA and no default responder URL\n");
            goto done;
        }
        host = srctx->host;
        path = srctx->path;
        port = srctx->port;
        use_ssl = srctx->use_ssl;
    }

    if (!X509_STORE_CTX_init(&inctx,
                             SSL_CTX_get_cert_store(SSL_get_SSL_CTX(s)),
                             NULL, NULL))
        goto err;
    if (X509_STORE_get_by_subject(&inctx, X509_LU_X509,
                                  X509_get_issuer_name(x), &obj) <= 0) {
        BIO_puts(bio_err, "cert_status: Can't retrieve issuer certificate.\n");
        X509_STORE_CTX_cleanup(&inctx);
        goto done;
    }
    req = OCSP_REQUEST_new();
    if (req == NULL)
        goto err;
    id = OCSP_cert_to_id(NULL, x, obj.data.x509);
    X509_free(obj.data.x509);
    X509_STORE_CTX_cleanup(&inctx);
    if (!id)
        goto err;
    if (!OCSP_request_add0_id(req, id))
        goto err;
    id = NULL;
    /* Add any extensions to the request */
    SSL_get_tlsext_status_exts(s, &exts);
    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        if (!OCSP_REQUEST_add_ext(req, ext, -1))
            goto err;
    }
    resp = process_responder(req, host, path, port, use_ssl, NULL,
                             srctx->timeout);
    if (!resp) {
        BIO_puts(bio_err, "cert_status: error querying responder\n");
        goto done;
    }
    rspderlen = i2d_OCSP_RESPONSE(resp, &rspder);
    if (rspderlen <= 0)
        goto err;
    SSL_set_tlsext_status_ocsp_resp(s, rspder, rspderlen);
    if (srctx->verbose) {
        BIO_puts(bio_err, "cert_status: ocsp response sent:\n");
        OCSP_RESPONSE_print(bio_err, resp, 2);
    }
    ret = SSL_TLSEXT_ERR_OK;
 done:
    if (ret != SSL_TLSEXT_ERR_OK)
        ERR_print_errors(bio_err);
    if (aia) {
        OPENSSL_free(host);
        OPENSSL_free(path);
        OPENSSL_free(port);
        X509_email_free(aia);
    }
    OCSP_CERTID_free(id);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    return ret;
 err:
    ret = SSL_TLSEXT_ERR_ALERT_FATAL;
    goto done;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/* This is the context that we pass to next_proto_cb */
typedef struct tlsextnextprotoctx_st {
    unsigned char *data;
    unsigned int len;
} tlsextnextprotoctx;

static int next_proto_cb(SSL *s, const unsigned char **data,
                         unsigned int *len, void *arg)
{
    tlsextnextprotoctx *next_proto = arg;

    *data = next_proto->data;
    *len = next_proto->len;

    return SSL_TLSEXT_ERR_OK;
}
#endif                         /* ndef OPENSSL_NO_NEXTPROTONEG */

/* This the context that we pass to alpn_cb */
typedef struct tlsextalpnctx_st {
    unsigned char *data;
    unsigned short len;
} tlsextalpnctx;

static int alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg)
{
    tlsextalpnctx *alpn_ctx = arg;

    if (!s_quiet) {
        /* We can assume that |in| is syntactically valid. */
        unsigned i;
        BIO_printf(bio_s_out, "ALPN protocols advertised by the client: ");
        for (i = 0; i < inlen;) {
            if (i)
                BIO_write(bio_s_out, ", ", 2);
            BIO_write(bio_s_out, &in[i + 1], in[i]);
            i += in[i] + 1;
        }
        BIO_write(bio_s_out, "\n", 1);
    }

    if (SSL_select_next_proto
        ((unsigned char **)out, outlen, alpn_ctx->data, alpn_ctx->len, in,
         inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!s_quiet) {
        BIO_printf(bio_s_out, "ALPN protocols selected: ");
        BIO_write(bio_s_out, *out, *outlen);
        BIO_write(bio_s_out, "\n", 1);
    }

    return SSL_TLSEXT_ERR_OK;
}

static int not_resumable_sess_cb(SSL *s, int is_forward_secure)
{
    /* disable resumption for sessions with forward secure ciphers */
    return is_forward_secure;
}

static char *jpake_secret = NULL;
#ifndef OPENSSL_NO_SRP
static srpsrvparm srp_callback_parm;
#endif
#ifndef OPENSSL_NO_SRTP
static char *srtp_profiles = NULL;
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_PORT, OPT_UNIX, OPT_UNLINK, OPT_NACCEPT,
    OPT_VERIFY, OPT_UPPER_V_VERIFY, OPT_CONTEXT, OPT_CERT, OPT_CRL,
    OPT_CRL_DOWNLOAD, OPT_SERVERINFO, OPT_CERTFORM, OPT_KEY, OPT_KEYFORM,
    OPT_PASS, OPT_CERT_CHAIN, OPT_DHPARAM, OPT_DCERTFORM, OPT_DCERT,
    OPT_DKEYFORM, OPT_DPASS, OPT_DKEY, OPT_DCERT_CHAIN, OPT_NOCERT,
    OPT_CAPATH, OPT_NOCAPATH, OPT_CHAINCAPATH, OPT_VERIFYCAPATH, OPT_NO_CACHE,
    OPT_EXT_CACHE, OPT_CRLFORM, OPT_VERIFY_RET_ERROR, OPT_VERIFY_QUIET,
    OPT_BUILD_CHAIN, OPT_CAFILE, OPT_NOCAFILE, OPT_CHAINCAFILE,
    OPT_VERIFYCAFILE, OPT_NBIO, OPT_NBIO_TEST, OPT_IGN_EOF, OPT_NO_IGN_EOF,
    OPT_DEBUG, OPT_TLSEXTDEBUG, OPT_STATUS, OPT_STATUS_VERBOSE,
    OPT_STATUS_TIMEOUT, OPT_STATUS_URL, OPT_MSG, OPT_MSGFILE, OPT_TRACE,
    OPT_SECURITY_DEBUG, OPT_SECURITY_DEBUG_VERBOSE, OPT_STATE, OPT_CRLF,
    OPT_QUIET, OPT_BRIEF, OPT_NO_TMP_RSA, OPT_NO_DHE, OPT_NO_ECDHE,
    OPT_NO_RESUME_EPHEMERAL, OPT_PSK_HINT, OPT_PSK, OPT_SRPVFILE,
    OPT_SRPUSERSEED, OPT_REV, OPT_WWW, OPT_UPPER_WWW, OPT_HTTP, OPT_ASYNC,
    OPT_SSL3,
    OPT_TLS1_2, OPT_TLS1_1, OPT_TLS1, OPT_DTLS, OPT_DTLS1,
    OPT_DTLS1_2, OPT_TIMEOUT, OPT_MTU, OPT_CHAIN, OPT_LISTEN,
    OPT_ID_PREFIX, OPT_RAND, OPT_SERVERNAME, OPT_SERVERNAME_FATAL,
    OPT_CERT2, OPT_KEY2, OPT_NEXTPROTONEG, OPT_ALPN, OPT_JPAKE,
    OPT_SRTP_PROFILES, OPT_KEYMATEXPORT, OPT_KEYMATEXPORTLEN,
    OPT_S_ENUM,
    OPT_V_ENUM,
    OPT_X_ENUM
} OPTION_CHOICE;

OPTIONS s_server_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"port", OPT_PORT, 'p'},
    {"accept", OPT_PORT, 'p',
     "TCP/IP port to accept on (default is " PORT_STR ")"},
    {"unix", OPT_UNIX, 's', "Unix domain socket to accept on"},
    {"unlink", OPT_UNLINK, '-', "For -unix, unlink existing socket first"},
    {"context", OPT_CONTEXT, 's', "Set session ID context"},
    {"verify", OPT_VERIFY, 'n', "Turn on peer certificate verification"},
    {"Verify", OPT_UPPER_V_VERIFY, 'n',
     "Turn on peer certificate verification, must have a cert"},
    {"cert", OPT_CERT, '<', "Certificate file to use; default is " TEST_CERT},
    {"naccept", OPT_NACCEPT, 'p', "Terminate after pnum connections"},
    {"serverinfo", OPT_SERVERINFO, 's',
     "PEM serverinfo file for certificate"},
    {"certform", OPT_CERTFORM, 'F',
     "Certificate format (PEM or DER) PEM default"},
    {"key", OPT_KEY, '<',
     "Private Key if not in -cert; default is " TEST_CERT},
    {"keyform", OPT_KEYFORM, 'f',
     "Key format (PEM, DER or ENGINE) PEM default"},
    {"pass", OPT_PASS, 's', "Private key file pass phrase source"},
    {"dcert", OPT_DCERT, '<',
     "Second certificate file to use (usually for DSA)"},
    {"dcertform", OPT_DCERTFORM, 'F',
     "Second certificate format (PEM or DER) PEM default"},
    {"dkey", OPT_DKEY, '<',
     "Second private key file to use (usually for DSA)"},
    {"dkeyform", OPT_DKEYFORM, 'F',
     "Second key format (PEM, DER or ENGINE) PEM default"},
    {"dpass", OPT_DPASS, 's', "Second private key file pass phrase source"},
    {"nbio_test", OPT_NBIO_TEST, '-', "Test with the non-blocking test bio"},
    {"crlf", OPT_CRLF, '-', "Convert LF from terminal into CRLF"},
    {"debug", OPT_DEBUG, '-', "Print more output"},
    {"msg", OPT_MSG, '-', "Show protocol messages"},
    {"msgfile", OPT_MSGFILE, '>'},
    {"state", OPT_STATE, '-', "Print the SSL states"},
    {"CAfile", OPT_CAFILE, '<', "PEM format file of CA's"},
    {"CApath", OPT_CAPATH, '/', "PEM format directory of CA's"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"nocert", OPT_NOCERT, '-', "Don't use any certificates (Anon-DH)"},
    {"quiet", OPT_QUIET, '-', "No server output"},
    {"no_tmp_rsa", OPT_NO_TMP_RSA, '-', "Do not generate a tmp RSA key"},
    {"tls1_2", OPT_TLS1_2, '-', "just talk TLSv1.2"},
    {"tls1_1", OPT_TLS1_1, '-', "Just talk TLSv1.1"},
    {"tls1", OPT_TLS1, '-', "Just talk TLSv1"},
    {"no_resume_ephemeral", OPT_NO_RESUME_EPHEMERAL, '-',
     "Disable caching and tickets if ephemeral (EC)DH is used"},
    {"www", OPT_WWW, '-', "Respond to a 'GET /' with a status page"},
    {"WWW", OPT_UPPER_WWW, '-', "Respond to a 'GET with the file ./path"},
    {"servername", OPT_SERVERNAME, 's',
     "Servername for HostName TLS extension"},
    {"servername_fatal", OPT_SERVERNAME_FATAL, '-',
     "mismatch send fatal alert (default warning alert)"},
    {"cert2", OPT_CERT2, '<',
     "Certificate file to use for servername; default is" TEST_CERT2},
    {"key2", OPT_KEY2, '<',
     "-Private Key file to use for servername if not in -cert2"},
    {"tlsextdebug", OPT_TLSEXTDEBUG, '-',
     "Hex dump of all TLS extensions received"},
    {"HTTP", OPT_HTTP, '-', "Like -WWW but ./path incluedes HTTP headers"},
    {"id_prefix", OPT_ID_PREFIX, 's',
     "Generate SSL/TLS session IDs prefixed by arg"},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"keymatexport", OPT_KEYMATEXPORT, 's',
     "Export keying material using label"},
    {"keymatexportlen", OPT_KEYMATEXPORTLEN, 'p',
     "Export len bytes of keying material (default 20)"},
    {"CRL", OPT_CRL, '<'},
    {"crl_download", OPT_CRL_DOWNLOAD, '-'},
    {"cert_chain", OPT_CERT_CHAIN, '<'},
    {"dcert_chain", OPT_DCERT_CHAIN, '<'},
    {"chainCApath", OPT_CHAINCAPATH, '/'},
    {"verifyCApath", OPT_VERIFYCAPATH, '/'},
    {"no_cache", OPT_NO_CACHE, '-'},
    {"ext_cache", OPT_EXT_CACHE, '-'},
    {"CRLform", OPT_CRLFORM, 'F'},
    {"verify_return_error", OPT_VERIFY_RET_ERROR, '-'},
    {"verify_quiet", OPT_VERIFY_QUIET, '-'},
    {"build_chain", OPT_BUILD_CHAIN, '-'},
    {"chainCAfile", OPT_CHAINCAFILE, '<'},
    {"verifyCAfile", OPT_VERIFYCAFILE, '<'},
    {"ign_eof", OPT_IGN_EOF, '-'},
    {"no_ign_eof", OPT_NO_IGN_EOF, '-'},
    {"status", OPT_STATUS, '-'},
    {"status_verbose", OPT_STATUS_VERBOSE, '-'},
    {"status_timeout", OPT_STATUS_TIMEOUT, 'n'},
    {"status_url", OPT_STATUS_URL, 's'},
    {"trace", OPT_TRACE, '-'},
    {"security_debug", OPT_SECURITY_DEBUG, '-'},
    {"security_debug_verbose", OPT_SECURITY_DEBUG_VERBOSE, '-'},
    {"brief", OPT_BRIEF, '-'},
    {"rev", OPT_REV, '-'},
    {"async", OPT_ASYNC, '-', "Operate in asynchronous mode"},
    OPT_S_OPTIONS,
    OPT_V_OPTIONS,
    OPT_X_OPTIONS,
#ifdef FIONBIO
    {"nbio", OPT_NBIO, '-', "Use non-blocking IO"},
#endif
#ifndef OPENSSL_NO_PSK
    {"psk_hint", OPT_PSK_HINT, 's', "PSK identity hint to use"},
    {"psk", OPT_PSK, 's', "PSK in hex (without 0x)"},
# ifndef OPENSSL_NO_JPAKE
    {"jpake", OPT_JPAKE, 's', "JPAKE secret to use"},
# endif
#endif
#ifndef OPENSSL_NO_SRP
    {"srpvfile", OPT_SRPVFILE, '<', "The verifier file for SRP"},
    {"srpuserseed", OPT_SRPUSERSEED, 's',
     "A seed string for a default user salt"},
#endif
#ifndef OPENSSL_NO_SSL3
    {"ssl3", OPT_SSL3, '-', "Just talk SSLv3"},
#endif
#ifndef OPENSSL_NO_DTLS1
    {"dtls", OPT_DTLS, '-'},
    {"dtls1", OPT_DTLS1, '-', "Just talk DTLSv1"},
    {"dtls1_2", OPT_DTLS1_2, '-', "Just talk DTLSv1.2"},
    {"timeout", OPT_TIMEOUT, '-', "Enable timeouts"},
    {"mtu", OPT_MTU, 'p', "Set link layer MTU"},
    {"chain", OPT_CHAIN, '-', "Read a certificate chain"},
    {"listen", OPT_LISTEN, '-',
     "Listen for a DTLS ClientHello with a cookie and then connect"},
#endif
#ifndef OPENSSL_NO_DH
    {"no_dhe", OPT_NO_DHE, '-', "Disable ephemeral DH"},
#endif
#ifndef OPENSSL_NO_EC
    {"no_ecdhe", OPT_NO_ECDHE, '-', "Disable ephemeral ECDH"},
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
    {"nextprotoneg", OPT_NEXTPROTONEG, 's',
     "Set the advertised protocols for the NPN extension (comma-separated list)"},
#endif
#ifndef OPENSSL_NO_SRTP
    {"use_srtp", OPT_SRTP_PROFILES, 's',
     "Offer SRTP key management with a colon-separated profile list"},
    {"alpn", OPT_ALPN, 's',
     "Set the advertised protocols for the ALPN extension (comma-separated list)"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's'},
#endif
    {NULL}
};

int s_server_main(int argc, char *argv[])
{
    ENGINE *e = NULL;
    EVP_PKEY *s_key = NULL, *s_dkey = NULL;
    SSL_CONF_CTX *cctx = NULL;
    const SSL_METHOD *meth = TLS_server_method();
    SSL_EXCERT *exc = NULL;
    STACK_OF(OPENSSL_STRING) *ssl_args = NULL;
    STACK_OF(X509) *s_chain = NULL, *s_dchain = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509 *s_cert = NULL, *s_dcert = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    char *CApath = NULL, *CAfile = NULL, *chCApath = NULL, *chCAfile = NULL;
#ifndef OPENSSL_NO_DH
    char *dhfile = NULL;
#endif
    char *dpassarg = NULL, *dpass = NULL, *inrand = NULL;
    char *passarg = NULL, *pass = NULL, *vfyCApath = NULL, *vfyCAfile = NULL;
    char *crl_file = NULL, *prog;
#ifndef OPENSSL_NO_PSK
    char *p;
#endif
    const char *unix_path = NULL;
#ifndef NO_SYS_UN_H
    int unlink_unix_path = 0;
#endif
    int (*server_cb) (char *hostname, int s, int stype,
                      unsigned char *context);
    int vpmtouched = 0, build_chain = 0, no_cache = 0, ext_cache = 0;
#ifndef OPENSSL_NO_DH
    int no_dhe = 0;
#endif
    int no_tmp_rsa = 0, no_ecdhe = 0, nocert = 0, ret = 1;
    int noCApath = 0, noCAfile = 0;
    int s_cert_format = FORMAT_PEM, s_key_format = FORMAT_PEM;
    int s_dcert_format = FORMAT_PEM, s_dkey_format = FORMAT_PEM;
    int rev = 0, naccept = -1, sdebug = 0, socket_type = SOCK_STREAM;
    int state = 0, crl_format = FORMAT_PEM, crl_download = 0;
    unsigned short port = PORT;
    unsigned char *context = NULL;
    OPTION_CHOICE o;
    EVP_PKEY *s_key2 = NULL;
    X509 *s_cert2 = NULL;
    tlsextctx tlsextcbp = { NULL, NULL, SSL_TLSEXT_ERR_ALERT_WARNING };
#ifndef OPENSSL_NO_NEXTPROTONEG
    const char *next_proto_neg_in = NULL;
    tlsextnextprotoctx next_proto = { NULL, 0 };
#endif
    const char *alpn_in = NULL;
    tlsextalpnctx alpn_ctx = { NULL, 0 };
#ifndef OPENSSL_NO_PSK
    /* by default do not send a PSK identity hint */
    static char *psk_identity_hint = NULL;
#endif
#ifndef OPENSSL_NO_SRP
    char *srpuserseed = NULL;
    char *srp_verifier_file = NULL;
#endif

    local_argc = argc;
    local_argv = argv;

    s_server_init();
    cctx = SSL_CONF_CTX_new();
    vpm = X509_VERIFY_PARAM_new();
    if (cctx == NULL || vpm == NULL)
        goto end;
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CMDLINE);

    prog = opt_init(argc, argv, s_server_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
#ifdef OPENSSL_NO_PSK
        case OPT_PSK_HINT:
        case OPT_PSK:
#endif
#ifdef OPENSSL_NO_DTLS1
        case OPT_DTLS:
        case OPT_DTLS1:
        case OPT_DTLS1_2:
        case OPT_TIMEOUT:
        case OPT_MTU:
        case OPT_CHAIN:
#endif
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(s_server_options);
            ret = 0;
            goto end;

        case OPT_PORT:
            if (!extract_port(opt_arg(), &port))
                goto end;
            break;
        case OPT_UNIX:
#ifdef NO_SYS_UN_H
            BIO_printf(bio_err, "unix domain sockets unsupported\n");
            goto end;
#else
            unix_path = opt_arg();
#endif
            break;
        case OPT_UNLINK:
#ifdef NO_SYS_UN_H
            BIO_printf(bio_err, "unix domain sockets unsupported\n");
            goto end;
#else
            unlink_unix_path = 1;
#endif
            break;
        case OPT_NACCEPT:
            naccept = atol(opt_arg());
            break;
        case OPT_VERIFY:
            s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
            verify_depth = atoi(opt_arg());
            if (!s_quiet)
                BIO_printf(bio_err, "verify depth is %d\n", verify_depth);
            break;
        case OPT_UPPER_V_VERIFY:
            s_server_verify =
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                SSL_VERIFY_CLIENT_ONCE;
            verify_depth = atoi(opt_arg());
            if (!s_quiet)
                BIO_printf(bio_err,
                           "verify depth is %d, must return a certificate\n",
                           verify_depth);
            break;
        case OPT_CONTEXT:
            context = (unsigned char *)opt_arg();
            break;
        case OPT_CERT:
            s_cert_file = opt_arg();
            break;
        case OPT_CRL:
            crl_file = opt_arg();
            break;
        case OPT_CRL_DOWNLOAD:
            crl_download = 1;
            break;
        case OPT_SERVERINFO:
            s_serverinfo_file = opt_arg();
            break;
        case OPT_CERTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &s_cert_format))
                goto opthelp;
            break;
        case OPT_KEY:
            s_key_file = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &s_key_format))
                goto opthelp;
            break;
        case OPT_PASS:
            passarg = opt_arg();
            break;
        case OPT_CERT_CHAIN:
            s_chain_file = opt_arg();
            break;
        case OPT_DHPARAM:
#ifndef OPENSSL_NO_DH
            dhfile = opt_arg();
#endif
            break;
        case OPT_DCERTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &s_dcert_format))
                goto opthelp;
            break;
        case OPT_DCERT:
            s_dcert_file = opt_arg();
            break;
        case OPT_DKEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &s_dkey_format))
                goto opthelp;
            break;
        case OPT_DPASS:
            dpassarg = opt_arg();
            break;
        case OPT_DKEY:
            s_dkey_file = opt_arg();
            break;
        case OPT_DCERT_CHAIN:
            s_dchain_file = opt_arg();
            break;
        case OPT_NOCERT:
            nocert = 1;
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_CHAINCAPATH:
            chCApath = opt_arg();
            break;
        case OPT_VERIFYCAPATH:
            vfyCApath = opt_arg();
            break;
        case OPT_NO_CACHE:
            no_cache = 1;
            break;
        case OPT_EXT_CACHE:
            ext_cache = 1;
            break;
        case OPT_CRLFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &crl_format))
                goto opthelp;
            break;
        case OPT_S_CASES:
            if (ssl_args == NULL)
                ssl_args = sk_OPENSSL_STRING_new_null();
            if (ssl_args == NULL
                || !sk_OPENSSL_STRING_push(ssl_args, opt_flag())
                || !sk_OPENSSL_STRING_push(ssl_args, opt_arg())) {
                BIO_printf(bio_err, "%s: Memory allocation failure\n", prog);
                goto end;
            }
            break;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto end;
            vpmtouched++;
            break;
        case OPT_X_CASES:
            if (!args_excert(o, &exc))
                goto end;
            break;
        case OPT_VERIFY_RET_ERROR:
            verify_return_error = 1;
            break;
        case OPT_VERIFY_QUIET:
            verify_quiet = 1;
            break;
        case OPT_BUILD_CHAIN:
            build_chain = 1;
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_CHAINCAFILE:
            chCAfile = opt_arg();
            break;
        case OPT_VERIFYCAFILE:
            vfyCAfile = opt_arg();
            break;
        case OPT_NBIO:
            s_nbio = 1;
            break;
        case OPT_NBIO_TEST:
            s_nbio = s_nbio_test = 1;
            break;
        case OPT_IGN_EOF:
            s_ign_eof = 1;
            break;
        case OPT_NO_IGN_EOF:
            s_ign_eof = 0;
            break;
        case OPT_DEBUG:
            s_debug = 1;
            break;
        case OPT_TLSEXTDEBUG:
            s_tlsextdebug = 1;
            break;
        case OPT_STATUS:
            s_tlsextstatus = 1;
            break;
        case OPT_STATUS_VERBOSE:
            s_tlsextstatus = tlscstatp.verbose = 1;
            break;
        case OPT_STATUS_TIMEOUT:
            s_tlsextstatus = 1;
            tlscstatp.timeout = atoi(opt_arg());
            break;
        case OPT_STATUS_URL:
            s_tlsextstatus = 1;
            if (!OCSP_parse_url(opt_arg(),
                                &tlscstatp.host,
                                &tlscstatp.port,
                                &tlscstatp.path, &tlscstatp.use_ssl)) {
                BIO_printf(bio_err, "Error parsing URL\n");
                goto end;
            }
            break;
        case OPT_MSG:
            s_msg = 1;
            break;
        case OPT_MSGFILE:
            bio_s_msg = BIO_new_file(opt_arg(), "w");
            break;
        case OPT_TRACE:
#ifndef OPENSSL_NO_SSL_TRACE
            s_msg = 2;
#else
            break;
#endif
        case OPT_SECURITY_DEBUG:
            sdebug = 1;
            break;
        case OPT_SECURITY_DEBUG_VERBOSE:
            sdebug = 2;
            break;
        case OPT_STATE:
            state = 1;
            break;
        case OPT_CRLF:
            s_crlf = 1;
            break;
        case OPT_QUIET:
            s_quiet = 1;
            break;
        case OPT_BRIEF:
            s_quiet = s_brief = verify_quiet = 1;
            break;
        case OPT_NO_TMP_RSA:
            no_tmp_rsa = 1;
            break;
        case OPT_NO_DHE:
#ifndef OPENSSL_NO_DH
            no_dhe = 1;
#endif
            break;
        case OPT_NO_ECDHE:
            no_ecdhe = 1;
            break;
        case OPT_NO_RESUME_EPHEMERAL:
            no_resume_ephemeral = 1;
            break;
#ifndef OPENSSL_NO_PSK
        case OPT_PSK_HINT:
            psk_identity_hint = opt_arg();
            break;
        case OPT_PSK:
            for (p = psk_key = opt_arg(); *p; p++) {
                if (isxdigit(*p))
                    continue;
                BIO_printf(bio_err, "Not a hex number '%s'\n", *argv);
                goto end;
            }
            break;
#endif
#ifndef OPENSSL_NO_SRP
        case OPT_SRPVFILE:
            srp_verifier_file = opt_arg();
            meth = TLSv1_server_method();
            break;
        case OPT_SRPUSERSEED:
            srpuserseed = opt_arg();
            meth = TLSv1_server_method();
            break;
#else
        case OPT_SRPVFILE:
        case OPT_SRPUSERSEED:
            break;
#endif
        case OPT_REV:
            rev = 1;
            break;
        case OPT_WWW:
            www = 1;
            break;
        case OPT_UPPER_WWW:
            www = 2;
            break;
        case OPT_HTTP:
            www = 3;
            break;
        case OPT_SSL3:
#ifndef OPENSSL_NO_SSL3
            meth = SSLv3_server_method();
#endif
            break;
        case OPT_TLS1_2:
            meth = TLSv1_2_server_method();
            break;
        case OPT_TLS1_1:
            meth = TLSv1_1_server_method();
            break;
        case OPT_TLS1:
            meth = TLSv1_server_method();
            break;
#ifndef OPENSSL_NO_DTLS1
        case OPT_DTLS:
            meth = DTLS_server_method();
            socket_type = SOCK_DGRAM;
            break;
        case OPT_DTLS1:
            meth = DTLSv1_server_method();
            socket_type = SOCK_DGRAM;
            break;
        case OPT_DTLS1_2:
            meth = DTLSv1_2_server_method();
            socket_type = SOCK_DGRAM;
            break;
        case OPT_TIMEOUT:
            enable_timeouts = 1;
            break;
        case OPT_MTU:
            socket_mtu = atol(opt_arg());
            break;
        case OPT_CHAIN:
            cert_chain = 1;
            break;
        case OPT_LISTEN:
            dtlslisten = 1;
            break;
#else
        case OPT_DTLS:
        case OPT_DTLS1:
        case OPT_DTLS1_2:
        case OPT_TIMEOUT:
        case OPT_MTU:
        case OPT_CHAIN:
        case OPT_LISTEN:
            break;
#endif
        case OPT_ID_PREFIX:
            session_id_prefix = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 1);
            break;
        case OPT_RAND:
            inrand = opt_arg();
            break;
        case OPT_SERVERNAME:
            tlsextcbp.servername = opt_arg();
            break;
        case OPT_SERVERNAME_FATAL:
            tlsextcbp.extension_error = SSL_TLSEXT_ERR_ALERT_FATAL;
            break;
        case OPT_CERT2:
            s_cert_file2 = opt_arg();
            break;
        case OPT_KEY2:
            s_key_file2 = opt_arg();
            break;
        case OPT_NEXTPROTONEG:
# ifndef OPENSSL_NO_NEXTPROTONEG
            next_proto_neg_in = opt_arg();
#endif
            break;
        case OPT_ALPN:
            alpn_in = opt_arg();
            break;
#if !defined(OPENSSL_NO_JPAKE) && !defined(OPENSSL_NO_PSK)
        case OPT_JPAKE:
            jpake_secret = opt_arg();
            break;
#else
        case OPT_JPAKE:
            goto opthelp;
#endif
        case OPT_SRTP_PROFILES:
            srtp_profiles = opt_arg();
            break;
        case OPT_KEYMATEXPORT:
            keymatexportlabel = opt_arg();
            break;
        case OPT_KEYMATEXPORTLEN:
            keymatexportlen = atoi(opt_arg());
            break;
        case OPT_ASYNC:
            async = 1;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

#ifndef OPENSSL_NO_DTLS1
    if (www && socket_type == SOCK_DGRAM) {
        BIO_printf(bio_err, "Can't use -HTTP, -www or -WWW with DTLS\n");
        goto end;
    }

    if (dtlslisten && socket_type != SOCK_DGRAM) {
        BIO_printf(bio_err, "Can only use -listen with DTLS\n");
        goto end;
    }
#endif

    if (unix_path && (socket_type != SOCK_STREAM)) {
        BIO_printf(bio_err,
                   "Can't use unix sockets and datagrams together\n");
        goto end;
    }
#if !defined(OPENSSL_NO_JPAKE) && !defined(OPENSSL_NO_PSK)
    if (jpake_secret) {
        if (psk_key) {
            BIO_printf(bio_err, "Can't use JPAKE and PSK together\n");
            goto end;
        }
        psk_identity = "JPAKE";
    }
#endif

    if (!app_passwd(passarg, dpassarg, &pass, &dpass)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (s_key_file == NULL)
        s_key_file = s_cert_file;

    if (s_key_file2 == NULL)
        s_key_file2 = s_cert_file2;

    if (!load_excert(&exc))
        goto end;

    if (nocert == 0) {
        s_key = load_key(s_key_file, s_key_format, 0, pass, e,
                         "server certificate private key file");
        if (!s_key) {
            ERR_print_errors(bio_err);
            goto end;
        }

        s_cert = load_cert(s_cert_file, s_cert_format,
                           NULL, e, "server certificate file");

        if (!s_cert) {
            ERR_print_errors(bio_err);
            goto end;
        }
        if (s_chain_file) {
            s_chain = load_certs(s_chain_file, FORMAT_PEM,
                                 NULL, e, "server certificate chain");
            if (!s_chain)
                goto end;
        }

        if (tlsextcbp.servername) {
            s_key2 = load_key(s_key_file2, s_key_format, 0, pass, e,
                              "second server certificate private key file");
            if (!s_key2) {
                ERR_print_errors(bio_err);
                goto end;
            }

            s_cert2 = load_cert(s_cert_file2, s_cert_format,
                                NULL, e, "second server certificate file");

            if (!s_cert2) {
                ERR_print_errors(bio_err);
                goto end;
            }
        }
    }
#if !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto_neg_in) {
        unsigned short len;
        next_proto.data = next_protos_parse(&len, next_proto_neg_in);
        if (next_proto.data == NULL)
            goto end;
        next_proto.len = len;
    } else {
        next_proto.data = NULL;
    }
#endif
    alpn_ctx.data = NULL;
    if (alpn_in) {
        unsigned short len;
        alpn_ctx.data = next_protos_parse(&len, alpn_in);
        if (alpn_ctx.data == NULL)
            goto end;
        alpn_ctx.len = len;
    }

    if (crl_file) {
        X509_CRL *crl;
        crl = load_crl(crl_file, crl_format);
        if (!crl) {
            BIO_puts(bio_err, "Error loading CRL\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        crls = sk_X509_CRL_new_null();
        if (!crls || !sk_X509_CRL_push(crls, crl)) {
            BIO_puts(bio_err, "Error adding CRL\n");
            ERR_print_errors(bio_err);
            X509_CRL_free(crl);
            goto end;
        }
    }

    if (s_dcert_file) {

        if (s_dkey_file == NULL)
            s_dkey_file = s_dcert_file;

        s_dkey = load_key(s_dkey_file, s_dkey_format,
                          0, dpass, e, "second certificate private key file");
        if (!s_dkey) {
            ERR_print_errors(bio_err);
            goto end;
        }

        s_dcert = load_cert(s_dcert_file, s_dcert_format,
                            NULL, e, "second server certificate file");

        if (!s_dcert) {
            ERR_print_errors(bio_err);
            goto end;
        }
        if (s_dchain_file) {
            s_dchain = load_certs(s_dchain_file, FORMAT_PEM,
                                  NULL, e, "second server certificate chain");
            if (!s_dchain)
                goto end;
        }

    }

    if (!app_RAND_load_file(NULL, 1) && inrand == NULL
        && !RAND_status()) {
        BIO_printf(bio_err,
                   "warning, not much extra random data, consider using the -rand option\n");
    }
    if (inrand != NULL)
        BIO_printf(bio_err, "%ld semi-random bytes loaded\n",
                   app_RAND_load_files(inrand));

    if (bio_s_out == NULL) {
        if (s_quiet && !s_debug) {
            bio_s_out = BIO_new(BIO_s_null());
            if (s_msg && !bio_s_msg)
                bio_s_msg = dup_bio_out(FORMAT_TEXT);
        } else {
            if (bio_s_out == NULL)
                bio_s_out = dup_bio_out(FORMAT_TEXT);
        }
    }
#if !defined(OPENSSL_NO_RSA) || !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_EC)
    if (nocert)
#endif
    {
        s_cert_file = NULL;
        s_key_file = NULL;
        s_dcert_file = NULL;
        s_dkey_file = NULL;
        s_cert_file2 = NULL;
        s_key_file2 = NULL;
    }

    ctx = SSL_CTX_new(meth);
    if (sdebug)
        ssl_ctx_security_debug(ctx, sdebug);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (session_id_prefix) {
        if (strlen(session_id_prefix) >= 32)
            BIO_printf(bio_err,
                       "warning: id_prefix is too long, only one new session will be possible\n");
        if (!SSL_CTX_set_generate_session_id(ctx, generate_session_id)) {
            BIO_printf(bio_err, "error setting 'id_prefix'\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        BIO_printf(bio_err, "id_prefix '%s' set.\n", session_id_prefix);
    }
    SSL_CTX_set_quiet_shutdown(ctx, 1);
    if (exc)
        ssl_ctx_set_excert(ctx, exc);

    if (state)
        SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
    if (no_cache)
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    else if (ext_cache)
        init_session_cache_ctx(ctx);
    else
        SSL_CTX_sess_set_cache_size(ctx, 128);

    if (async) {
        SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);
        ASYNC_init(1, 0, 0);
    }

#ifndef OPENSSL_NO_SRTP
    if (srtp_profiles != NULL) {
        /* Returns 0 on success! */
        if (SSL_CTX_set_tlsext_use_srtp(ctx, srtp_profiles) != 0) {
            BIO_printf(bio_err, "Error setting SRTP profile\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif

    if (!ctx_set_verify_locations(ctx, CAfile, CApath, noCAfile, noCApath)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (vpmtouched && !SSL_CTX_set1_param(ctx, vpm)) {
        BIO_printf(bio_err, "Error setting verify params\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    ssl_ctx_add_crls(ctx, crls, 0);
    if (!config_ctx(cctx, ssl_args, ctx, no_ecdhe, jpake_secret == NULL))
        goto end;

    if (!ssl_load_stores(ctx, vfyCApath, vfyCAfile, chCApath, chCAfile,
                         crls, crl_download)) {
        BIO_printf(bio_err, "Error loading store locations\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (s_cert2) {
        ctx2 = SSL_CTX_new(meth);
        if (ctx2 == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (ctx2) {
        BIO_printf(bio_s_out, "Setting secondary ctx parameters\n");

        if (sdebug)
            ssl_ctx_security_debug(ctx, sdebug);

        if (session_id_prefix) {
            if (strlen(session_id_prefix) >= 32)
                BIO_printf(bio_err,
                           "warning: id_prefix is too long, only one new session will be possible\n");
            if (!SSL_CTX_set_generate_session_id(ctx2, generate_session_id)) {
                BIO_printf(bio_err, "error setting 'id_prefix'\n");
                ERR_print_errors(bio_err);
                goto end;
            }
            BIO_printf(bio_err, "id_prefix '%s' set.\n", session_id_prefix);
        }
        SSL_CTX_set_quiet_shutdown(ctx2, 1);
        if (exc)
            ssl_ctx_set_excert(ctx2, exc);

        if (state)
            SSL_CTX_set_info_callback(ctx2, apps_ssl_info_callback);

        if (no_cache)
            SSL_CTX_set_session_cache_mode(ctx2, SSL_SESS_CACHE_OFF);
        else if (ext_cache)
            init_session_cache_ctx(ctx2);
        else
            SSL_CTX_sess_set_cache_size(ctx2, 128);

        if (async)
            SSL_CTX_set_mode(ctx2, SSL_MODE_ASYNC);

        if ((!SSL_CTX_load_verify_locations(ctx2, CAfile, CApath)) ||
            (!SSL_CTX_set_default_verify_paths(ctx2))) {
            ERR_print_errors(bio_err);
        }
        if (vpmtouched && !SSL_CTX_set1_param(ctx2, vpm)) {
            BIO_printf(bio_err, "Error setting verify params\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        ssl_ctx_add_crls(ctx2, crls, 0);
        if (!config_ctx(cctx, ssl_args, ctx2, no_ecdhe, jpake_secret == NULL))
            goto end;
    }
#ifndef OPENSSL_NO_NEXTPROTONEG
    if (next_proto.data)
        SSL_CTX_set_next_protos_advertised_cb(ctx, next_proto_cb,
                                              &next_proto);
#endif
    if (alpn_ctx.data)
        SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, &alpn_ctx);

#ifndef OPENSSL_NO_DH
    if (!no_dhe) {
        DH *dh = NULL;

        if (dhfile)
            dh = load_dh_param(dhfile);
        else if (s_cert_file)
            dh = load_dh_param(s_cert_file);

        if (dh != NULL) {
            BIO_printf(bio_s_out, "Setting temp DH parameters\n");
        } else {
            BIO_printf(bio_s_out, "Using default temp DH parameters\n");
        }
        (void)BIO_flush(bio_s_out);

        if (dh == NULL)
            SSL_CTX_set_dh_auto(ctx, 1);
        else if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
            BIO_puts(bio_err, "Error setting temp DH parameters\n");
            ERR_print_errors(bio_err);
            DH_free(dh);
            goto end;
        }

        if (ctx2) {
            if (!dhfile) {
                DH *dh2 = load_dh_param(s_cert_file2);
                if (dh2 != NULL) {
                    BIO_printf(bio_s_out, "Setting temp DH parameters\n");
                    (void)BIO_flush(bio_s_out);

                    DH_free(dh);
                    dh = dh2;
                }
            }
            if (dh == NULL)
                SSL_CTX_set_dh_auto(ctx2, 1);
            else if (!SSL_CTX_set_tmp_dh(ctx2, dh)) {
                BIO_puts(bio_err, "Error setting temp DH parameters\n");
                ERR_print_errors(bio_err);
                DH_free(dh);
                goto end;
            }
        }
        DH_free(dh);
    }
#endif

    if (!set_cert_key_stuff(ctx, s_cert, s_key, s_chain, build_chain))
        goto end;

    if (s_serverinfo_file != NULL
        && !SSL_CTX_use_serverinfo_file(ctx, s_serverinfo_file)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (ctx2 && !set_cert_key_stuff(ctx2, s_cert2, s_key2, NULL, build_chain))
        goto end;

    if (s_dcert != NULL) {
        if (!set_cert_key_stuff(ctx, s_dcert, s_dkey, s_dchain, build_chain))
            goto end;
    }
#ifndef OPENSSL_NO_RSA
    if (!no_tmp_rsa) {
        SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb);
        if (ctx2)
            SSL_CTX_set_tmp_rsa_callback(ctx2, tmp_rsa_cb);
    }
#endif

    if (no_resume_ephemeral) {
        SSL_CTX_set_not_resumable_session_callback(ctx,
                                                   not_resumable_sess_cb);

        if (ctx2)
            SSL_CTX_set_not_resumable_session_callback(ctx2,
                                                       not_resumable_sess_cb);
    }
#ifndef OPENSSL_NO_PSK
# ifdef OPENSSL_NO_JPAKE
    if (psk_key != NULL)
# else
    if (psk_key != NULL || jpake_secret)
# endif
    {
        if (s_debug)
            BIO_printf(bio_s_out,
                       "PSK key given or JPAKE in use, setting server callback\n");
        SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);
    }

    if (!SSL_CTX_use_psk_identity_hint(ctx, psk_identity_hint)) {
        BIO_printf(bio_err, "error setting PSK identity hint to context\n");
        ERR_print_errors(bio_err);
        goto end;
    }
#endif

    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);
    if (!SSL_CTX_set_session_id_context(ctx,
                (void *)&s_server_session_id_context,
                sizeof s_server_session_id_context)) {
        BIO_printf(bio_err, "error setting session id context\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    /* Set DTLS cookie generation and verification callbacks */
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);

    if (ctx2) {
        SSL_CTX_set_verify(ctx2, s_server_verify, verify_callback);
        if (!SSL_CTX_set_session_id_context(ctx2,
                    (void *)&s_server_session_id_context,
                    sizeof s_server_session_id_context)) {
            BIO_printf(bio_err, "error setting session id context\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        tlsextcbp.biodebug = bio_s_out;
        SSL_CTX_set_tlsext_servername_callback(ctx2, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx2, &tlsextcbp);
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx, &tlsextcbp);
    }

#ifndef OPENSSL_NO_SRP
    if (srp_verifier_file != NULL) {
        srp_callback_parm.vb = SRP_VBASE_new(srpuserseed);
        srp_callback_parm.user = NULL;
        srp_callback_parm.login = NULL;
        if ((ret =
             SRP_VBASE_init(srp_callback_parm.vb,
                            srp_verifier_file)) != SRP_NO_ERROR) {
            BIO_printf(bio_err,
                       "Cannot initialize SRP verifier file \"%s\":ret=%d\n",
                       srp_verifier_file, ret);
            goto end;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
        SSL_CTX_set_srp_cb_arg(ctx, &srp_callback_parm);
        SSL_CTX_set_srp_username_callback(ctx, ssl_srp_server_param_cb);
    } else
#endif
    if (CAfile != NULL) {
        SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CAfile));

        if (ctx2)
            SSL_CTX_set_client_CA_list(ctx2, SSL_load_client_CA_file(CAfile));
    }
    if (s_tlsextstatus) {
        SSL_CTX_set_tlsext_status_cb(ctx, cert_status_cb);
        SSL_CTX_set_tlsext_status_arg(ctx, &tlscstatp);
        if (ctx2) {
            SSL_CTX_set_tlsext_status_cb(ctx2, cert_status_cb);
            SSL_CTX_set_tlsext_status_arg(ctx2, &tlscstatp);
        }
    }

    BIO_printf(bio_s_out, "ACCEPT\n");
    (void)BIO_flush(bio_s_out);
    if (rev)
        server_cb = rev_body;
    else if (www)
        server_cb = www_body;
    else
        server_cb = sv_body;
#ifndef NO_SYS_UN_H
    if (unix_path) {
        if (unlink_unix_path)
            unlink(unix_path);
        do_server_unix(unix_path, &accept_socket, server_cb, context,
                       naccept);
    } else
#endif
        do_server(port, socket_type, &accept_socket, server_cb, context,
                  naccept);
    print_stats(bio_s_out, ctx);
    ret = 0;
 end:
    SSL_CTX_free(ctx);
    X509_free(s_cert);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    X509_free(s_dcert);
    EVP_PKEY_free(s_key);
    EVP_PKEY_free(s_dkey);
    sk_X509_pop_free(s_chain, X509_free);
    sk_X509_pop_free(s_dchain, X509_free);
    OPENSSL_free(pass);
    OPENSSL_free(dpass);
    X509_VERIFY_PARAM_free(vpm);
    free_sessions();
    OPENSSL_free(tlscstatp.host);
    OPENSSL_free(tlscstatp.port);
    OPENSSL_free(tlscstatp.path);
    SSL_CTX_free(ctx2);
    X509_free(s_cert2);
    EVP_PKEY_free(s_key2);
    BIO_free(serverinfo_in);
#ifndef OPENSSL_NO_NEXTPROTONEG
    OPENSSL_free(next_proto.data);
#endif
    OPENSSL_free(alpn_ctx.data);
    ssl_excert_free(exc);
    sk_OPENSSL_STRING_free(ssl_args);
    SSL_CONF_CTX_free(cctx);
    BIO_free(bio_s_out);
    bio_s_out = NULL;
    BIO_free(bio_s_msg);
    bio_s_msg = NULL;
    if (async) {
        ASYNC_cleanup(1);
    }
    return (ret);
}

static void print_stats(BIO *bio, SSL_CTX *ssl_ctx)
{
    BIO_printf(bio, "%4ld items in the session cache\n",
               SSL_CTX_sess_number(ssl_ctx));
    BIO_printf(bio, "%4ld client connects (SSL_connect())\n",
               SSL_CTX_sess_connect(ssl_ctx));
    BIO_printf(bio, "%4ld client renegotiates (SSL_connect())\n",
               SSL_CTX_sess_connect_renegotiate(ssl_ctx));
    BIO_printf(bio, "%4ld client connects that finished\n",
               SSL_CTX_sess_connect_good(ssl_ctx));
    BIO_printf(bio, "%4ld server accepts (SSL_accept())\n",
               SSL_CTX_sess_accept(ssl_ctx));
    BIO_printf(bio, "%4ld server renegotiates (SSL_accept())\n",
               SSL_CTX_sess_accept_renegotiate(ssl_ctx));
    BIO_printf(bio, "%4ld server accepts that finished\n",
               SSL_CTX_sess_accept_good(ssl_ctx));
    BIO_printf(bio, "%4ld session cache hits\n", SSL_CTX_sess_hits(ssl_ctx));
    BIO_printf(bio, "%4ld session cache misses\n",
               SSL_CTX_sess_misses(ssl_ctx));
    BIO_printf(bio, "%4ld session cache timeouts\n",
               SSL_CTX_sess_timeouts(ssl_ctx));
    BIO_printf(bio, "%4ld callback cache hits\n",
               SSL_CTX_sess_cb_hits(ssl_ctx));
    BIO_printf(bio, "%4ld cache full overflows (%ld allowed)\n",
               SSL_CTX_sess_cache_full(ssl_ctx),
               SSL_CTX_sess_get_cache_size(ssl_ctx));
}

static int sv_body(char *hostname, int s, int stype, unsigned char *context)
{
    char *buf = NULL;
    fd_set readfds;
    int ret = 1, width;
    int k, i;
    unsigned long l;
    SSL *con = NULL;
    BIO *sbio;
    struct timeval timeout;
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE)
    struct timeval tv;
#else
    struct timeval *timeoutp;
#endif

    buf = app_malloc(bufsize, "server buffer");
#ifdef FIONBIO
    if (s_nbio) {
        unsigned long sl = 1;

        if (!s_quiet)
            BIO_printf(bio_err, "turning on non blocking io\n");
        if (BIO_socket_ioctl(s, FIONBIO, &sl) < 0)
            ERR_print_errors(bio_err);
    }
#endif

    if (con == NULL) {
        con = SSL_new(ctx);

        if (s_tlsextdebug) {
            SSL_set_tlsext_debug_callback(con, tlsext_cb);
            SSL_set_tlsext_debug_arg(con, bio_s_out);
        }

        if (context
                && !SSL_set_session_id_context(con,
                        context, strlen((char *)context))) {
            BIO_printf(bio_err, "Error setting session id context\n");
            ret = -1;
            goto err;
        }
    }
    if (!SSL_clear(con)) {
        BIO_printf(bio_err, "Error clearing SSL connection\n");
        ret = -1;
        goto err;
    }

    if (stype == SOCK_DGRAM) {

        sbio = BIO_new_dgram(s, BIO_NOCLOSE);

        if (enable_timeouts) {
            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_RCV_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_SND_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        }

        if (socket_mtu) {
            if (socket_mtu < DTLS_get_link_min_mtu(con)) {
                BIO_printf(bio_err, "MTU too small. Must be at least %ld\n",
                           DTLS_get_link_min_mtu(con));
                ret = -1;
                BIO_free(sbio);
                goto err;
            }
            SSL_set_options(con, SSL_OP_NO_QUERY_MTU);
            if (!DTLS_set_link_mtu(con, socket_mtu)) {
                BIO_printf(bio_err, "Failed to set MTU\n");
                ret = -1;
                BIO_free(sbio);
                goto err;
            }
        } else
            /* want to do MTU discovery */
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);

        /* turn on cookie exchange */
        SSL_set_options(con, SSL_OP_COOKIE_EXCHANGE);
    } else
        sbio = BIO_new_socket(s, BIO_NOCLOSE);

    if (s_nbio_test) {
        BIO *test;

        test = BIO_new(BIO_f_nbio_test());
        sbio = BIO_push(test, sbio);
    }
#ifndef OPENSSL_NO_JPAKE
    if (jpake_secret)
        jpake_server_auth(bio_s_out, sbio, jpake_secret);
#endif

    SSL_set_bio(con, sbio, sbio);
    SSL_set_accept_state(con);
    /* SSL_set_fd(con,s); */

    if (s_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(SSL_get_rbio(con), bio_dump_callback);
        BIO_set_callback_arg(SSL_get_rbio(con), (char *)bio_s_out);
    }
    if (s_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (s_msg == 2)
            SSL_set_msg_callback(con, SSL_trace);
        else
#endif
            SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_s_msg ? bio_s_msg : bio_s_out);
    }

    if (s_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_s_out);
    }

    width = s + 1;
    for (;;) {
        int read_from_terminal;
        int read_from_sslcon;

        read_from_terminal = 0;
        read_from_sslcon = SSL_pending(con)
                           || (async && SSL_waiting_for_async(con));

        if (!read_from_sslcon) {
            FD_ZERO(&readfds);
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_NETWARE)
            openssl_fdset(fileno(stdin), &readfds);
#endif
            openssl_fdset(s, &readfds);
            /*
             * Note: under VMS with SOCKETSHR the second parameter is
             * currently of type (int *) whereas under other systems it is
             * (void *) if you don't have a cast it will choke the compiler:
             * if you do have a cast then you can either go for (int *) or
             * (void *).
             */
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE)
            /*
             * Under DOS (non-djgpp) and Windows we can't select on stdin:
             * only on sockets. As a workaround we timeout the select every
             * second and check for any keypress. In a proper Windows
             * application we wouldn't do this because it is inefficient.
             */
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            i = select(width, (void *)&readfds, NULL, NULL, &tv);
            if ((i < 0) || (!i && !_kbhit()))
                continue;
            if (_kbhit())
                read_from_terminal = 1;
#else
            if ((SSL_version(con) == DTLS1_VERSION) &&
                DTLSv1_get_timeout(con, &timeout))
                timeoutp = &timeout;
            else
                timeoutp = NULL;

            i = select(width, (void *)&readfds, NULL, NULL, timeoutp);

            if ((SSL_version(con) == DTLS1_VERSION)
                && DTLSv1_handle_timeout(con) > 0) {
                BIO_printf(bio_err, "TIMEOUT occurred\n");
            }

            if (i <= 0)
                continue;
            if (FD_ISSET(fileno(stdin), &readfds))
                read_from_terminal = 1;
#endif
            if (FD_ISSET(s, &readfds))
                read_from_sslcon = 1;
        }
        if (read_from_terminal) {
            if (s_crlf) {
                int j, lf_num;

                i = raw_read_stdin(buf, bufsize / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (buf[j] == '\n')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    buf[j + lf_num] = buf[j];
                    if (buf[j] == '\n') {
                        lf_num--;
                        i++;
                        buf[j + lf_num] = '\r';
                    }
                }
                assert(lf_num == 0);
            } else
                i = raw_read_stdin(buf, bufsize);
            if (!s_quiet && !s_brief) {
                if ((i <= 0) || (buf[0] == 'Q')) {
                    BIO_printf(bio_s_out, "DONE\n");
                    (void)BIO_flush(bio_s_out);
                    SHUTDOWN(s);
                    close_accept_socket();
                    ret = -11;
                    goto err;
                }
                if ((i <= 0) || (buf[0] == 'q')) {
                    BIO_printf(bio_s_out, "DONE\n");
                    (void)BIO_flush(bio_s_out);
                    if (SSL_version(con) != DTLS1_VERSION)
                        SHUTDOWN(s);
                    /*
                     * close_accept_socket(); ret= -11;
                     */
                    goto err;
                }
#ifndef OPENSSL_NO_HEARTBEATS
                if ((buf[0] == 'B') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    BIO_printf(bio_err, "HEARTBEATING\n");
                    SSL_heartbeat(con);
                    i = 0;
                    continue;
                }
#endif
                if ((buf[0] == 'r') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    SSL_renegotiate(con);
                    i = SSL_do_handshake(con);
                    printf("SSL_do_handshake -> %d\n", i);
                    i = 0;      /* 13; */
                    continue;
                    /*
                     * strcpy(buf,"server side RE-NEGOTIATE\n");
                     */
                }
                if ((buf[0] == 'R') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    SSL_set_verify(con,
                                   SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                                   NULL);
                    SSL_renegotiate(con);
                    i = SSL_do_handshake(con);
                    printf("SSL_do_handshake -> %d\n", i);
                    i = 0;      /* 13; */
                    continue;
                    /*
                     * strcpy(buf,"server side RE-NEGOTIATE asking for client
                     * cert\n");
                     */
                }
                if (buf[0] == 'P') {
                    static const char *str = "Lets print some clear text\n";
                    BIO_write(SSL_get_wbio(con), str, strlen(str));
                }
                if (buf[0] == 'S') {
                    print_stats(bio_s_out, SSL_get_SSL_CTX(con));
                }
            }
#ifdef CHARSET_EBCDIC
            ebcdic2ascii(buf, buf, i);
#endif
            l = k = 0;
            for (;;) {
                /* should do a select for the write */
#ifdef RENEG
                {
                    static count = 0;
                    if (++count == 100) {
                        count = 0;
                        SSL_renegotiate(con);
                    }
                }
#endif
                k = SSL_write(con, &(buf[l]), (unsigned int)i);
#ifndef OPENSSL_NO_SRP
                while (SSL_get_error(con, k) == SSL_ERROR_WANT_X509_LOOKUP) {
                    BIO_printf(bio_s_out, "LOOKUP renego during write\n");
                    srp_callback_parm.user =
                        SRP_VBASE_get_by_user(srp_callback_parm.vb,
                                              srp_callback_parm.login);
                    if (srp_callback_parm.user)
                        BIO_printf(bio_s_out, "LOOKUP done %s\n",
                                   srp_callback_parm.user->info);
                    else
                        BIO_printf(bio_s_out, "LOOKUP not successful\n");
                    k = SSL_write(con, &(buf[l]), (unsigned int)i);
                }
#endif
                switch (SSL_get_error(con, k)) {
                case SSL_ERROR_NONE:
                    break;
                case SSL_ERROR_WANT_ASYNC:
                    BIO_printf(bio_s_out, "Write BLOCK (Async)\n");
                    wait_for_async(con);
                    break;
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_X509_LOOKUP:
                    BIO_printf(bio_s_out, "Write BLOCK\n");
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    BIO_printf(bio_s_out, "ERROR\n");
                    (void)BIO_flush(bio_s_out);
                    ERR_print_errors(bio_err);
                    ret = 1;
                    goto err;
                    /* break; */
                case SSL_ERROR_ZERO_RETURN:
                    BIO_printf(bio_s_out, "DONE\n");
                    (void)BIO_flush(bio_s_out);
                    ret = 1;
                    goto err;
                }
                if (k > 0) {
                    l += k;
                    i -= k;
                }
                if (i <= 0)
                    break;
            }
        }
        if (read_from_sslcon) {
            /*
             * init_ssl_connection handles all async events itself so if we're
             * waiting for async then we shouldn't go back into
             * init_ssl_connection
             */
            if ((!async || !SSL_waiting_for_async(con))
                    && !SSL_is_init_finished(con)) {
                i = init_ssl_connection(con);

                if (i < 0) {
                    ret = 0;
                    goto err;
                } else if (i == 0) {
                    ret = 1;
                    goto err;
                }
            } else {
 again:
                i = SSL_read(con, (char *)buf, bufsize);
#ifndef OPENSSL_NO_SRP
                while (SSL_get_error(con, i) == SSL_ERROR_WANT_X509_LOOKUP) {
                    BIO_printf(bio_s_out, "LOOKUP renego during read\n");
                    srp_callback_parm.user =
                        SRP_VBASE_get_by_user(srp_callback_parm.vb,
                                              srp_callback_parm.login);
                    if (srp_callback_parm.user)
                        BIO_printf(bio_s_out, "LOOKUP done %s\n",
                                   srp_callback_parm.user->info);
                    else
                        BIO_printf(bio_s_out, "LOOKUP not successful\n");
                    i = SSL_read(con, (char *)buf, bufsize);
                }
#endif
                switch (SSL_get_error(con, i)) {
                case SSL_ERROR_NONE:
#ifdef CHARSET_EBCDIC
                    ascii2ebcdic(buf, buf, i);
#endif
                    raw_write_stdout(buf, (unsigned int)i);
                    if (SSL_pending(con))
                        goto again;
                    break;
                case SSL_ERROR_WANT_ASYNC:
                    BIO_printf(bio_s_out, "Read BLOCK (Async)\n");
                    wait_for_async(con);
                    break;
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                    BIO_printf(bio_s_out, "Read BLOCK\n");
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    BIO_printf(bio_s_out, "ERROR\n");
                    (void)BIO_flush(bio_s_out);
                    ERR_print_errors(bio_err);
                    ret = 1;
                    goto err;
                case SSL_ERROR_ZERO_RETURN:
                    BIO_printf(bio_s_out, "DONE\n");
                    (void)BIO_flush(bio_s_out);
                    ret = 1;
                    goto err;
                }
            }
        }
    }
 err:
    if (con != NULL) {
        BIO_printf(bio_s_out, "shutting down SSL\n");
        SSL_set_shutdown(con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(con);
    }
    BIO_printf(bio_s_out, "CONNECTION CLOSED\n");
    OPENSSL_clear_free(buf, bufsize);
    if (ret >= 0)
        BIO_printf(bio_s_out, "ACCEPT\n");
    (void)BIO_flush(bio_s_out);
    return (ret);
}

static void close_accept_socket(void)
{
    BIO_printf(bio_err, "shutdown accept socket\n");
    if (accept_socket >= 0) {
        SHUTDOWN2(accept_socket);
    }
}

static int init_ssl_connection(SSL *con)
{
    int i;
    const char *str;
    X509 *peer;
    long verify_err;
    char buf[BUFSIZ];
#if !defined(OPENSSL_NO_NEXTPROTONEG)
    const unsigned char *next_proto_neg;
    unsigned next_proto_neg_len;
#endif
    unsigned char *exportedkeymat;
    struct sockaddr_storage client;

#ifndef OPENSSL_NO_DTLS1
    if(dtlslisten) {
        i = DTLSv1_listen(con, &client);
        if (i > 0) {
            BIO *wbio;
            int fd = -1;

            wbio = SSL_get_wbio(con);
            if(wbio) {
                BIO_get_fd(wbio, &fd);
            }

            if(!wbio || connect(fd, (struct sockaddr *)&client,
                                sizeof(struct sockaddr_storage))) {
                BIO_printf(bio_err, "ERROR - unable to connect\n");
                return 0;
            }
            dtlslisten = 0;
            i = SSL_accept(con);
        }
    } else
#endif

    do {
        i = SSL_accept(con);

#ifdef CERT_CB_TEST_RETRY
        {
            while (i <= 0 && SSL_get_error(con, i) == SSL_ERROR_WANT_X509_LOOKUP
                    && SSL_get_state(con) == TLS_ST_SR_CLNT_HELLO) {
                BIO_printf(bio_err,
                       "LOOKUP from certificate callback during accept\n");
                i = SSL_accept(con);
            }
        }
#endif

#ifndef OPENSSL_NO_SRP
        while (i <= 0 && SSL_get_error(con, i) == SSL_ERROR_WANT_X509_LOOKUP) {
            BIO_printf(bio_s_out, "LOOKUP during accept %s\n",
                       srp_callback_parm.login);
            srp_callback_parm.user =
                SRP_VBASE_get_by_user(srp_callback_parm.vb,
                                      srp_callback_parm.login);
            if (srp_callback_parm.user)
                BIO_printf(bio_s_out, "LOOKUP done %s\n",
                           srp_callback_parm.user->info);
            else
                BIO_printf(bio_s_out, "LOOKUP not successful\n");
            i = SSL_accept(con);
        }
#endif
    } while (i < 0 && SSL_waiting_for_async(con));

    if (i <= 0) {
        if ((dtlslisten && i == 0)
                || (!dtlslisten && BIO_sock_should_retry(i))) {
            BIO_printf(bio_s_out, "DELAY\n");
            return (1);
        }

        BIO_printf(bio_err, "ERROR\n");

        verify_err = SSL_get_verify_result(con);
        if (verify_err != X509_V_OK) {
            BIO_printf(bio_err, "verify error:%s\n",
                       X509_verify_cert_error_string(verify_err));
        }
        /* Always print any error messages */
        ERR_print_errors(bio_err);
        return (0);
    }

    if (s_brief)
        print_ssl_summary(con);

    PEM_write_bio_SSL_SESSION(bio_s_out, SSL_get_session(con));

    peer = SSL_get_peer_certificate(con);
    if (peer != NULL) {
        BIO_printf(bio_s_out, "Client certificate\n");
        PEM_write_bio_X509(bio_s_out, peer);
        X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof buf);
        BIO_printf(bio_s_out, "subject=%s\n", buf);
        X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof buf);
        BIO_printf(bio_s_out, "issuer=%s\n", buf);
        X509_free(peer);
    }

    if (SSL_get_shared_ciphers(con, buf, sizeof buf) != NULL)
        BIO_printf(bio_s_out, "Shared ciphers:%s\n", buf);
    str = SSL_CIPHER_get_name(SSL_get_current_cipher(con));
    ssl_print_sigalgs(bio_s_out, con);
#ifndef OPENSSL_NO_EC
    ssl_print_point_formats(bio_s_out, con);
    ssl_print_curves(bio_s_out, con, 0);
#endif
    BIO_printf(bio_s_out, "CIPHER is %s\n", (str != NULL) ? str : "(NONE)");

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    SSL_get0_next_proto_negotiated(con, &next_proto_neg, &next_proto_neg_len);
    if (next_proto_neg) {
        BIO_printf(bio_s_out, "NEXTPROTO is ");
        BIO_write(bio_s_out, next_proto_neg, next_proto_neg_len);
        BIO_printf(bio_s_out, "\n");
    }
#endif
#ifndef OPENSSL_NO_SRTP
    {
        SRTP_PROTECTION_PROFILE *srtp_profile
            = SSL_get_selected_srtp_profile(con);

        if (srtp_profile)
            BIO_printf(bio_s_out, "SRTP Extension negotiated, profile=%s\n",
                       srtp_profile->name);
    }
#endif
    if (SSL_cache_hit(con))
        BIO_printf(bio_s_out, "Reused session-id\n");
    BIO_printf(bio_s_out, "Secure Renegotiation IS%s supported\n",
               SSL_get_secure_renegotiation_support(con) ? "" : " NOT");
    if (keymatexportlabel != NULL) {
        BIO_printf(bio_s_out, "Keying material exporter:\n");
        BIO_printf(bio_s_out, "    Label: '%s'\n", keymatexportlabel);
        BIO_printf(bio_s_out, "    Length: %i bytes\n", keymatexportlen);
        exportedkeymat = app_malloc(keymatexportlen, "export key");
        if (!SSL_export_keying_material(con, exportedkeymat,
                                        keymatexportlen,
                                        keymatexportlabel,
                                        strlen(keymatexportlabel),
                                        NULL, 0, 0)) {
            BIO_printf(bio_s_out, "    Error\n");
        } else {
            BIO_printf(bio_s_out, "    Keying material: ");
            for (i = 0; i < keymatexportlen; i++)
                BIO_printf(bio_s_out, "%02X", exportedkeymat[i]);
            BIO_printf(bio_s_out, "\n");
        }
        OPENSSL_free(exportedkeymat);
    }

    return (1);
}

#ifndef OPENSSL_NO_DH
static DH *load_dh_param(const char *dhfile)
{
    DH *ret = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(dhfile, "r")) == NULL)
        goto err;
    ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
 err:
    BIO_free(bio);
    return (ret);
}
#endif

static int www_body(char *hostname, int s, int stype, unsigned char *context)
{
    char *buf = NULL;
    int ret = 1;
    int i, j, k, dot;
    SSL *con;
    const SSL_CIPHER *c;
    BIO *io, *ssl_bio, *sbio;
#ifdef RENEG
    int total_bytes = 0;
#endif
    int width;
    fd_set readfds;

    /* Set width for a select call if needed */
    width = s + 1;

    buf = app_malloc(bufsize, "server www buffer");
    io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    if ((io == NULL) || (ssl_bio == NULL))
        goto err;

#ifdef FIONBIO
    if (s_nbio) {
        unsigned long sl = 1;

        if (!s_quiet)
            BIO_printf(bio_err, "turning on non blocking io\n");
        if (BIO_socket_ioctl(s, FIONBIO, &sl) < 0)
            ERR_print_errors(bio_err);
    }
#endif

    /* lets make the output buffer a reasonable size */
    if (!BIO_set_write_buffer_size(io, bufsize))
        goto err;

    if ((con = SSL_new(ctx)) == NULL)
        goto err;

    if (s_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_s_out);
    }

    if (context && !SSL_set_session_id_context(con, context,
                        strlen((char *)context)))
        goto err;

    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    if (s_nbio_test) {
        BIO *test;

        test = BIO_new(BIO_f_nbio_test());
        sbio = BIO_push(test, sbio);
    }
    SSL_set_bio(con, sbio, sbio);
    SSL_set_accept_state(con);

    /* SSL_set_fd(con,s); */
    BIO_set_ssl(ssl_bio, con, BIO_CLOSE);
    BIO_push(io, ssl_bio);
#ifdef CHARSET_EBCDIC
    io = BIO_push(BIO_new(BIO_f_ebcdic_filter()), io);
#endif

    if (s_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(SSL_get_rbio(con), bio_dump_callback);
        BIO_set_callback_arg(SSL_get_rbio(con), (char *)bio_s_out);
    }
    if (s_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (s_msg == 2)
            SSL_set_msg_callback(con, SSL_trace);
        else
#endif
            SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_s_msg ? bio_s_msg : bio_s_out);
    }

    for (;;) {
        i = BIO_gets(io, buf, bufsize - 1);
        if (i < 0) {            /* error */
            if (!BIO_should_retry(io) && !SSL_waiting_for_async(con)) {
                if (!s_quiet)
                    ERR_print_errors(bio_err);
                goto err;
            } else {
                BIO_printf(bio_s_out, "read R BLOCK\n");
#ifndef OPENSSL_NO_SRP
                if (BIO_should_io_special(io)
                    && BIO_get_retry_reason(io) == BIO_RR_SSL_X509_LOOKUP) {
                    BIO_printf(bio_s_out, "LOOKUP renego during read\n");
                    srp_callback_parm.user =
                        SRP_VBASE_get_by_user(srp_callback_parm.vb,
                                              srp_callback_parm.login);
                    if (srp_callback_parm.user)
                        BIO_printf(bio_s_out, "LOOKUP done %s\n",
                                   srp_callback_parm.user->info);
                    else
                        BIO_printf(bio_s_out, "LOOKUP not successful\n");
                    continue;
                }
#endif
#if defined(OPENSSL_SYS_NETWARE)
                delay(1000);
#elif !defined(OPENSSL_SYS_MSDOS)
                sleep(1);
#endif
                continue;
            }
        } else if (i == 0) {    /* end of input */
            ret = 1;
            goto end;
        }

        /* else we have data */
        if (((www == 1) && (strncmp("GET ", buf, 4) == 0)) ||
            ((www == 2) && (strncmp("GET /stats ", buf, 11) == 0))) {
            char *p;
            X509 *peer;
            STACK_OF(SSL_CIPHER) *sk;
            static const char *space = "                          ";

            if (www == 1 && strncmp("GET /reneg", buf, 10) == 0) {
                if (strncmp("GET /renegcert", buf, 14) == 0)
                    SSL_set_verify(con,
                                   SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                                   NULL);
                i = SSL_renegotiate(con);
                BIO_printf(bio_s_out, "SSL_renegotiate -> %d\n", i);
                /* Send the HelloRequest */
                i = SSL_do_handshake(con);
                if (i <= 0) {
                    BIO_printf(bio_s_out, "SSL_do_handshake() Retval %d\n",
                               SSL_get_error(con, i));
                    ERR_print_errors(bio_err);
                    goto err;
                }
                /* Wait for a ClientHello to come back */
                FD_ZERO(&readfds);
                openssl_fdset(s, &readfds);
                i = select(width, (void *)&readfds, NULL, NULL, NULL);
                if (i <= 0 || !FD_ISSET(s, &readfds)) {
                    BIO_printf(bio_s_out, "Error waiting for client response\n");
                    ERR_print_errors(bio_err);
                    goto err;
                }
                /*
                 * We're not acutally expecting any data here and we ignore
                 * any that is sent. This is just to force the handshake that
                 * we're expecting to come from the client. If they haven't
                 * sent one there's not much we can do.
                 */
                BIO_gets(io, buf, bufsize - 1);
            }

            BIO_puts(io,
                     "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
            BIO_puts(io, "<HTML><BODY BGCOLOR=\"#ffffff\">\n");
            BIO_puts(io, "<pre>\n");
/*                      BIO_puts(io,OpenSSL_version(OPENSSL_VERSION));*/
            BIO_puts(io, "\n");
            for (i = 0; i < local_argc; i++) {
                const char *myp;
                for (myp = local_argv[i]; *myp; myp++)
                    switch (*myp) {
                    case '<':
                        BIO_puts(io, "&lt;");
                        break;
                    case '>':
                        BIO_puts(io, "&gt;");
                        break;
                    case '&':
                        BIO_puts(io, "&amp;");
                        break;
                    default:
                        BIO_write(io, myp, 1);
                        break;
                    }
                BIO_write(io, " ", 1);
            }
            BIO_puts(io, "\n");

            BIO_printf(io,
                       "Secure Renegotiation IS%s supported\n",
                       SSL_get_secure_renegotiation_support(con) ?
                       "" : " NOT");

            /*
             * The following is evil and should not really be done
             */
            BIO_printf(io, "Ciphers supported in s_server binary\n");
            sk = SSL_get_ciphers(con);
            j = sk_SSL_CIPHER_num(sk);
            for (i = 0; i < j; i++) {
                c = sk_SSL_CIPHER_value(sk, i);
                BIO_printf(io, "%-11s:%-25s ",
                           SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
                if ((((i + 1) % 2) == 0) && (i + 1 != j))
                    BIO_puts(io, "\n");
            }
            BIO_puts(io, "\n");
            p = SSL_get_shared_ciphers(con, buf, bufsize);
            if (p != NULL) {
                BIO_printf(io,
                           "---\nCiphers common between both SSL end points:\n");
                j = i = 0;
                while (*p) {
                    if (*p == ':') {
                        BIO_write(io, space, 26 - j);
                        i++;
                        j = 0;
                        BIO_write(io, ((i % 3) ? " " : "\n"), 1);
                    } else {
                        BIO_write(io, p, 1);
                        j++;
                    }
                    p++;
                }
                BIO_puts(io, "\n");
            }
            ssl_print_sigalgs(io, con);
#ifndef OPENSSL_NO_EC
            ssl_print_curves(io, con, 0);
#endif
            BIO_printf(io, (SSL_cache_hit(con)
                            ? "---\nReused, " : "---\nNew, "));
            c = SSL_get_current_cipher(con);
            BIO_printf(io, "%s, Cipher is %s\n",
                       SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
            SSL_SESSION_print(io, SSL_get_session(con));
            BIO_printf(io, "---\n");
            print_stats(io, SSL_get_SSL_CTX(con));
            BIO_printf(io, "---\n");
            peer = SSL_get_peer_certificate(con);
            if (peer != NULL) {
                BIO_printf(io, "Client certificate\n");
                X509_print(io, peer);
                PEM_write_bio_X509(io, peer);
            } else
                BIO_puts(io, "no client certificate available\n");
            BIO_puts(io, "</BODY></HTML>\r\n\r\n");
            break;
        } else if ((www == 2 || www == 3)
                   && (strncmp("GET /", buf, 5) == 0)) {
            BIO *file;
            char *p, *e;
            static const char *text =
                "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n";

            /* skip the '/' */
            p = &(buf[5]);

            dot = 1;
            for (e = p; *e != '\0'; e++) {
                if (e[0] == ' ')
                    break;

                switch (dot) {
                case 1:
                    dot = (e[0] == '.') ? 2 : 0;
                    break;
                case 2:
                    dot = (e[0] == '.') ? 3 : 0;
                    break;
                case 3:
                    dot = (e[0] == '/') ? -1 : 0;
                    break;
                }
                if (dot == 0)
                    dot = (e[0] == '/') ? 1 : 0;
            }
            dot = (dot == 3) || (dot == -1); /* filename contains ".."
                                              * component */

            if (*e == '\0') {
                BIO_puts(io, text);
                BIO_printf(io, "'%s' is an invalid file name\r\n", p);
                break;
            }
            *e = '\0';

            if (dot) {
                BIO_puts(io, text);
                BIO_printf(io, "'%s' contains '..' reference\r\n", p);
                break;
            }

            if (*p == '/') {
                BIO_puts(io, text);
                BIO_printf(io, "'%s' is an invalid path\r\n", p);
                break;
            }

            /* if a directory, do the index thang */
            if (app_isdir(p) > 0) {
                BIO_puts(io, text);
                BIO_printf(io, "'%s' is a directory\r\n", p);
                break;
            }

            if ((file = BIO_new_file(p, "r")) == NULL) {
                BIO_puts(io, text);
                BIO_printf(io, "Error opening '%s'\r\n", p);
                ERR_print_errors(io);
                break;
            }

            if (!s_quiet)
                BIO_printf(bio_err, "FILE:%s\n", p);

            if (www == 2) {
                i = strlen(p);
                if (((i > 5) && (strcmp(&(p[i - 5]), ".html") == 0)) ||
                    ((i > 4) && (strcmp(&(p[i - 4]), ".php") == 0)) ||
                    ((i > 4) && (strcmp(&(p[i - 4]), ".htm") == 0)))
                    BIO_puts(io,
                             "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
                else
                    BIO_puts(io,
                             "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n");
            }
            /* send the file */
            for (;;) {
                i = BIO_read(file, buf, bufsize);
                if (i <= 0)
                    break;

#ifdef RENEG
                total_bytes += i;
                BIO_printf(bio_err, "%d\n", i);
                if (total_bytes > 3 * 1024) {
                    total_bytes = 0;
                    BIO_printf(bio_err, "RENEGOTIATE\n");
                    SSL_renegotiate(con);
                }
#endif

                for (j = 0; j < i;) {
#ifdef RENEG
                    {
                        static count = 0;
                        if (++count == 13) {
                            SSL_renegotiate(con);
                        }
                    }
#endif
                    k = BIO_write(io, &(buf[j]), i - j);
                    if (k <= 0) {
                        if (!BIO_should_retry(io)  && !SSL_waiting_for_async(con))
                            goto write_error;
                        else {
                            BIO_printf(bio_s_out, "rwrite W BLOCK\n");
                        }
                    } else {
                        j += k;
                    }
                }
            }
 write_error:
            BIO_free(file);
            break;
        }
    }

    for (;;) {
        i = (int)BIO_flush(io);
        if (i <= 0) {
            if (!BIO_should_retry(io))
                break;
        } else
            break;
    }
 end:
    /* make sure we re-use sessions */
    SSL_set_shutdown(con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

 err:
    if (ret >= 0)
        BIO_printf(bio_s_out, "ACCEPT\n");
    OPENSSL_free(buf);
    BIO_free_all(io);
    return (ret);
}

static int rev_body(char *hostname, int s, int stype, unsigned char *context)
{
    char *buf = NULL;
    int i;
    int ret = 1;
    SSL *con;
    BIO *io, *ssl_bio, *sbio;

    buf = app_malloc(bufsize, "server rev buffer");
    io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    if ((io == NULL) || (ssl_bio == NULL))
        goto err;

    /* lets make the output buffer a reasonable size */
    if (!BIO_set_write_buffer_size(io, bufsize))
        goto err;

    if ((con = SSL_new(ctx)) == NULL)
        goto err;

    if (s_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_s_out);
    }
    if (context && !SSL_set_session_id_context(con, context,
                        strlen((char *)context))) {
        ERR_print_errors(bio_err);
        goto err;
    }

    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(con, sbio, sbio);
    SSL_set_accept_state(con);

    BIO_set_ssl(ssl_bio, con, BIO_CLOSE);
    BIO_push(io, ssl_bio);
#ifdef CHARSET_EBCDIC
    io = BIO_push(BIO_new(BIO_f_ebcdic_filter()), io);
#endif

    if (s_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(SSL_get_rbio(con), bio_dump_callback);
        BIO_set_callback_arg(SSL_get_rbio(con), (char *)bio_s_out);
    }
    if (s_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (s_msg == 2)
            SSL_set_msg_callback(con, SSL_trace);
        else
#endif
            SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_s_msg ? bio_s_msg : bio_s_out);
    }

    for (;;) {
        i = BIO_do_handshake(io);
        if (i > 0)
            break;
        if (!BIO_should_retry(io)) {
            BIO_puts(bio_err, "CONNECTION FAILURE\n");
            ERR_print_errors(bio_err);
            goto end;
        }
#ifndef OPENSSL_NO_SRP
        if (BIO_should_io_special(io)
            && BIO_get_retry_reason(io) == BIO_RR_SSL_X509_LOOKUP) {
            BIO_printf(bio_s_out, "LOOKUP renego during accept\n");
            srp_callback_parm.user =
                SRP_VBASE_get_by_user(srp_callback_parm.vb,
                                      srp_callback_parm.login);
            if (srp_callback_parm.user)
                BIO_printf(bio_s_out, "LOOKUP done %s\n",
                           srp_callback_parm.user->info);
            else
                BIO_printf(bio_s_out, "LOOKUP not successful\n");
            continue;
        }
#endif
    }
    BIO_printf(bio_err, "CONNECTION ESTABLISHED\n");
    print_ssl_summary(con);

    for (;;) {
        i = BIO_gets(io, buf, bufsize - 1);
        if (i < 0) {            /* error */
            if (!BIO_should_retry(io)) {
                if (!s_quiet)
                    ERR_print_errors(bio_err);
                goto err;
            } else {
                BIO_printf(bio_s_out, "read R BLOCK\n");
#ifndef OPENSSL_NO_SRP
                if (BIO_should_io_special(io)
                    && BIO_get_retry_reason(io) == BIO_RR_SSL_X509_LOOKUP) {
                    BIO_printf(bio_s_out, "LOOKUP renego during read\n");
                    srp_callback_parm.user =
                        SRP_VBASE_get_by_user(srp_callback_parm.vb,
                                              srp_callback_parm.login);
                    if (srp_callback_parm.user)
                        BIO_printf(bio_s_out, "LOOKUP done %s\n",
                                   srp_callback_parm.user->info);
                    else
                        BIO_printf(bio_s_out, "LOOKUP not successful\n");
                    continue;
                }
#endif
#if defined(OPENSSL_SYS_NETWARE)
                delay(1000);
#elif !defined(OPENSSL_SYS_MSDOS)
                sleep(1);
#endif
                continue;
            }
        } else if (i == 0) {    /* end of input */
            ret = 1;
            BIO_printf(bio_err, "CONNECTION CLOSED\n");
            goto end;
        } else {
            char *p = buf + i - 1;
            while (i && (*p == '\n' || *p == '\r')) {
                p--;
                i--;
            }
            if (!s_ign_eof && (i == 5) && (strncmp(buf, "CLOSE", 5) == 0)) {
                ret = 1;
                BIO_printf(bio_err, "CONNECTION CLOSED\n");
                goto end;
            }
            BUF_reverse((unsigned char *)buf, NULL, i);
            buf[i] = '\n';
            BIO_write(io, buf, i + 1);
            for (;;) {
                i = BIO_flush(io);
                if (i > 0)
                    break;
                if (!BIO_should_retry(io))
                    goto end;
            }
        }
    }
 end:
    /* make sure we re-use sessions */
    SSL_set_shutdown(con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

 err:

    OPENSSL_free(buf);
    BIO_free_all(io);
    return (ret);
}

#ifndef OPENSSL_NO_RSA
static RSA *tmp_rsa_cb(SSL *s, int is_export, int keylength)
{
    BIGNUM *bn = NULL;
    static RSA *rsa_tmp = NULL;

    if (!rsa_tmp && ((bn = BN_new()) == NULL))
        BIO_printf(bio_err, "Allocation error in generating RSA key\n");
    if (!rsa_tmp && bn) {
        if (!s_quiet) {
            BIO_printf(bio_err, "Generating temp (%d bit) RSA key...",
                       keylength);
            (void)BIO_flush(bio_err);
        }
        if (!BN_set_word(bn, RSA_F4) || ((rsa_tmp = RSA_new()) == NULL) ||
            !RSA_generate_key_ex(rsa_tmp, keylength, bn, NULL)) {
            RSA_free(rsa_tmp);
            rsa_tmp = NULL;
        }
        if (!s_quiet) {
            BIO_printf(bio_err, "\n");
            (void)BIO_flush(bio_err);
        }
        BN_free(bn);
    }
    return (rsa_tmp);
}
#endif

#define MAX_SESSION_ID_ATTEMPTS 10
static int generate_session_id(const SSL *ssl, unsigned char *id,
                               unsigned int *id_len)
{
    unsigned int count = 0;
    do {
        if (RAND_bytes(id, *id_len) <= 0)
            return 0;
        /*
         * Prefix the session_id with the required prefix. NB: If our prefix
         * is too long, clip it - but there will be worse effects anyway, eg.
         * the server could only possibly create 1 session ID (ie. the
         * prefix!) so all future session negotiations will fail due to
         * conflicts.
         */
        memcpy(id, session_id_prefix,
               (strlen(session_id_prefix) < *id_len) ?
               strlen(session_id_prefix) : *id_len);
    }
    while (SSL_has_matching_session_id(ssl, id, *id_len) &&
           (++count < MAX_SESSION_ID_ATTEMPTS));
    if (count >= MAX_SESSION_ID_ATTEMPTS)
        return 0;
    return 1;
}

/*
 * By default s_server uses an in-memory cache which caches SSL_SESSION
 * structures without any serialisation. This hides some bugs which only
 * become apparent in deployed servers. By implementing a basic external
 * session cache some issues can be debugged using s_server.
 */

typedef struct simple_ssl_session_st {
    unsigned char *id;
    unsigned int idlen;
    unsigned char *der;
    int derlen;
    struct simple_ssl_session_st *next;
} simple_ssl_session;

static simple_ssl_session *first = NULL;

static int add_session(SSL *ssl, SSL_SESSION *session)
{
    simple_ssl_session *sess = app_malloc(sizeof(*sess), "get session");
    unsigned char *p;

    SSL_SESSION_get_id(session, &sess->idlen);
    sess->derlen = i2d_SSL_SESSION(session, NULL);
    if (sess->derlen < 0) {
        BIO_printf(bio_err, "Error encoding session\n");
        OPENSSL_free(sess);
        return 0;
    }

    sess->id = BUF_memdup(SSL_SESSION_get_id(session, NULL), sess->idlen);
    sess->der = app_malloc(sess->derlen, "get session buffer");
    if (!sess->id) {
        BIO_printf(bio_err, "Out of memory adding to external cache\n");
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        OPENSSL_free(sess);
        return 0;
    }
    p = sess->der;

    /* Assume it still works. */
    if (i2d_SSL_SESSION(session, &p) != sess->derlen) {
        BIO_printf(bio_err, "Unexpected session encoding length\n");
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        OPENSSL_free(sess);
        return 0;
    }

    sess->next = first;
    first = sess;
    BIO_printf(bio_err, "New session added to external cache\n");
    return 0;
}

static SSL_SESSION *get_session(SSL *ssl, unsigned char *id, int idlen,
                                int *do_copy)
{
    simple_ssl_session *sess;
    *do_copy = 0;
    for (sess = first; sess; sess = sess->next) {
        if (idlen == (int)sess->idlen && !memcmp(sess->id, id, idlen)) {
            const unsigned char *p = sess->der;
            BIO_printf(bio_err, "Lookup session: cache hit\n");
            return d2i_SSL_SESSION(NULL, &p, sess->derlen);
        }
    }
    BIO_printf(bio_err, "Lookup session: cache miss\n");
    return NULL;
}

static void del_session(SSL_CTX *sctx, SSL_SESSION *session)
{
    simple_ssl_session *sess, *prev = NULL;
    const unsigned char *id;
    unsigned int idlen;
    id = SSL_SESSION_get_id(session, &idlen);
    for (sess = first; sess; sess = sess->next) {
        if (idlen == sess->idlen && !memcmp(sess->id, id, idlen)) {
            if (prev)
                prev->next = sess->next;
            else
                first = sess->next;
            OPENSSL_free(sess->id);
            OPENSSL_free(sess->der);
            OPENSSL_free(sess);
            return;
        }
        prev = sess;
    }
}

static void init_session_cache_ctx(SSL_CTX *sctx)
{
    SSL_CTX_set_session_cache_mode(sctx,
                                   SSL_SESS_CACHE_NO_INTERNAL |
                                   SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_new_cb(sctx, add_session);
    SSL_CTX_sess_set_get_cb(sctx, get_session);
    SSL_CTX_sess_set_remove_cb(sctx, del_session);
}

static void free_sessions(void)
{
    simple_ssl_session *sess, *tsess;
    for (sess = first; sess;) {
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        tsess = sess;
        sess = sess->next;
        OPENSSL_free(tsess);
    }
    first = NULL;
}
