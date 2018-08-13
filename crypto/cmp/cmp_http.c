/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "e_os.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <ctype.h>
#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "cmp_int.h"

#ifndef OPENSSL_NO_SOCK

/* from apps.h */
# ifndef openssl_fdset
#  ifdef OPENSSL_SYSNAME_WIN32
#   define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#  else
#   define openssl_fdset(a,b) FD_SET(a, b)
#  endif
# endif

/*
 * TODO dvo: push generic defs upstream with extended load_cert_crl_http(),
 * simplifying also other uses, e.g., in query_responder() in apps/ocsp.c
 */

/*
 * TODO dvo: push that upstream with extended load_cert_crl_http(),
 * simplifying also other uses of select(), e.g., in query_responder()
 * in apps/ocsp.c
 */
/* returns < 0 on error, 0 on timeout, > 0 on success */
static int socket_wait(int fd, int for_read, int timeout)
{
    fd_set confds;
    struct timeval tv;

    if (timeout <= 0)
        return 0;

    FD_ZERO(&confds);
    openssl_fdset(fd, &confds);
    tv.tv_usec = 0;
    tv.tv_sec = timeout;
    return select(fd + 1, for_read ? &confds : NULL,
                  for_read ? NULL : &confds, NULL, &tv);
}

/*
 * TODO dvo: push that upstream with extended load_cert_crl_http(),
 * simplifying also other uses of select(), e.g., in query_responder()
 * in apps/ocsp.c
 */
/* returns < 0 on error, 0 on timeout, > 0 on success */
static int bio_wait(BIO *bio, int timeout) {
    int fd;
    if (BIO_get_fd(bio, &fd) <= 0)
        return -1;
    return socket_wait(fd, BIO_should_read(bio), timeout);
}

/*
 * TODO dvo: push that upstream with extended load_cert_crl_http(),
 * simplifying also other uses of connect(), e.g., in query_responder()
 * in apps/ocsp.c
 */
/* returns -1 on error, 0 on timeout, 1 on success */
static int bio_connect(BIO *bio, int timeout) {
    int blocking;
    time_t max_time;
    int rv;
    blocking = timeout <= 0;
    max_time = timeout > 0 ? time(NULL) + timeout : 0;

/* https://www.openssl.org/docs/man1.1.0/crypto/BIO_should_io_special.html */
    if (!blocking)
        BIO_set_nbio(bio, 1);
 retry: /* it does not help here to set SSL_MODE_AUTO_RETRY */
    rv = BIO_do_connect(bio); /* This indirectly calls ERR_clear_error(); */
    /*
     * in blocking case, despite blocking BIO, BIO_do_connect() timed out
     * when non-blocking, BIO_do_connect() timed out early
     * with rv == -1 and errno == 0
     */
    if (rv <= 0 && (errno == ETIMEDOUT ||
                    ERR_GET_REASON(ERR_peek_error()) == ETIMEDOUT)) {
        ERR_clear_error();
        (void)BIO_reset(bio);
        /*
         * otherwise, blocking next connect() may crash and
         * non-blocking next BIO_do_connect() will fail
         */
        goto retry;
    }
    if (rv <= 0 && BIO_should_retry(bio)) {
        if (blocking || (rv = bio_wait(bio, (int)(max_time - time(NULL)))) > 0)
            goto retry;
    }
    return rv;
}

#endif /* OPENSSL_NO_SOCK */



#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)

/*
 * TODO dvo: push that upstream with extended load_cert_crl_http(),
 * simplifying also other uses of XXX_sendreq_nbio, e.g., in query_responder()
 * in apps/ocsp.c
 */
typedef int (*http_fn)(OCSP_REQ_CTX *rctx,ASN1_VALUE **resp);
/*
 * Even better would be to extend OCSP_REQ_CTX_nbio() and
 * thus OCSP_REQ_CTX_nbio_d2i() to include this retry behavior */
/*
 * Exchange ASN.1 request and response via HTTP on any BIO
 * returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
 * 1: success and then provides the received message via the *resp argument
 */
static int bio_http(BIO *bio/* could be removed if we could access rctx->io */,
                    OCSP_REQ_CTX *rctx, http_fn fn, ASN1_VALUE **resp,
                    time_t max_time)
{
    int rv = -4, rc, sending = 1;
    int blocking = max_time == 0;
    ASN1_VALUE *const pattern = (ASN1_VALUE *)-1;

    *resp = pattern; /* used for detecting parse errors */
    do {
        rc = (*fn)(rctx, resp);
        if (rc != -1) {
            if (rc == 0) { /* an error occurred */
                if (sending && !blocking)
                    rv = -3; /* send error */
                else {
                    if (*resp == pattern)
                        rv = -2;/* receive error */
                    else
                        rv = -1; /* parse error */
                }
                *resp = NULL;
            }
            break;
        }
        /* else BIO_should_retry was true */
        sending = 0;
        if (!blocking) {
            rv = bio_wait(bio, (int)(max_time - time(NULL)));
            if (rv <= 0) { /* error or timeout */
                if (rv < 0) /* error */
                    rv = -4;
                *resp = NULL;
                break;
            }
        }
    } while (rc == -1); /* BIO_should_retry was true */

    return rv;
}

/* one declaration and three defines copied from ocsp_ht.c; keep in sync! */
/* dummy declaration to get access to internal state variable */
struct ocsp_req_ctx_st {
    int state;                  /* Current I/O state */
    unsigned char *iobuf;       /* Line buffer */
    int iobuflen;               /* Line buffer length */
    BIO *io;                    /* BIO to perform I/O with */
    BIO *mem;                   /* Memory BIO response is built into */
};
# define OHS_NOREAD              0x1000
# define OHS_ASN1_WRITE_INIT     (5 | OHS_NOREAD)

/*
 * adapted from OCSP_REQ_CTX_i2d in crypto/ocsp/ocsp_ht.c -
 * TODO: generalize the function there
 */
static int OCSP_REQ_CTX_i2d_hdr(OCSP_REQ_CTX *rctx, const char *req_hdr,
                                const ASN1_ITEM *it, ASN1_VALUE *val)
{
    int reqlen = ASN1_item_i2d(val, NULL, it);
    if (BIO_printf(rctx->mem, req_hdr, reqlen) <= 0)
        return 0;
    if (ASN1_item_i2d_bio(it, rctx->mem, val) <= 0)
        return 0;
    rctx->state = OHS_ASN1_WRITE_INIT;
    return 1;
}



static void add_conn_error_hint(const OSSL_CMP_CTX *ctx, unsigned long errdetail)
{
    char buf[200];
    snprintf(buf, 200, "connecting to '%s' port %d", ctx->serverName,
             ctx->serverPort);
    OSSL_CMP_add_error_data(buf);
    if (errdetail == 0) {
        snprintf(buf, 200, "server has disconnected%s",
                 ctx->http_cb_arg != NULL ? " violating the protocol" :
                               ", likely because it requires the use of TLS");
        OSSL_CMP_add_error_data(buf);
    }
}

/*
 * internal function
 * Create a new http connection, with a specified source ip/interface
 * returns the created BIO or NULL on failure
 */
static BIO *CMP_new_http_bio(const OSSL_CMP_CTX *ctx)
{
    char *host;
    int port;
    BIO *cbio = NULL;
    char buf[32];

    if (ctx == NULL)
        goto end;

    host = ctx->proxyName;
    port = ctx->proxyPort;
    if (host == NULL || port == 0) {
        host = ctx->serverName;
        port = ctx->serverPort;
    }
    cbio = BIO_new_connect(host);
    if (cbio == NULL)
        goto end;
    snprintf(buf, sizeof(buf), "%d", port);
    (void)BIO_set_conn_port(cbio, buf);

 end:
    return cbio;
}

static OCSP_REQ_CTX *CMP_sendreq_new(BIO *io, const char *path,
                                     const OSSL_CMP_MSG *req, int maxline)
{
    static const char req_hdr[] =
        "Content-Type: application/pkixcmp\r\n"
        "Cache-Control: no-cache\r\n" "Content-Length: %d\r\n\r\n";
    OCSP_REQ_CTX *rctx = NULL;

    rctx = OCSP_REQ_CTX_new(io, maxline);
    if (rctx == NULL)
        return NULL;

    if (!OCSP_REQ_CTX_http(rctx, "POST", path))
        goto err;

    if (req != NULL && !OCSP_REQ_CTX_i2d_hdr(rctx, req_hdr,
                                             ASN1_ITEM_rptr(OSSL_CMP_MSG),
                                             (ASN1_VALUE *)req))
        goto err;

    return rctx;

 err:
    OCSP_REQ_CTX_free(rctx);
    return NULL;
}

/*
 * Exchange CMP request/response via HTTP on (non-)blocking BIO
 * returns 1 on success, 0 on error, -1 on BIO_should_retry
 */
static int CMP_http_nbio(OCSP_REQ_CTX *rctx, ASN1_VALUE **resp)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx, resp, ASN1_ITEM_rptr(OSSL_CMP_MSG));
}

/*
 * Send out CMP request and get response on blocking or non-blocking BIO
 * returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
 * 1: success and then provides the received message via the *resp argument
 */
static int CMP_sendreq(BIO *bio, const char *path, const OSSL_CMP_MSG *req,
                       OSSL_CMP_MSG **resp, time_t max_time)
{
    OCSP_REQ_CTX *rctx;
    int rv;

    if ((rctx = CMP_sendreq_new(bio, path, req, -1)) == NULL)
        return -4;

    rv = bio_http(bio, rctx, CMP_http_nbio, (ASN1_VALUE **)resp, max_time);
 /* This indirectly calls ERR_clear_error(); */

    OCSP_REQ_CTX_free(rctx);

    return rv;
}

/*
 * Send the PKIMessage req and on success place the response in *res.
 * Any previous error is likely to be removed by ERR_clear_error().
 * returns 0 on success, else a CMP error reason code defined in cmp.h
 */
int OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req,
                              OSSL_CMP_MSG **res)
{
    int rv;
    char *path = NULL;
    size_t pos = 0, pathlen = 0;
    BIO *bio, *hbio = NULL;
    int err = ERR_R_MALLOC_FAILURE;
    time_t max_time;

    if (ctx == NULL || req == NULL || res == NULL ||
        ctx->serverName == NULL || ctx->serverPath == NULL || !ctx->serverPort)
        return CMP_R_NULL_ARGUMENT;

    max_time = ctx->msgtimeout > 0 ? time(NULL) + ctx->msgtimeout : 0;

    if ((hbio = CMP_new_http_bio(ctx)) == NULL)
        goto err;
    if (ctx->http_cb != NULL) {
        if ((bio = (*ctx->http_cb)(ctx, hbio, 1)) == NULL)
            goto err;
        hbio = bio;
    }

    /* TODO: it looks like bio_connect() is superflous except for maybe 
       better error/timeout handling and reporting? Remove next 9 lines? */
    /* tentatively set error, which allows accumulating diagnostic info */
    (void)ERR_set_mark();
    CMPerr(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM, CMP_R_ERROR_CONNECTING);
    rv = bio_connect(hbio, ctx->msgtimeout);
    if (rv <= 0) {
        err = (rv == 0) ? CMP_R_CONNECT_TIMEOUT : CMP_R_ERROR_CONNECTING;
        goto err;
    } else
        (void)ERR_pop_to_mark(); /* discard diagnostic info */

    pathlen = strlen(ctx->serverName) + strlen(ctx->serverPath) + 33;
    path = (char *)OPENSSL_malloc(pathlen);
    if (path == NULL)
        goto err;

    /*
     * Section 5.1.2 of RFC 1945 states that the absoluteURI form is only
     * allowed when using a proxy
     */
    if (ctx->proxyName != NULL && ctx->proxyPort != 0)
        pos = BIO_snprintf(path, pathlen-1, "http://%s:%d",
                           ctx->serverName, ctx->serverPort);

    /* make sure path includes a forward slash */
    if (ctx->serverPath[0] != '/')
        path[pos++] = '/';

    BIO_snprintf(path + pos, pathlen - pos - 1, "%s", ctx->serverPath);

    rv = CMP_sendreq(hbio, path, req, res, max_time);
    OPENSSL_free(path);
    if (rv == -3)
        err = CMP_R_FAILED_TO_SEND_REQUEST;
    else if (rv == -2)
        err = CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE;
    else if (rv == -1)
        err = CMP_R_ERROR_DECODING_MESSAGE;
    else if (rv == 0) { /* timeout */
        err = CMP_R_READ_TIMEOUT;
    } else
        err = 0;

 err:
    /* for any cert verify error at TLS level: */
    put_cert_verify_err(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM);

    if (err != 0) {
        if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL)
            err = CMP_R_TLS_ERROR;
        CMPerr(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM, err);
        if (err == CMP_R_TLS_ERROR || err == CMP_R_CONNECT_TIMEOUT
                                   || err == CMP_R_ERROR_CONNECTING)
            add_conn_error_hint(ctx, ERR_peek_error());
    }

    if (ctx->http_cb && (*ctx->http_cb)(ctx, hbio, ERR_peek_error()) == NULL)
        err = ERR_R_MALLOC_FAILURE;
    BIO_free_all(hbio); /* also frees any (e.g., SSL/TLS) BIOs linked with hbio
       and, like BIO_reset(hbio), calls SSL_shutdown() to notify/alert peer */

    return err;
}

/* TODO DvO push that upstream as a separate PR #crls_timeout_local */
/* adapted from apps/apps.c to include connection timeout */
int OSSL_CMP_load_cert_crl_http_timeout(const char *url, int req_timeout,
                                        X509 **pcert, X509_CRL **pcrl,
                                        BIO *bio_err)
{
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    BIO *bio = NULL;
    OCSP_REQ_CTX *rctx = NULL;
    int use_ssl;
    int rv = 0;
    time_t max_time = req_timeout > 0 ? time(NULL) + req_timeout : 0;

    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        BIO_puts(bio_err, "https not supported for CRL fetching\n");
        goto err;
    }
    bio = BIO_new_connect(host);
    if (bio == NULL || !BIO_set_conn_port(bio, port))
        goto err;

    if (bio_connect(bio, req_timeout) <= 0)
        goto err;

    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (rctx == NULL)
        goto err;
    if (!OCSP_REQ_CTX_http(rctx, "GET", path))
        goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "Host", host))
        goto err;

    rv = bio_http(bio, rctx,
         pcert != NULL ? (http_fn)X509_http_nbio : (http_fn)X509_CRL_http_nbio,
         pcert != NULL ? (ASN1_VALUE **)pcert : (ASN1_VALUE **)pcrl, max_time);

 err:
    OPENSSL_free(host);
    OPENSSL_free(path);
    OPENSSL_free(port);
    BIO_free_all(bio);
    OCSP_REQ_CTX_free(rctx);
    if (rv != 1) {
        BIO_printf(bio_err, "%s loading %s from '%s'\n",
                   rv == 0 ? "timeout" : rv == -1 ?
                           "parse Error" : "transfer error",
                   pcert != NULL ? "certificate" : "CRL", url);
        ERR_print_errors(bio_err);
    }
    return rv;
}

#endif /* !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK) */
