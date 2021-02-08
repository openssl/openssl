/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ocsp.h>
#include <openssl/http.h>
#include "../http/http_local.h"

#ifndef OPENSSL_NO_OCSP

OSSL_HTTP_REQ_CTX *OCSP_sendreq_new(BIO *io, const char *path,
                                    const OCSP_REQUEST *req, int maxline)
{
    OSSL_HTTP_REQ_CTX *rctx = NULL;

    if ((rctx = OSSL_HTTP_REQ_CTX_new(io, io, 1 /* POST */,
                                      maxline, 0 /* default max_resp_len */,
                                      0 /* no timeout, blocking indefinitely */,
                                      NULL, 1 /* expect_asn1 */)) == NULL)
        return NULL;

    if (!OSSL_HTTP_REQ_CTX_set_request_line(rctx, NULL, NULL, path))
        goto err;

    if (req != NULL && !OSSL_HTTP_REQ_CTX_i2d(rctx, "application/ocsp-request",
                                              ASN1_ITEM_rptr(OCSP_REQUEST),
                                              (ASN1_VALUE *)req))
        goto err;

    return rctx;

 err:
    OSSL_HTTP_REQ_CTX_free(rctx);
    return NULL;
}

int OCSP_sendreq_nbio(OCSP_RESPONSE **presp, OSSL_HTTP_REQ_CTX *rctx)
{
    *presp = (OCSP_RESPONSE *)
        OSSL_HTTP_REQ_CTX_sendreq_d2i(rctx, ASN1_ITEM_rptr(OCSP_RESPONSE));
    return *presp != NULL;
}

OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req)
{
    OCSP_RESPONSE *resp = NULL;
    OSSL_HTTP_REQ_CTX *ctx;
    int rv;

    ctx = OCSP_sendreq_new(b, path, req, -1 /* default max resp line length */);
    if (ctx == NULL)
        return NULL;

    rv = OCSP_sendreq_nbio(&resp, ctx);

    /* this indirectly calls ERR_clear_error(): */
    OSSL_HTTP_REQ_CTX_free(ctx);

    return rv == 1 ? resp : NULL;
}
#endif /* !defined(OPENSSL_NO_OCSP) */
