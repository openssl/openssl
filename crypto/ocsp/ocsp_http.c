/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
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

int OCSP_REQ_CTX_set1_req(OCSP_REQ_CTX *rctx, const OCSP_REQUEST *req)
{
    return OCSP_REQ_CTX_i2d(rctx, "application/ocsp-request",
                            ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE *)req);
}

OCSP_REQ_CTX *OCSP_sendreq_new(BIO *io, const char *path, OCSP_REQUEST *req,
                               int maxline)
{
    BIO *req_mem = HTTP_asn1_item2bio(ASN1_ITEM_rptr(OCSP_REQUEST),
                                      (ASN1_VALUE *)req);
    OCSP_REQ_CTX *res =
        HTTP_REQ_CTX_new(io, io, 0 /* no HTTP proxy used */, NULL, NULL, path,
                         NULL /* headers */, "application/ocsp-request",
                         req_mem /* may be NULL */,
                         maxline, 0 /* default max_resp_len */,
                         0 /* no timeout, blocking indefinite */, NULL,
                         1 /* expect_asn1 */);
    BIO_free(req_mem);
    return res;
}

# ifndef OPENSSL_NO_SOCK
int OCSP_sendreq_nbio(OCSP_RESPONSE **presp, OCSP_REQ_CTX *rctx)
{
    *presp = (OCSP_RESPONSE *)
        OCSP_REQ_CTX_nbio_d2i(rctx, ASN1_ITEM_rptr(OCSP_RESPONSE));
    return *presp != NULL;
}

OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req)
{
    OCSP_RESPONSE *resp = NULL;
    OCSP_REQ_CTX *ctx;
    int rv;

    ctx = OCSP_sendreq_new(b, path, req, -1 /* default max resp line length */);
    if (ctx == NULL)
        return NULL;

    rv = OCSP_sendreq_nbio(&resp, ctx);

    /* this indirectly calls ERR_clear_error(): */
    OCSP_REQ_CTX_free(ctx);

    return rv == 1 ? resp : NULL;
}
# endif /* !defined(OPENSSL_NO_SOCK) */

#endif /* !defined(OPENSSL_NO_OCSP) */
