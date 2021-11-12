/*
 * Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>

#include <openssl/asn1t.h>
#include <openssl/http.h>

#include <openssl/cmp.h>
#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cmp.h>
#include <openssl/err.h>

#define DEFAULT_RETRY_AFTER 60 /* one minute */

static int keep_alive(int keep_alive, int body_type, BIO *bio)
{
    if (keep_alive != 0 && bio == NULL
        /* Ask for persistent connection only if may need more round trips */
            && body_type != OSSL_CMP_PKIBODY_IR
            && body_type != OSSL_CMP_PKIBODY_CR
            && body_type != OSSL_CMP_PKIBODY_P10CR
            && body_type != OSSL_CMP_PKIBODY_KUR
            && body_type != OSSL_CMP_PKIBODY_POLLREQ)
        keep_alive = 0;
    return keep_alive >= 2 ? OSSL_HTTP_FLAG_REQUIRE_KEEP_ALIVE :
        keep_alive == 1 ? OSSL_HTTP_FLAG_ENABLE_KEEP_ALIVE : 0;
}

/*
 * Send the PKIMessage req and on success return the response, else NULL.
 * Any previous error queue entries will likely be removed by ERR_clear_error().
 */
OSSL_CMP_MSG *OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx,
                                        const OSSL_CMP_MSG *req)
{
    char server_port[32] = { '\0' };
    STACK_OF(CONF_VALUE) *headers = NULL;
    int tls_used;
    const ASN1_ITEM *it = ASN1_ITEM_rptr(OSSL_CMP_MSG);
    const char content_type_pkix[] = "application/pkixcmp";
    int flags = OSSL_HTTP_FLAG_ENABLE_RETRY | OSSL_HTTP_FLAG_EXPECT_ASN1;
    BIO *rsp, *bio;
    OSSL_CMP_MSG *res = NULL;

    if (ctx == NULL || req == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    if (!X509V3_add_value("Pragma", "no-cache", &headers))
        return NULL;

    bio = OSSL_CMP_CTX_get_transfer_cb_arg(ctx);
    if (ctx->serverPort != 0)
        BIO_snprintf(server_port, sizeof(server_port), "%d", ctx->serverPort);
    tls_used = OSSL_CMP_CTX_get_http_cb_arg(ctx) != NULL;
    if (ctx->http_ctx == NULL) {
        const char *path = ctx->serverPath;

        if (path == NULL)
            path = "";
        if (*path == '/')
            path++;
        if (bio == NULL)
            ossl_cmp_log4(DEBUG, ctx, "connecting to CMP server %s:%s%s; will use HTTP path \"/%s\"",
                          ctx->server, server_port,
                          tls_used ? " using TLS" : "", path);
        else
            ossl_cmp_log1(DEBUG, ctx,
                          "contacting CMP server via existing connection; will use HTTP path \"/%s\"",
                          path);
    }

    flags |= keep_alive(ctx->keep_alive, req->body->type, bio);
    rsp = OSSL_HTTP_transfer_ex(&ctx->http_ctx, ctx->server, server_port,
                                ctx->serverPath, tls_used,
                                ctx->proxy, ctx->no_proxy,
                                bio, bio /* rbio */, ctx->http_cb,
                                OSSL_CMP_CTX_get_http_cb_arg(ctx),
                                0 /* buf_size */, headers,
                                content_type_pkix, NULL, NULL, 0,
                                (const ASN1_VALUE *)req, it, content_type_pkix,
                                flags, OSSL_HTTP_DEFAULT_MAX_RESP_LEN,
                                DEFAULT_RETRY_AFTER, ctx->msg_timeout);
    res = (OSSL_CMP_MSG *)ASN1_item_d2i_bio(it, rsp, NULL);
    BIO_free(rsp);

    if (ctx->http_ctx == NULL)
        ossl_cmp_debug(ctx, "disconnected from CMP server");
    /*
     * Note that on normal successful end of the transaction the
     * HTTP connection is not closed at this level if keep_alive() != 0.
     * It should be closed by the CMP client application
     * using OSSL_CMP_CTX_free() or OSSL_CMP_CTX_reinit().
     * Note that any pre-existing bio (== ctx->transfer_cb_arg) is not freed.
     */
    if (res != NULL)
        ossl_cmp_debug(ctx, "finished reading response from CMP server");
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    return res;
}
