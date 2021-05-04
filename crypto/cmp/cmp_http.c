/*
 * Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/sockets.h"

#include "openssl/cmp.h"
#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cmp.h>
#include <openssl/err.h>

/*
 * Send the PKIMessage req and on success return the response, else NULL.
 * Any previous error queue entries will likely be removed by ERR_clear_error().
 */
OSSL_CMP_MSG *OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx,
                                        const OSSL_CMP_MSG *req)
{
    char server_port[32] = { '\0' };
    STACK_OF(CONF_VALUE) *headers = NULL;
    const char content_type_pkix[] = "application/pkixcmp";
    int tls_used;
    const ASN1_ITEM *it = ASN1_ITEM_rptr(OSSL_CMP_MSG);
    BIO *req_mem, *rsp;
    OSSL_CMP_MSG *res = NULL;

    if (ctx == NULL || req == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    if (!X509V3_add_value("Pragma", "no-cache", &headers))
        return NULL;
    if ((req_mem = ASN1_item_i2d_mem_bio(it, (const ASN1_VALUE *)req)) == NULL)
        goto err;

    if (ctx->serverPort != 0)
        BIO_snprintf(server_port, sizeof(server_port), "%d", ctx->serverPort);

    tls_used = OSSL_CMP_CTX_get_http_cb_arg(ctx) != NULL;
    ossl_cmp_log2(DEBUG, ctx, "connecting to CMP server %s%s",
                  ctx->server, tls_used ? " using TLS" : "");
    rsp = OSSL_HTTP_transfer(NULL, ctx->server, server_port,
                             ctx->serverPath, tls_used,
                             ctx->proxy, ctx->no_proxy,
                             NULL /* bio */, NULL /* rbio */,
                             ctx->http_cb, OSSL_CMP_CTX_get_http_cb_arg(ctx),
                             0 /* buf_size */, headers,
                             content_type_pkix, req_mem,
                             content_type_pkix, 1 /* expect_asn1 */,
                             HTTP_DEFAULT_MAX_RESP_LEN,
                             ctx->msg_timeout, 0 /* keep_alive */);
    BIO_free(req_mem);
    res = (OSSL_CMP_MSG *)ASN1_item_d2i_bio(it, rsp, NULL);
    BIO_free(rsp);
    ossl_cmp_debug(ctx, "disconnected from CMP server");
 err:
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    return res;
}
