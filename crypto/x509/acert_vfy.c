/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

#include "crypto/ctype.h"
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/core_names.h>
#include "internal/dane.h"
#include "crypto/x509.h"
#include "x509_local.h"
#include "crypto/x509_acert.h"
#include "openssl/x509_acert.h"

/*-
 * Check attribute certificate validity times.
 */
int ossl_x509_check_acert_time(X509_STORE_CTX *ctx, X509_ACERT *acert)
{
    time_t *ptime;
    int i;

    if ((ctx->param->flags & X509_V_FLAG_USE_CHECK_TIME) != 0)
        ptime = &ctx->param->check_time;
    else if ((ctx->param->flags & X509_V_FLAG_NO_CHECK_TIME) != 0)
        return X509_V_OK;
    else
        ptime = NULL;

    i = X509_cmp_time(X509_ACERT_get0_notBefore(acert), ptime);
    if (i == 0)
        return X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
    if (i > 0)
        return X509_V_ERR_CERT_NOT_YET_VALID;

    i = X509_cmp_time(X509_ACERT_get0_notAfter(acert), ptime);
    if (i == 0)
        return X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
    if (i < 0)
        return X509_V_ERR_CERT_HAS_EXPIRED;

    return X509_V_OK;
}

int ossl_x509_check_acert_exts(X509_ACERT *acert)
{
    int i;
    X509_EXTENSION *current_ext;
    int n = X509_acert_get_ext_count(acert);

    for (i = 0; i < n; i++) {
        current_ext = X509_acert_get_ext(acert, i);
        if (current_ext == NULL)
            break;
        if (current_ext->critical)
            /* All extensions for attribute certificates not validated. Those
            for public-key certs are not applicable. */
            return X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION;
    }
    return X509_V_OK;
}

int X509_attr_cert_verify(X509_STORE_CTX *ctx, X509_ACERT *acert)
{
    int rc;
    EVP_PKEY *pkey;
    X509 *subj_pkc;

    if (X509_ALGOR_cmp(&acert->sig_alg, &acert->acinfo->signature) != 0)
        return 0;
    rc = X509_STORE_CTX_verify(ctx);
    if (rc != X509_V_OK)
        return rc;
    if (sk_X509_num(ctx->chain) <= 0)
        return 0;
    subj_pkc = sk_X509_value(ctx->chain, 0);
    if ((pkey = X509_get0_pubkey(subj_pkc)) == NULL)
        return X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
    rc = ASN1_item_verify(ASN1_ITEM_rptr(X509_ACERT), &acert->sig_alg,
                           &acert->signature, &acert->acinfo, pkey);
    if (rc != 1)
        return X509_V_ERR_CERT_SIGNATURE_FAILURE;

    rc = ossl_x509_check_acert_time(ctx, acert);
    if (rc != X509_V_OK)
        return rc;

    rc = ossl_x509_check_acert_exts(acert);
    if (rc != X509_V_OK)
        return rc;

    return X509_V_OK;
}

/*-
 * Inform the verify callback of an error, CRL-specific variant.  Here, the
 * error depth and certificate are already set, we just specify the error
 * number.
 *
 * Returns 0 to abort verification with an error, non-zero to continue.
 */
static int verify_cb_crl(X509_STORE_CTX *ctx, int err)
{
    ctx->error = err;
    return ctx->verify_cb(0, ctx);
}

int acert_crl(X509_STORE_CTX *ctx, X509_CRL *crl, X509_ACERT *x)
{
    X509_REVOKED *rev;

    /*
     * The rules changed for this... previously if a CRL contained unhandled
     * critical extensions it could still be used to indicate a certificate
     * was revoked. This has since been changed since critical extensions can
     * change the meaning of CRL entries.
     */
    if ((ctx->param->flags & X509_V_FLAG_IGNORE_CRITICAL) == 0
        && (crl->flags & EXFLAG_CRITICAL) != 0 &&
        !verify_cb_crl(ctx, X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION))
        return 0;
    /*
     * Look for serial number of certificate in CRL.  If found, make sure
     * reason is not removeFromCRL.
     */
    if (X509_CRL_get0_by_serial(crl, &rev, &x->acinfo->serialNumber)) {
        if (rev->reason == CRL_REASON_REMOVE_FROM_CRL)
            return 2;
        if (!verify_cb_crl(ctx, X509_V_ERR_CERT_REVOKED))
            return 0;
    }

    return 1;
}