/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Revocation checking for proof verification: a certificate is checked
 * against a CRL from its issuer held by the trust store, verified with a key
 * the caller supplies.  Delta, indirect and reason-scoped CRLs are not used,
 * and there is no verification callback: a failing check sets ctx->error and
 * fails.
 */

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include "crypto/x509.h"
#include "crypto/proof.h"

/*
 * Whether crl is one proof verification uses: a complete CRL, not indirect,
 * not scoped to reason codes, with a valid issuing distribution point and no
 * unhandled critical extension.
 */
static int crl_usable(const X509_CRL *crl)
{
    return (crl->idp_flags & (IDP_INVALID | IDP_INDIRECT | IDP_REASONS)) == 0
        && crl->base_crl_number == NULL
        && (crl->flags & EXFLAG_CRITICAL) == 0;
}

/*
 * Find a CRL for x, issued under the name x carries as its issuer and
 * covering x (a partitioned CRL only through a distribution point x names),
 * among the usable CRLs the store looks up by that name; among candidates one
 * currently valid is preferred.  Returns a new reference to the CRL, or NULL
 * if there is none.
 */
static X509_CRL *find_crl(X509_STORE_CTX *ctx, X509 *x)
{
    const X509_NAME *nm = X509_get_issuer_name(x);
    STACK_OF(X509_CRL) *crls = ctx->lookup_crls(ctx, nm);
    X509_CRL *crl, *best = NULL;
    int best_valid = 0, i;

    for (i = 0; i < sk_X509_CRL_num(crls) && !best_valid; i++) {
        crl = sk_X509_CRL_value(crls, i);
        if (!crl_usable(crl)
            || X509_NAME_cmp(nm, X509_CRL_get_issuer(crl)) != 0
            || !ossl_x509_crl_covers(x, crl))
            continue;
        if (best == NULL || ossl_x509_check_crl_time(ctx, crl, 0)) {
            best = crl;
            best_valid = ossl_x509_check_crl_time(ctx, crl, 0);
        }
    }
    if (best != NULL && !X509_CRL_up_ref(best))
        best = NULL;
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    return best;
}

/*
 * Check x, whose issuer signs with key, against a CRL: find one, verify its
 * signature with key, confirm it is current, and look x up in it.  Returns 1
 * if x is not revoked, 0 otherwise with ctx->error set.
 */
static int check_crl(X509_STORE_CTX *ctx, X509 *x, EVP_PKEY *key)
{
    X509_CRL *crl = find_crl(ctx, x);
    X509_REVOKED *rev;
    int ok = 0;

    if (crl == NULL) {
        ctx->error = X509_V_ERR_UNABLE_TO_GET_CRL;
        return 0;
    }
    ctx->current_crl = crl;
    if (X509_CRL_verify(crl, key) <= 0) {
        ctx->error = X509_V_ERR_CRL_SIGNATURE_FAILURE;
        goto err;
    }
    if (!ossl_x509_check_crl_time(ctx, crl, 1))
        goto err;
    if (X509_CRL_get0_by_cert(crl, &rev, x)
        && rev->reason != CRL_REASON_REMOVE_FROM_CRL) {
        ctx->error = X509_V_ERR_CERT_REVOKED;
        goto err;
    }
    ok = 1;
err:
    ctx->current_crl = NULL;
    X509_CRL_free(crl);
    return ok;
}

int ossl_proof_check_revocation(X509_STORE_CTX *ctx, X509 *x, EVP_PKEY *key)
{
    if ((X509_VERIFY_PARAM_get_flags(ctx->param) & X509_V_FLAG_CRL_CHECK) == 0)
        return 1;
    ctx->error_depth = 0;
    ctx->current_cert = x;
    ctx->current_issuer = NULL;
    return check_crl(ctx, x, key);
}
