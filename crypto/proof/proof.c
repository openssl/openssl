/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * The public OSSL_PROOF verification API.  The only proof form at present is
 * a Merkle Tree Certificate; OSSL_PROOF_verify() runs ossl_x509_verify_mtc()
 * over a transient X509_STORE_CTX built from the trust configuration and the
 * verification parameters, and reports the outcome through an
 * OSSL_PROOF_OUTPUT.
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/proof.h>
#include "crypto/x509.h"

/* Proof forms.  A new form adds a value here and a case in OSSL_PROOF_verify(). */
enum ossl_proof_type {
    OSSL_PROOF_TYPE_MTC = 1
};

/* Whether a proof form is X.509-based. */
static int proof_type_is_x509(enum ossl_proof_type type)
{
    return type == OSSL_PROOF_TYPE_MTC;
}

struct ossl_proof_st {
    enum ossl_proof_type type; /**< which proof form this is */
    const X509 *cert; /**< the proof's certificate, held and read only */
};

struct ossl_proof_trust_st {
    OSSL_LIB_CTX *libctx; /**< library context verifications run in */
    char *propq; /**< property query for fetches during verification */
    X509_STORE *store; /**< X.509 trust store; holds the trusted MTC CAs */
};

struct ossl_proof_params_st {
    X509_VERIFY_PARAM *x509_param; /**< X.509 verification parameters */
    size_t mtc_cosigner_quorum; /**< MTC: trusted cosigners a standalone certificate needs */
};

/*
 * The output of a verification.  The X.509 fields are set for an X.509-based
 * proof form and are the output's own copies or references, so the output
 * outlives the verification context that produced it.
 */
struct ossl_proof_output_st {
    enum ossl_proof_type type; /**< the proof form that was verified */
    int x509_error; /**< X.509 error reason, X509_V_OK on success */
    int x509_error_depth; /**< depth of the certificate at fault on failure */
    X509 *x509_error_cert; /**< the certificate at fault on failure, or NULL */
    STACK_OF(X509) *x509_chain; /**< the verified chain on success, or NULL */
    char *x509_peername; /**< the peer name matched by the host check, or NULL */
    X509_POLICY_TREE *x509_policy_tree; /**< the policy tree when policy checking ran, or NULL */
};

OSSL_PROOF *OSSL_PROOF_new_mtc(const X509 *cert)
{
    OSSL_PROOF *proof;

    if (cert == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if ((proof = OPENSSL_zalloc(sizeof(*proof))) == NULL)
        return NULL;
    /* Take a reference; the caller must not mutate cert while it is held. */
    if (!X509_up_ref((X509 *)cert)) { /* XXX casts away const */
        OPENSSL_free(proof);
        return NULL;
    }
    proof->type = OSSL_PROOF_TYPE_MTC;
    proof->cert = cert;
    return proof;
}

void OSSL_PROOF_free(OSSL_PROOF *proof)
{
    if (proof == NULL)
        return;
    X509_free((X509 *)proof->cert); /* XXX casts away const */
    OPENSSL_free(proof);
}

OSSL_PROOF_TRUST *OSSL_PROOF_TRUST_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_PROOF_TRUST *trust = OPENSSL_zalloc(sizeof(*trust));

    if (trust == NULL)
        return NULL;
    trust->libctx = libctx;
    if (propq != NULL && (trust->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(trust);
        return NULL;
    }
    return trust;
}

void OSSL_PROOF_TRUST_free(OSSL_PROOF_TRUST *trust)
{
    if (trust == NULL)
        return;
    X509_STORE_free(trust->store);
    OPENSSL_free(trust->propq);
    OPENSSL_free(trust);
}

int OSSL_PROOF_TRUST_set1_x509_store(OSSL_PROOF_TRUST *trust, X509_STORE *store)
{
    if (trust == NULL || store == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!X509_STORE_up_ref(store))
        return 0;
    X509_STORE_free(trust->store);
    trust->store = store;
    return 1;
}

X509_STORE *OSSL_PROOF_TRUST_get0_x509_store(const OSSL_PROOF_TRUST *trust)
{
    if (trust == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    return trust->store;
}

OSSL_PROOF_PARAMS *OSSL_PROOF_PARAMS_new(void)
{
    OSSL_PROOF_PARAMS *params = OPENSSL_zalloc(sizeof(*params));

    if (params == NULL)
        return NULL;
    if ((params->x509_param = X509_VERIFY_PARAM_new()) == NULL) {
        OPENSSL_free(params);
        return NULL;
    }
    return params;
}

void OSSL_PROOF_PARAMS_free(OSSL_PROOF_PARAMS *params)
{
    if (params == NULL)
        return;
    X509_VERIFY_PARAM_free(params->x509_param);
    OPENSSL_free(params);
}

X509_VERIFY_PARAM *OSSL_PROOF_PARAMS_get0_x509_param(const OSSL_PROOF_PARAMS *params)
{
    if (params == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    return params->x509_param;
}

int OSSL_PROOF_PARAMS_set1_x509_param(OSSL_PROOF_PARAMS *params,
    const X509_VERIFY_PARAM *param)
{
    if (params == NULL || param == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return X509_VERIFY_PARAM_set1(params->x509_param, param);
}

int OSSL_PROOF_PARAMS_set_mtc_cosigner_quorum(OSSL_PROOF_PARAMS *params,
    size_t quorum)
{
    if (params == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    params->mtc_cosigner_quorum = quorum;
    return 1;
}

size_t OSSL_PROOF_PARAMS_get_mtc_cosigner_quorum(const OSSL_PROOF_PARAMS *params)
{
    if (params == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return params->mtc_cosigner_quorum;
}

void OSSL_PROOF_OUTPUT_free(OSSL_PROOF_OUTPUT *output)
{
    if (output == NULL)
        return;
    X509_free(output->x509_error_cert);
    OSSL_STACK_OF_X509_free(output->x509_chain);
    OPENSSL_free(output->x509_peername);
    X509_policy_tree_free(output->x509_policy_tree);
    OPENSSL_free(output);
}

/* Create the output of verifying a proof of the given form. */
static OSSL_PROOF_OUTPUT *proof_output_new(enum ossl_proof_type type)
{
    OSSL_PROOF_OUTPUT *output = OPENSSL_zalloc(sizeof(*output));

    if (output == NULL)
        return NULL;
    output->type = type;
    output->x509_error = X509_V_OK;
    return output;
}

/*
 * Record on output what an X.509-based verification left on its context: the
 * error, its depth and certificate, and, on success, the verified chain, the
 * matched peer name and the policy tree.  The chain and certificate are
 * referenced, the peer name copied, and the policy tree taken over from ctx
 * (X509_STORE_CTX_cleanup() would otherwise free it).
 */
static int proof_output_set_x509(OSSL_PROOF_OUTPUT *output, X509_STORE_CTX *ctx,
    int verified)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    const char *peername;

    output->x509_error = X509_STORE_CTX_get_error(ctx);
    output->x509_error_depth = X509_STORE_CTX_get_error_depth(ctx);
    if (cert != NULL) {
        if (!X509_up_ref(cert))
            return 0;
        output->x509_error_cert = cert;
    }
    if (!verified)
        return 1;
    if ((output->x509_chain = X509_STORE_CTX_get1_chain(ctx)) == NULL)
        return 0;
    peername = X509_VERIFY_PARAM_get0_peername(X509_STORE_CTX_get0_param(ctx));
    if (peername != NULL
        && (output->x509_peername = OPENSSL_strdup(peername)) == NULL)
        return 0;
    output->x509_policy_tree = ctx->tree;
    ctx->tree = NULL;
    return 1;
}

/* Whether output is from an X.509-based proof, raising an error if not. */
static int output_is_x509(const OSSL_PROOF_OUTPUT *output)
{
    if (output == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return proof_type_is_x509(output->type);
}

int OSSL_PROOF_OUTPUT_get_x509_error(const OSSL_PROOF_OUTPUT *output,
    int *out_code)
{
    if (out_code == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!output_is_x509(output))
        return 0;
    *out_code = output->x509_error;
    return 1;
}

int OSSL_PROOF_OUTPUT_get_x509_error_depth(const OSSL_PROOF_OUTPUT *output,
    int *out_depth)
{
    if (out_depth == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!output_is_x509(output))
        return 0;
    *out_depth = output->x509_error_depth;
    return 1;
}

X509 *OSSL_PROOF_OUTPUT_get0_x509_error_cert(const OSSL_PROOF_OUTPUT *output)
{
    if (!output_is_x509(output))
        return NULL;
    return output->x509_error_cert;
}

STACK_OF(X509) *OSSL_PROOF_OUTPUT_get0_x509_chain(const OSSL_PROOF_OUTPUT *output)
{
    if (!output_is_x509(output))
        return NULL;
    return output->x509_chain;
}

const char *OSSL_PROOF_OUTPUT_get0_x509_peername(const OSSL_PROOF_OUTPUT *output)
{
    if (!output_is_x509(output))
        return NULL;
    return output->x509_peername;
}

X509_POLICY_TREE *OSSL_PROOF_OUTPUT_get0_x509_policy_tree(const OSSL_PROOF_OUTPUT *output)
{
    if (!output_is_x509(output))
        return NULL;
    return output->x509_policy_tree;
}

/* The verification callback of a proof verification: no check is waived. */
static int proof_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    return ok;
}

/*
 * Verify an MTC proof: the section 7.2 proof plus the X.509 leaf checks,
 * against a transient X509_STORE_CTX carrying the trust store and parameters.
 * The outcome is recorded on output, which must be of the MTC form.
 */
static int proof_verify_mtc(OSSL_PROOF_TRUST *trust, OSSL_PROOF *proof,
    const OSSL_PROOF_PARAMS *params, OSSL_PROOF_OUTPUT *output)
{
    OSSL_LIB_CTX *libctx = trust != NULL ? trust->libctx : NULL;
    const char *propq = trust != NULL ? trust->propq : NULL;
    X509_STORE *store = trust != NULL ? trust->store : NULL;
    X509_STORE_CTX *ctx = NULL;
    int ret = 0;

    if ((ctx = X509_STORE_CTX_new_ex(libctx, propq)) == NULL) {
        output->x509_error = X509_V_ERR_OUT_OF_MEM;
        return 0;
    }
    output->x509_error = X509_V_ERR_UNSPECIFIED;
    /* A missing store is the verifier's X509_V_ERR_MTC_UNTRUSTED_CA. */
    /* XXX casts away const */
    if (!X509_STORE_CTX_init(ctx, store, (X509 *)proof->cert, NULL))
        goto err;
    if (params != NULL
        && !X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(ctx),
            params->x509_param))
        goto err;
    X509_STORE_CTX_set_verify_cb(ctx, proof_verify_cb);
    ret = ossl_x509_verify_mtc(ctx,
        params != NULL ? params->mtc_cosigner_quorum : 0);
    if (!proof_output_set_x509(output, ctx, ret)) {
        output->x509_error = X509_V_ERR_OUT_OF_MEM;
        ret = 0;
    }
err:
    X509_STORE_CTX_free(ctx);
    return ret;
}

/*
 * The X.509 verification flags that request a revocation check an X.509-based
 * proof verification does not perform: OCSP, and CRLs beyond the complete CRL
 * of the issuer.
 */
#define PROOF_X509_FLAGS_UNSUPPORTED                               \
    (X509_V_FLAG_OCSP_RESP_CHECK | X509_V_FLAG_OCSP_RESP_CHECK_ALL \
        | X509_V_FLAG_EXTENDED_CRL_SUPPORT)

int OSSL_PROOF_verify(OSSL_PROOF_TRUST *trust, OSSL_PROOF *proof,
    const OSSL_PROOF_PARAMS *params, OSSL_PROOF_OUTPUT **out_output)
{
    OSSL_PROOF_OUTPUT *output;
    int ret = 0;

    if (out_output != NULL)
        *out_output = NULL;
    if (proof == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (params != NULL && proof_type_is_x509(proof->type)
        && (X509_VERIFY_PARAM_get_flags(params->x509_param)
               & PROOF_X509_FLAGS_UNSUPPORTED)
            != 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if ((output = proof_output_new(proof->type)) == NULL)
        return 0;
    switch (proof->type) {
    case OSSL_PROOF_TYPE_MTC:
        ret = proof_verify_mtc(trust, proof, params, output);
        break;
    }
    if (out_output != NULL)
        *out_output = output;
    else
        OSSL_PROOF_OUTPUT_free(output);
    return ret;
}
