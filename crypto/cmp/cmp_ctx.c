/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/trace.h>
#include <openssl/bio.h>
#include <openssl/ocsp.h> /* for OCSP_REVOKED_STATUS_* */

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/err.h>

/*
 * Get current certificate store containing trusted root CA certs
 */
X509_STORE *OSSL_CMP_CTX_get0_trustedStore(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return ctx->trusted;
}

/*
 * Set certificate store containing trusted (root) CA certs and possibly CRLs
 * and a cert verification callback function used for CMP server authentication.
 * Any already existing store entry is freed. Given NULL, the entry is reset.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_trustedStore(OSSL_CMP_CTX *ctx, X509_STORE *store)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_STORE_free(ctx->trusted);
    ctx->trusted = store;
    return 1;
}

/*
 * Get current list of non-trusted intermediate certs
 */
STACK_OF(X509) *OSSL_CMP_CTX_get0_untrusted_certs(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return ctx->untrusted_certs;
}

/*
 * Set untrusted certificates for path construction in authentication of
 * the CMP server and potentially others (TLS server, newly enrolled cert).
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_untrusted_certs(OSSL_CMP_CTX *ctx, STACK_OF(X509) *certs)
{
    STACK_OF(X509) *untrusted_certs;
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if ((untrusted_certs = sk_X509_new_null()) == NULL)
        return 0;
    if (ossl_cmp_sk_X509_add1_certs(untrusted_certs, certs, 0, 1, 0) != 1)
        goto err;
    sk_X509_pop_free(ctx->untrusted_certs, X509_free);
    ctx->untrusted_certs = untrusted_certs;
    return 1;
err:
    sk_X509_pop_free(untrusted_certs, X509_free);
    return 0;
}

/*
 * Allocates and initializes OSSL_CMP_CTX context structure with default values.
 * Returns new context on success, NULL on error
 */
OSSL_CMP_CTX *OSSL_CMP_CTX_new(void)
{
    OSSL_CMP_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;

    ctx->log_verbosity = OSSL_CMP_LOG_INFO;

    ctx->status = -1;
    ctx->failInfoCode = -1;

    ctx->serverPort = OSSL_CMP_DEFAULT_PORT;
    ctx->proxyPort = OSSL_CMP_DEFAULT_PORT;
    ctx->msgtimeout = 2 * 60;

    if ((ctx->untrusted_certs = sk_X509_new_null()) == NULL)
        goto err;

    ctx->pbm_slen = 16;
    ctx->pbm_owf = NID_sha256;
    ctx->pbm_itercnt = 500;
    ctx->pbm_mac = NID_hmac_sha1;

    ctx->digest = NID_sha256;
    ctx->popoMethod = OSSL_CRMF_POPO_SIGNATURE;
    ctx->revocationReason = CRL_REASON_NONE;

    /* all other elements are initialized to 0 or NULL, respectively */
    return ctx;

 err:
    OSSL_CMP_CTX_free(ctx);
    return NULL;
}

/*
 * Prepare the OSSL_CMP_CTX for next use, partly re-initializing OSSL_CMP_CTX
 */
int OSSL_CMP_CTX_reinit(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    ctx->status = -1;
    ctx->failInfoCode = -1;

    return ossl_cmp_ctx_set0_statusString(ctx, NULL)
        && ossl_cmp_ctx_set0_newCert(ctx, NULL)
        && ossl_cmp_ctx_set1_caPubs(ctx, NULL)
        && ossl_cmp_ctx_set1_extraCertsIn(ctx, NULL)
        && ossl_cmp_ctx_set0_validatedSrvCert(ctx, NULL)
        && OSSL_CMP_CTX_set1_transactionID(ctx, NULL)
        && OSSL_CMP_CTX_set1_senderNonce(ctx, NULL)
        && ossl_cmp_ctx_set1_recipNonce(ctx, NULL);
}

/*
 * Frees OSSL_CMP_CTX variables allocated in OSSL_CMP_CTX_new()
 */
void OSSL_CMP_CTX_free(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx->serverPath);
    OPENSSL_free(ctx->serverName);
    OPENSSL_free(ctx->proxyName);

    X509_free(ctx->srvCert);
    X509_free(ctx->validatedSrvCert);
    X509_NAME_free(ctx->expected_sender);
    X509_STORE_free(ctx->trusted);
    sk_X509_pop_free(ctx->untrusted_certs, X509_free);

    X509_free(ctx->clCert);
    EVP_PKEY_free(ctx->pkey);
    ASN1_OCTET_STRING_free(ctx->referenceValue);
    if (ctx->secretValue != NULL)
        OPENSSL_cleanse(ctx->secretValue->data, ctx->secretValue->length);
    ASN1_OCTET_STRING_free(ctx->secretValue);

    X509_NAME_free(ctx->recipient);
    ASN1_OCTET_STRING_free(ctx->transactionID);
    ASN1_OCTET_STRING_free(ctx->senderNonce);
    ASN1_OCTET_STRING_free(ctx->recipNonce);
    sk_OSSL_CMP_ITAV_pop_free(ctx->geninfo_ITAVs, OSSL_CMP_ITAV_free);
    sk_X509_pop_free(ctx->extraCertsOut, X509_free);

    EVP_PKEY_free(ctx->newPkey);
    X509_NAME_free(ctx->issuer);
    X509_NAME_free(ctx->subjectName);
    sk_GENERAL_NAME_pop_free(ctx->subjectAltNames, GENERAL_NAME_free);
    sk_X509_EXTENSION_pop_free(ctx->reqExtensions, X509_EXTENSION_free);
    sk_POLICYINFO_pop_free(ctx->policies, POLICYINFO_free);
    X509_free(ctx->oldCert);
    X509_REQ_free(ctx->p10CSR);

    sk_OSSL_CMP_ITAV_pop_free(ctx->genm_ITAVs, OSSL_CMP_ITAV_free);

    sk_ASN1_UTF8STRING_pop_free(ctx->statusString, ASN1_UTF8STRING_free);
    X509_free(ctx->newCert);
    sk_X509_pop_free(ctx->caPubs, X509_free);
    sk_X509_pop_free(ctx->extraCertsIn, X509_free);

    OPENSSL_free(ctx);
}

int ossl_cmp_ctx_set_status(OSSL_CMP_CTX *ctx, int status)
{
    if (!ossl_assert(ctx != NULL))
        return 0;
    ctx->status = status;
    return 1;
}

/*
 * Returns the PKIStatus from the last CertRepMessage
 * or Revocation Response or error message, -1 on error
 */
int OSSL_CMP_CTX_get_status(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return -1;
    }
    return ctx->status;
}

/*
 * Returns the statusString from the last CertRepMessage
 * or Revocation Response or error message, NULL on error
 */
OSSL_CMP_PKIFREETEXT *OSSL_CMP_CTX_get0_statusString(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return ctx->statusString;
}

int ossl_cmp_ctx_set0_statusString(OSSL_CMP_CTX *ctx,
                                   OSSL_CMP_PKIFREETEXT *text)
{
    if (!ossl_assert(ctx != NULL))
        return 0;
    sk_ASN1_UTF8STRING_pop_free(ctx->statusString, ASN1_UTF8STRING_free);
    ctx->statusString = text;
    return 1;
}

int ossl_cmp_ctx_set0_validatedSrvCert(OSSL_CMP_CTX *ctx, X509 *cert)
{
    if (!ossl_assert(ctx != NULL))
        return 0;
    X509_free(ctx->validatedSrvCert);
    ctx->validatedSrvCert = cert;
    return 1;
}

/*
 * Set callback function for checking if the cert is ok or should
 * it be rejected.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_certConf_cb_t cb)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->certConf_cb = cb;
    return 1;
}

/*
 * Set argument, respectively a pointer to a structure containing arguments,
 * optionally to be used by the certConf callback.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_certConf_cb_arg(OSSL_CMP_CTX *ctx, void *arg)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->certConf_cb_arg = arg;
    return 1;
}

/*
 * Get argument, respectively the pointer to a structure containing arguments,
 * optionally to be used by certConf callback.
 * Returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_certConf_cb_arg(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return ctx->certConf_cb_arg;
}

#ifndef OPENSSL_NO_TRACE
static size_t ossl_cmp_log_trace_cb(const char *buf, size_t cnt,
                                    int category, int cmd, void *vdata)
{
    OSSL_CMP_CTX *ctx = vdata;
    const char *prefix_msg;
    OSSL_CMP_severity level = -1;
    char *func = NULL;
    char *file = NULL;
    int line = 0;

    if (buf == NULL || cnt == 0 || cmd != OSSL_TRACE_CTRL_WRITE || ctx == NULL)
        return 0;
    if (ctx->log_cb == NULL)
        return 1; /* silently drop message */

    prefix_msg = ossl_cmp_log_parse_metadata(buf, &level, &func, &file, &line);

    if (level > ctx->log_verbosity) /* excludes the case level is unknown */
        goto end; /* suppress output since severity is not sufficient */

    if (!ctx->log_cb(func != NULL ? func : "(no func)",
                     file != NULL ? file : "(no file)",
                     line, level, prefix_msg))
        cnt = 0;

 end:
    OPENSSL_free(func);
    OPENSSL_free(file);
    return cnt;
}
#endif

/*
 * Set a callback function for error reporting and logging messages.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_log_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_log_cb_t cb)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->log_cb = cb;

#ifndef OPENSSL_NO_TRACE
    /* do also in case cb == NULL, to switch off logging output: */
    if (!OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_CMP,
                                 ossl_cmp_log_trace_cb, ctx))
        return 0;
#endif

    return 1;
}

/* Print OpenSSL and CMP errors via the log cb of the ctx or ERR_print_errors */
void OSSL_CMP_CTX_print_errors(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_print_errors_cb(ctx == NULL ? NULL : ctx->log_cb);
}

/*
 * Set or clear the reference value to be used for identification
 * (i.e., the user name) when using PBMAC.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_referenceValue(OSSL_CMP_CTX *ctx,
                                     const unsigned char *ref, int len)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return ossl_cmp_asn1_octet_string_set1_bytes(&ctx->referenceValue, ref,
                                                 len);
}

/*
 * Set or clear the password to be used for protecting messages with PBMAC.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_secretValue(OSSL_CMP_CTX *ctx, const unsigned char *sec,
                                  const int len)
{
    ASN1_OCTET_STRING *secretValue = NULL;
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (ossl_cmp_asn1_octet_string_set1_bytes(&secretValue, sec, len) != 1)
        return 0;
    if (ctx->secretValue != NULL) {
        OPENSSL_cleanse(ctx->secretValue->data, ctx->secretValue->length);
        ASN1_OCTET_STRING_free(ctx->secretValue);
    }
    ctx->secretValue = secretValue;
    return 1;
}

/*
 * Returns the stack of certificates received in a response message.
 * The stack is duplicated so the caller must handle freeing it!
 * Returns pointer to created stack on success, NULL on error
 */
STACK_OF(X509) *OSSL_CMP_CTX_get1_extraCertsIn(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    if (ctx->extraCertsIn == NULL)
        return sk_X509_new_null();
    return X509_chain_up_ref(ctx->extraCertsIn);
}

/*
 * Copies any given stack of inbound X509 certificates to extraCertsIn
 * of the OSSL_CMP_CTX structure so that they may be retrieved later.
 * Returns 1 on success, 0 on error.
 */
int ossl_cmp_ctx_set1_extraCertsIn(OSSL_CMP_CTX *ctx,
                                   STACK_OF(X509) *extraCertsIn)
{
    if (!ossl_assert(ctx != NULL))
        return 0;

    sk_X509_pop_free(ctx->extraCertsIn, X509_free);
    ctx->extraCertsIn = NULL;
    if (extraCertsIn == NULL)
        return 1;
    return (ctx->extraCertsIn = X509_chain_up_ref(extraCertsIn)) != NULL;
}

/*
 * Duplicate and set the given stack as the new stack of X509
 * certificates to send out in the extraCerts field.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_extraCertsOut(OSSL_CMP_CTX *ctx,
                                    STACK_OF(X509) *extraCertsOut)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    sk_X509_pop_free(ctx->extraCertsOut, X509_free);
    ctx->extraCertsOut = NULL;
    if (extraCertsOut == NULL)
        return 1;
    return (ctx->extraCertsOut = X509_chain_up_ref(extraCertsOut)) != NULL;
}

/*
 * Add the given policy info object
 * to the X509_EXTENSIONS of the requested certificate template.
 * Returns 1 on success, 0 on error.
 */
int OSSL_CMP_CTX_push0_policy(OSSL_CMP_CTX *ctx, POLICYINFO *pinfo)
{
    if (ctx == NULL || pinfo == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (ctx->policies == NULL
            && (ctx->policies = CERTIFICATEPOLICIES_new()) == NULL)
        return 0;

    return sk_POLICYINFO_push(ctx->policies, pinfo);
}

/*
 * Add an ITAV for geninfo of the PKI message header
 */
int OSSL_CMP_CTX_push0_geninfo_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return OSSL_CMP_ITAV_push0_stack_item(&ctx->geninfo_ITAVs, itav);
}

/*
 * Add an itav for the body of outgoing general messages
 */
int OSSL_CMP_CTX_push0_genm_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return OSSL_CMP_ITAV_push0_stack_item(&ctx->genm_ITAVs, itav);
}

/*
 * Returns a duplicate of the stack of X509 certificates that
 * were received in the caPubs field of the last CertRepMessage.
 * Returns NULL on error
 */
STACK_OF(X509) *OSSL_CMP_CTX_get1_caPubs(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    if (ctx->caPubs == NULL)
        return sk_X509_new_null();
    return X509_chain_up_ref(ctx->caPubs);
}

/*
 * Duplicate and copy the given stack of certificates to the given
 * OSSL_CMP_CTX structure so that they may be retrieved later.
 * Returns 1 on success, 0 on error
 */
int ossl_cmp_ctx_set1_caPubs(OSSL_CMP_CTX *ctx, STACK_OF(X509) *caPubs)
{
    if (!ossl_assert(ctx != NULL))
        return 0;

    sk_X509_pop_free(ctx->caPubs, X509_free);
    ctx->caPubs = NULL;
    if (caPubs == NULL)
        return 1;
    return (ctx->caPubs = X509_chain_up_ref(caPubs)) != NULL;
}

#define char_dup OPENSSL_strdup
#define char_free OPENSSL_free
#define DEFINE_OSSL_CMP_CTX_set1(FIELD, TYPE) /* this uses _dup */ \
int OSSL_CMP_CTX_set1_##FIELD(OSSL_CMP_CTX *ctx, const TYPE *val) \
{ \
    TYPE *val_dup = NULL; \
    \
    if (ctx == NULL) { \
        CMPerr(0, CMP_R_NULL_ARGUMENT); \
        return 0; \
    } \
    \
    if (val != NULL && (val_dup = TYPE##_dup(val)) == NULL) \
        return 0; \
    TYPE##_free(ctx->FIELD); \
    ctx->FIELD = val_dup; \
    return 1; \
}

#define DEFINE_OSSL_CMP_CTX_set1_up_ref(FIELD, TYPE) \
int OSSL_CMP_CTX_set1_##FIELD(OSSL_CMP_CTX *ctx, TYPE *val) \
{ \
    if (ctx == NULL) { \
        CMPerr(0, CMP_R_NULL_ARGUMENT); \
        return 0; \
    } \
    \
    if (val != NULL && !TYPE##_up_ref(val)) \
        return 0; \
    TYPE##_free(ctx->FIELD); \
    ctx->FIELD = val; \
    return 1; \
}

/*
 * Pins the server certificate to be directly trusted (even if it is expired)
 * for verifying response messages.
 * Cert pointer is not consumed. It may be NULL to clear the entry.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1_up_ref(srvCert, X509)

/*
 * Set the X509 name of the recipient. Set in the PKIHeader.
 * returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1(recipient, X509_NAME)

/*
 * Store the X509 name of the expected sender in the PKIHeader of responses.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1(expected_sender, X509_NAME)

/*
 * Set the X509 name of the issuer. Set in the PKIHeader.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1(issuer, X509_NAME)

/*
 * Set the subject name that will be placed in the certificate
 * request. This will be the subject name on the received certificate.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1(subjectName, X509_NAME)

/*
 * Set the X.509v3 certificate request extensions to be used in IR/CR/KUR.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0 && exts != NULL
            && X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1) >= 0) {
        CMPerr(0, CMP_R_MULTIPLE_SAN_SOURCES);
        return 0;
    }
    sk_X509_EXTENSION_pop_free(ctx->reqExtensions, X509_EXTENSION_free);
    ctx->reqExtensions = exts;
    return 1;
}

/* returns 1 if ctx contains a Subject Alternative Name extension, else 0 */
int OSSL_CMP_CTX_reqExtensions_have_SAN(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return -1;
    }
    /* if one of the following conditions 'fail' this is not an error */
    return ctx->reqExtensions != NULL
        && X509v3_get_ext_by_NID(ctx->reqExtensions,
                                 NID_subject_alt_name, -1) >= 0;
}

/*
 * Add a GENERAL_NAME structure that will be added to the CRMF
 * request's extensions field to request subject alternative names.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_push1_subjectAltName(OSSL_CMP_CTX *ctx,
                                      const GENERAL_NAME *name)
{
    GENERAL_NAME *name_dup;

    if (ctx == NULL || name == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (OSSL_CMP_CTX_reqExtensions_have_SAN(ctx) == 1) {
        CMPerr(0, CMP_R_MULTIPLE_SAN_SOURCES);
        return 0;
    }

    if (ctx->subjectAltNames == NULL
            && (ctx->subjectAltNames = sk_GENERAL_NAME_new_null()) == NULL)
        return 0;
    if ((name_dup = GENERAL_NAME_dup(name)) == NULL)
        return 0;
    if (!sk_GENERAL_NAME_push(ctx->subjectAltNames, name_dup)) {
        GENERAL_NAME_free(name_dup);
        return 0;
    }
    return 1;
}

/*
 * Set our own client certificate, used for example in KUR and when
 * doing the IR with existing certificate.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1_up_ref(clCert, X509)

/*
 * Set the old certificate that we are updating in KUR
 * or the certificate to be revoked in RR, respectively.
 * Also used as reference cert (defaulting to clCert) for deriving subject DN
 * and SANs. Its issuer is used as default recipient in the CMP message header.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1_up_ref(oldCert, X509)

/*
 * Set the PKCS#10 CSR to be sent in P10CR.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1(p10CSR, X509_REQ)

/*
 * Sets the (newly received in IP/KUP/CP) certificate in the context.
 * Returns 1 on success, 0 on error
 * TODO: this only permits for one cert to be enrolled at a time.
 */
int ossl_cmp_ctx_set0_newCert(OSSL_CMP_CTX *ctx, X509 *cert)
{
    if (!ossl_assert(ctx != NULL))
        return 0;

    X509_free(ctx->newCert);
    ctx->newCert = cert;
    return 1;
}

/*
 * Get the (newly received in IP/KUP/CP) client certificate from the context
 * TODO: this only permits for one client cert to be received...
 */
X509 *OSSL_CMP_CTX_get0_newCert(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return ctx->newCert;
}

/*
 * Set the client's current private key.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1_up_ref(pkey, EVP_PKEY)

/*
 * Set new key pair. Used e.g. when doing Key Update.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_newPkey(OSSL_CMP_CTX *ctx, int priv, EVP_PKEY *pkey)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    EVP_PKEY_free(ctx->newPkey);
    ctx->newPkey = pkey;
    ctx->newPkey_priv = priv;
    return 1;
}

/*
 * gets the private/public key to use for certificate enrollment, NULL on error
 */
EVP_PKEY *OSSL_CMP_CTX_get0_newPkey(const OSSL_CMP_CTX *ctx, int priv)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    if (ctx->newPkey != NULL)
        return priv && !ctx->newPkey_priv ? NULL : ctx->newPkey;
    if (ctx->p10CSR != NULL)
        return priv ? NULL : X509_REQ_get0_pubkey(ctx->p10CSR);
    return ctx->pkey; /* may be NULL */
}

/*
 * Sets the given transactionID to the context.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_transactionID(OSSL_CMP_CTX *ctx,
                                    const ASN1_OCTET_STRING *id)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return ossl_cmp_asn1_octet_string_set1(&ctx->transactionID, id);
}

/*
 * sets the given nonce to be used for the recipNonce in the next message to be
 * created.
 * returns 1 on success, 0 on error
 */
int ossl_cmp_ctx_set1_recipNonce(OSSL_CMP_CTX *ctx,
                            const ASN1_OCTET_STRING *nonce)
{
    if (!ossl_assert(ctx != NULL))
        return 0;
    return ossl_cmp_asn1_octet_string_set1(&ctx->recipNonce, nonce);
}

/*
 * Stores the given nonce as the last senderNonce sent out.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_senderNonce(OSSL_CMP_CTX *ctx,
                                  const ASN1_OCTET_STRING *nonce)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return ossl_cmp_asn1_octet_string_set1(&ctx->senderNonce, nonce);
}

/*
 * Set the host name of the (HTTP) proxy server to use for all connections
 * returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1(proxyName, char)

/*
 * Set the (HTTP) host name of the CA server.
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1(serverName, char)

/*
 * Sets the (HTTP) proxy port to be used.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_proxyPort(OSSL_CMP_CTX *ctx, int port)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->proxyPort = port;
    return 1;
}

/*
 * sets the http connect/disconnect callback function to be used for HTTP(S)
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_HTTP_bio_cb_t cb)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->http_cb = cb;
    return 1;
}

/*
 * Set argument optionally to be used by the http connect/disconnect callback.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_http_cb_arg(OSSL_CMP_CTX *ctx, void *arg)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->http_cb_arg = arg;
    return 1;
}

/*
 * Get argument optionally to be used by the http connect/disconnect callback
 * Returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_http_cb_arg(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return ctx->http_cb_arg;
}

/*
 * Set callback function for sending CMP request and receiving response.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_transfer_cb_t cb)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->transfer_cb = cb;
    return 1;
}

/*
 * Set argument optionally to be used by the transfer callback.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_transfer_cb_arg(OSSL_CMP_CTX *ctx, void *arg)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->transfer_cb_arg = arg;
    return 1;
}

/*
 * Get argument optionally to be used by the transfer callback.
 * Returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_transfer_cb_arg(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return ctx->transfer_cb_arg;
}

/*
 * Sets the (HTTP) server port to be used.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_serverPort(OSSL_CMP_CTX *ctx, int port)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->serverPort = port;
    return 1;
}

/*
 * Sets the HTTP path to be used on the server (e.g "pkix/").
 * Returns 1 on success, 0 on error
 */
DEFINE_OSSL_CMP_CTX_set1(serverPath, char)

/*
 * Set the failInfo error code as bit encoding in OSSL_CMP_CTX.
 * Returns 1 on success, 0 on error
 */
int ossl_cmp_ctx_set_failInfoCode(OSSL_CMP_CTX *ctx, int fail_info)
{
    if (!ossl_assert(ctx != NULL))
        return 0;
    ctx->failInfoCode = fail_info;
    return 1;
}

/*
 * Get the failInfo error code in OSSL_CMP_CTX as bit encoding.
 * Returns bit string as integer on success, -1 on error
 */
int OSSL_CMP_CTX_get_failInfoCode(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return -1;
    }
    return ctx->failInfoCode;
}

/*
 * Sets a Boolean or integer option of the context to the "val" arg.
 * Returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, int opt, int val)
{
    int min_val;

    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    switch (opt) {
    case OSSL_CMP_OPT_REVOCATION_REASON:
        min_val = OCSP_REVOKED_STATUS_NOSTATUS;
        break;
    case OSSL_CMP_OPT_POPOMETHOD:
        min_val = OSSL_CRMF_POPO_NONE;
        break;
    default:
        min_val = 0;
        break;
    }
    if (val < min_val) {
        CMPerr(0, CMP_R_INVALID_ARGS);
        return 0;
    }

    switch (opt) {
    case OSSL_CMP_OPT_LOG_VERBOSITY:
        if (val > OSSL_CMP_LOG_DEBUG) {
            CMPerr(0, CMP_R_INVALID_ARGS);
            return 0;
        }
        ctx->log_verbosity = val;
        break;
    case OSSL_CMP_OPT_IMPLICITCONFIRM:
        ctx->implicitConfirm = val;
        break;
    case OSSL_CMP_OPT_DISABLECONFIRM:
        ctx->disableConfirm = val;
        break;
    case OSSL_CMP_OPT_UNPROTECTED_SEND:
        ctx->unprotectedSend = val;
        break;
    case OSSL_CMP_OPT_UNPROTECTED_ERRORS:
        ctx->unprotectedErrors = val;
        break;
    case OSSL_CMP_OPT_VALIDITYDAYS:
        ctx->days = val;
        break;
    case OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT:
        ctx->SubjectAltName_nodefault = val;
        break;
    case OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL:
        ctx->setSubjectAltNameCritical = val;
        break;
    case OSSL_CMP_OPT_POLICIES_CRITICAL:
        ctx->setPoliciesCritical = val;
        break;
    case OSSL_CMP_OPT_IGNORE_KEYUSAGE:
        ctx->ignore_keyusage = val;
        break;
    case OSSL_CMP_OPT_POPOMETHOD:
        if (val > OSSL_CRMF_POPO_KEYAGREE) {
            CMPerr(0, CMP_R_INVALID_ARGS);
            return 0;
        }
        ctx->popoMethod = val;
        break;
    case OSSL_CMP_OPT_DIGEST_ALGNID:
        ctx->digest = val;
        break;
    case OSSL_CMP_OPT_OWF_ALGNID:
        ctx->pbm_owf = val;
        break;
    case OSSL_CMP_OPT_MAC_ALGNID:
        ctx->pbm_mac = val;
        break;
    case OSSL_CMP_OPT_MSGTIMEOUT:
        ctx->msgtimeout = val;
        break;
    case OSSL_CMP_OPT_TOTALTIMEOUT:
        ctx->totaltimeout = val;
        break;
    case OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR:
        ctx->permitTAInExtraCertsForIR = val;
        break;
    case OSSL_CMP_OPT_REVOCATION_REASON:
        if (val > OCSP_REVOKED_STATUS_AACOMPROMISE) {
            CMPerr(0, CMP_R_INVALID_ARGS);
            return 0;
        }
        ctx->revocationReason = val;
        break;
    default:
        CMPerr(0, CMP_R_INVALID_ARGS);
        return 0;
    }

    return 1;
}

/*
 * Reads a Boolean or integer option value from the context.
 * Returns -1 on error (which is the default OSSL_CMP_OPT_REVOCATION_REASON)
 */
int OSSL_CMP_CTX_get_option(const OSSL_CMP_CTX *ctx, int opt)
{
    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return -1;
    }

    switch (opt) {
    case OSSL_CMP_OPT_LOG_VERBOSITY:
        return ctx->log_verbosity;
    case OSSL_CMP_OPT_IMPLICITCONFIRM:
        return ctx->implicitConfirm;
    case OSSL_CMP_OPT_DISABLECONFIRM:
        return ctx->disableConfirm;
    case OSSL_CMP_OPT_UNPROTECTED_SEND:
        return ctx->unprotectedSend;
    case OSSL_CMP_OPT_UNPROTECTED_ERRORS:
        return ctx->unprotectedErrors;
    case OSSL_CMP_OPT_VALIDITYDAYS:
        return ctx->days;
    case OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT:
        return ctx->SubjectAltName_nodefault;
    case OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL:
        return ctx->setSubjectAltNameCritical;
    case OSSL_CMP_OPT_POLICIES_CRITICAL:
        return ctx->setPoliciesCritical;
    case OSSL_CMP_OPT_IGNORE_KEYUSAGE:
        return ctx->ignore_keyusage;
    case OSSL_CMP_OPT_POPOMETHOD:
        return ctx->popoMethod;
    case OSSL_CMP_OPT_DIGEST_ALGNID:
        return ctx->digest;
    case OSSL_CMP_OPT_OWF_ALGNID:
        return ctx->pbm_owf;
    case OSSL_CMP_OPT_MAC_ALGNID:
        return ctx->pbm_mac;
    case OSSL_CMP_OPT_MSGTIMEOUT:
        return ctx->msgtimeout;
    case OSSL_CMP_OPT_TOTALTIMEOUT:
        return ctx->totaltimeout;
    case OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR:
        return ctx->permitTAInExtraCertsForIR;
    case OSSL_CMP_OPT_REVOCATION_REASON:
        return ctx->revocationReason;
    default:
        CMPerr(0, CMP_R_INVALID_ARGS);
        return -1;
    }
}
