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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <dirent.h>
#endif

#include "cmp_int.h"

/*
 * NAMING
 * The 0 version uses the supplied structure pointer directly in the parent and
 * it will be freed up when the parent is freed. In the above example crl would
 * be freed but rev would not.
 *
 * The 1 function uses a copy of the supplied structure pointer (or in some
 * cases increases its link count) in the parent and so both (x and obj above)
 * should be freed up.
 */

/* OpenSSL ASN.1 macros in CTX struct */
ASN1_SEQUENCE(OSSL_CMP_CTX) = {
    ASN1_OPT(OSSL_CMP_CTX, referenceValue, ASN1_OCTET_STRING),
    ASN1_OPT(OSSL_CMP_CTX, secretValue, ASN1_OCTET_STRING),
    ASN1_OPT(OSSL_CMP_CTX, srvCert, X509),
    ASN1_OPT(OSSL_CMP_CTX, validatedSrvCert, X509),
    ASN1_OPT(OSSL_CMP_CTX, clCert, X509),
    ASN1_OPT(OSSL_CMP_CTX, oldClCert, X509),
    ASN1_OPT(OSSL_CMP_CTX, p10CSR, X509_REQ),
    ASN1_OPT(OSSL_CMP_CTX, issuer, X509_NAME),
    ASN1_OPT(OSSL_CMP_CTX, subjectName, X509_NAME),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, subjectAltNames, GENERAL_NAME),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, policies, POLICYINFO),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, reqExtensions, X509_EXTENSION),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, extraCertsOut, X509),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, extraCertsIn, X509),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, caPubs, X509),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, lastStatusString, ASN1_UTF8STRING),
    ASN1_OPT(OSSL_CMP_CTX, newClCert, X509),
    ASN1_OPT(OSSL_CMP_CTX, recipient, X509_NAME),
    ASN1_OPT(OSSL_CMP_CTX, expected_sender, X509_NAME),
    ASN1_OPT(OSSL_CMP_CTX, transactionID, ASN1_OCTET_STRING),
    ASN1_OPT(OSSL_CMP_CTX, recipNonce, ASN1_OCTET_STRING),
    ASN1_OPT(OSSL_CMP_CTX, last_senderNonce, ASN1_OCTET_STRING),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, geninfo_itavs, OSSL_CMP_ITAV),
    ASN1_SEQUENCE_OF_OPT(OSSL_CMP_CTX, genm_itavs, OSSL_CMP_ITAV),
} ASN1_SEQUENCE_END(OSSL_CMP_CTX)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(OSSL_CMP_CTX)

/*
 * Get current certificate store containing trusted root CA certs
 */
X509_STORE *OSSL_CMP_CTX_get0_trustedStore(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->trusted_store;
}

/*
 * Set certificate store containing trusted (root) CA certs and possibly CRLs
 * and a cert verification callback function used for CMP server authentication.
 * Any already existing store entry is freed. Given NULL, the entry is reset.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_trustedStore(OSSL_CMP_CTX *ctx, X509_STORE *store)
{
    if (ctx->trusted_store)
        X509_STORE_free(ctx->trusted_store);
    ctx->trusted_store = store != NULL ? store : X509_STORE_new();;
    return ctx->trusted_store != NULL;
}

/*
 * Get current list of non-trusted intermediate certs
 */
STACK_OF(X509) *OSSL_CMP_CTX_get0_untrusted_certs(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->untrusted_certs;
}

/*
 * Set untrusted certificates for path construction in authentication of
 * the CMP server and potentially others (TLS server, newly enrolled cert).
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_untrusted_certs(OSSL_CMP_CTX *ctx,
                                      const STACK_OF(X509) *certs)
{
    if (ctx->untrusted_certs)
        sk_X509_pop_free(ctx->untrusted_certs, X509_free);
    ctx->untrusted_certs = sk_X509_new_null();
    return OSSL_CMP_sk_X509_add1_certs(ctx->untrusted_certs, certs, 0, 1);
}

/*
 * Allocates and initializes a OSSL_CMP_CTX context structure with some
 * default values.
 * OpenSSL ASN.1 types are initialized to NULL by the call to OSSL_CMP_CTX_new()
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_init(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_INIT, CMP_R_INVALID_CONTEXT);
        goto err;
    }

#ifdef OpenSSL_add_all_algorithms
    OpenSSL_add_all_algorithms(); /* needed for SHA256 with OpenSSL 1.0.2 */
#endif

    /* all other elements are initialized through ASN1 macros */
    ctx->pkey = NULL;
    ctx->newPkey = NULL;

    ctx->pbm_slen = 16;
    ctx->pbm_owf = NID_sha256;
    ctx->pbm_itercnt = 500;
    ctx->pbm_mac = NID_hmac_sha1;

    ctx->days = 0;
    ctx->SubjectAltName_nodefault = 0;
    ctx->setSubjectAltNameCritical = 0;
    ctx->setPoliciesCritical = 0;
    ctx->digest = NID_sha256;
    ctx->popoMethod = OSSL_CRMF_POPO_SIGNATURE;
    ctx->revocationReason = CRL_REASON_NONE;
    ctx->permitTAInExtraCertsForIR = 0;
    ctx->implicitConfirm = 0;
    ctx->disableConfirm = 0;
    ctx->unprotectedSend = 0;
    ctx->unprotectedErrors = 0;
    ctx->ignore_keyusage = 0;

    ctx->lastPKIStatus = 0;
    ctx->failInfoCode = 0;

    ctx->log_cb = NULL;
    ctx->certConf_cb = NULL;
    ctx->certConf_cb_arg = NULL;
    ctx->trusted_store = X509_STORE_new();
    ctx->untrusted_certs = sk_X509_new_null();

    ctx->serverName = NULL;
    ctx->serverPort = 8080;
    /* serverPath must be an empty string if not set since it's not mandatory */
    ctx->serverPath = OPENSSL_zalloc(1); /* freed by OSSL_CMP_CTX_delete() */
    if (ctx->serverPath == NULL)
        goto err;
    ctx->proxyName = NULL;
    ctx->proxyPort = 8080;
    ctx->msgtimeout = 2 * 60;
    ctx->totaltimeout = 0;
 /* ctx->end_time = */
    ctx->http_cb = NULL;
    ctx->http_cb_arg = NULL;
    ctx->transfer_cb =
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        OSSL_CMP_MSG_http_perform;
#else
        NULL;
#endif
    ctx->transfer_cb_arg = NULL;
    return 1;

 err:
    return 0;
}

/*
 * frees OSSL_CMP_CTX variables allocated in CMP_CTX_init and calls CMP_CTX_free
 */
void OSSL_CMP_CTX_delete(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return;
    EVP_PKEY_free(ctx->pkey);
    EVP_PKEY_free(ctx->newPkey);
    if (ctx->secretValue != NULL)
        OPENSSL_cleanse(ctx->secretValue->data, ctx->secretValue->length);

    OPENSSL_free(ctx->serverName);
    OPENSSL_free(ctx->serverPath);
    OPENSSL_free(ctx->proxyName);
    X509_STORE_free(ctx->trusted_store);
    sk_X509_pop_free(ctx->untrusted_certs, X509_free);
    OSSL_CMP_CTX_free(ctx);
}

/*
 * creates and initializes a OSSL_CMP_CTX structure
 * returns pointer to created OSSL_CMP_CTX on success, NULL on error
 */
OSSL_CMP_CTX *OSSL_CMP_CTX_create(void)
{
    OSSL_CMP_CTX *ctx = NULL;

    if ((ctx = OSSL_CMP_CTX_new()) == NULL)
        goto err;
    if (!(OSSL_CMP_CTX_init(ctx)))
        goto err;

    return ctx;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_CREATE, CMP_R_OUT_OF_MEMORY);
    OSSL_CMP_CTX_free(ctx);
    return NULL;
}

/*
 * returns the PKIStatus from the last CertRepMessage
 * or Revocation Response, -1 on error
 */
long OSSL_CMP_CTX_status_get(OSSL_CMP_CTX *ctx)
{
    return ctx != NULL ? ctx->lastPKIStatus : -1;
}

/*
 * returns the statusString from the last CertRepMessage
 * or Revocation Response, NULL on error
 */
OSSL_CMP_PKIFREETEXT *OSSL_CMP_CTX_statusString_get(OSSL_CMP_CTX *ctx)
{
    return ctx != NULL ? ctx->lastStatusString : NULL;
}

/*
 * Set callback function for checking if the cert is ok or should
 * it be rejected.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_certConf_cb_t cb)
{
    if (ctx == NULL)
        goto err;
    ctx->certConf_cb = cb;
    return 1;
 err:
    return 0;
}

/*
 * Set argument, respecively a pointer to a structure containing arguments,
 * optionally to be used by the certConf callback
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_certConf_cb_arg(OSSL_CMP_CTX *ctx, void* arg)
{
    if (ctx == NULL)
        goto err;
    ctx->certConf_cb_arg = arg;
    return 1;
 err:
    return 0;
}

/*
 * Get argument, respecively the pointer to a structure containing arguments,
 * optionally to be used by certConf callback
 * returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_certConf_cb_arg(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->certConf_cb_arg;
}

/*
 * Set a callback function for log messages.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_log_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_log_cb_t cb)
{
    if (ctx == NULL)
        goto err;
    ctx->log_cb = cb;
    return 1;
 err:
    return 0;
}

/*
 * Set or clear the reference value to be used for identification (i.e. the
 * user name) when using PBMAC.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_referenceValue(OSSL_CMP_CTX *ctx,
                                     const unsigned char *ref, size_t len)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_REFERENCEVALUE, CMP_R_INVALID_ARGS);
        return 0;
    }
    return OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(&ctx->referenceValue, ref, len);
}

/*
 * Set or clear the password to be used for protecting messages with PBMAC
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_secretValue(OSSL_CMP_CTX *ctx, const unsigned char *sec,
                                  const size_t len)
{
    if (ctx == NULL){
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SECRETVALUE, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (ctx->secretValue != NULL)
        OPENSSL_cleanse(ctx->secretValue->data, ctx->secretValue->length);
    return OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(&ctx->secretValue, sec, len);
}

/*
 * Returns the stack of certificates received in a response message.
 * The stack is duplicated so the caller must handle freeing it!
 * returns pointer to created stack on success, NULL on error
 */
STACK_OF(X509) *OSSL_CMP_CTX_extraCertsIn_get1(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        goto err;
    if (ctx->extraCertsIn == NULL)
        return sk_X509_new_null();
    return X509_chain_up_ref(ctx->extraCertsIn);
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_EXTRACERTSIN_GET1, CMP_R_INVALID_ARGS);
    return NULL;
}

/*
 * Copies the given stack of inbound X509 certificates to extraCertsIn of
 * the OSSL_CMP_CTX structure so that they may be retrieved later.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_extraCertsIn(OSSL_CMP_CTX *ctx,
                                   STACK_OF(X509) *extraCertsIn)
{
    if (ctx == NULL)
        goto err;
    if (extraCertsIn == NULL)
        goto err;

    /* if there are already inbound extraCerts on the stack delete them */
    if (ctx->extraCertsIn != NULL) {
        sk_X509_pop_free(ctx->extraCertsIn, X509_free);
        ctx->extraCertsIn = NULL;
    }

    if ((ctx->extraCertsIn = X509_chain_up_ref(extraCertsIn)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSIN, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSIN, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Duplicate and push the given X509 certificate to the stack of
 * outbound certificates to send in the extraCerts field.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_extraCertsOut_push1(OSSL_CMP_CTX *ctx, const X509 *val)
{
    if (ctx == NULL)
        goto err;
    if ((ctx->extraCertsOut == NULL &&
         (ctx->extraCertsOut = sk_X509_new_null()) == NULL) ||
         (!sk_X509_push(ctx->extraCertsOut, X509_dup((X509 *)val)))) {
        CMPerr(CMP_F_OSSL_CMP_CTX_EXTRACERTSOUT_PUSH1, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_EXTRACERTSOUT_PUSH1, CMP_R_INVALID_ARGS);
    return 0;
}

/*
 * Duplicate and set the given stack as the new stack of X509
 * certificates to send out in the extraCerts field.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_extraCertsOut(OSSL_CMP_CTX *ctx,
                                    STACK_OF(X509) *extraCertsOut)
{
    if (ctx == NULL)
        goto err;
    if (extraCertsOut == NULL)
        goto err;

    if (ctx->extraCertsOut) {
        sk_X509_pop_free(ctx->extraCertsOut, X509_free);
        ctx->extraCertsOut = NULL;
    }

    if ((ctx->extraCertsOut = X509_chain_up_ref(extraCertsOut)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSOUT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSOUT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * OSSL_CMP_CTX_policyOID_push1() adds the certificate policy OID given by the
 * string to the X509_EXTENSIONS of the requested certificate template.
 * returns 1 on success, -1 on parse error, and 0 on other error.
 */
int OSSL_CMP_CTX_policyOID_push1(OSSL_CMP_CTX *ctx, const char *policyOID)
{
    ASN1_OBJECT *policy;
    POLICYINFO *pinfo = NULL;

    if ((ctx == NULL) || (policyOID == NULL))
        goto err;

    if ((policy = OBJ_txt2obj(policyOID, 1)) == 0)
        return -1; /* parse eror */

    if ((ctx->policies == NULL) &&
        ((ctx->policies = CERTIFICATEPOLICIES_new()) == NULL))
        goto err;

    if ((pinfo = POLICYINFO_new()) == NULL)
        goto err;
    pinfo->policyid = policy;

    return sk_POLICYINFO_push(ctx->policies, pinfo);

 err:
    return 0; /* out of memory */
}

/*
 * add an itav for geninfo of the PKI message header
 */
int OSSL_CMP_CTX_geninfo_itav_push0(OSSL_CMP_CTX *ctx, const OSSL_CMP_ITAV *itav)
{
    if (ctx == NULL)
        return 0;

    return OSSL_CMP_ITAV_stack_item_push0(&ctx->geninfo_itavs, itav);
}

/*
 * add an itav for the body of outgoing generalmessages
 */
int OSSL_CMP_CTX_genm_itav_push0(OSSL_CMP_CTX *ctx, const OSSL_CMP_ITAV *itav)
{
    if (ctx == NULL)
        return 0;

    return OSSL_CMP_ITAV_stack_item_push0(&ctx->genm_itavs, itav);
}

/*
 * Returns a duplicate of the stack of X509 certificates that
 * were received in the caPubs field of the last response message.
 * returns NULL on error
 */
STACK_OF(X509) *OSSL_CMP_CTX_caPubs_get1(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        goto err;
    if (ctx->caPubs == NULL)
        return NULL;
    return X509_chain_up_ref(ctx->caPubs);
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_CAPUBS_GET1, CMP_R_INVALID_ARGS);
    return NULL;
}

/*
 * Duplicate and copy the given stack of certificates to the given
 * OSSL_CMP_CTX structure so that they may be retrieved later.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_caPubs(OSSL_CMP_CTX *ctx, STACK_OF(X509) *caPubs)
{
    if ((ctx == NULL) || (caPubs == NULL))
        goto err;

    sk_X509_pop_free(ctx->caPubs, X509_free);
    ctx->caPubs = NULL;

    if ((ctx->caPubs = X509_chain_up_ref(caPubs)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_CAPUBS, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_CAPUBS, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Sets the server certificate to be directly trusted for verifying response
 * messages. Additionally using OSSL_CMP_CTX_set0_trustedStore() is recommended
 * in order to be able to supply verification parameters and CRLs.
 * Cert pointer is not consumed. It may be NULL to clear the entry.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_srvCert(OSSL_CMP_CTX *ctx, const X509 *cert)
{
    if (ctx == NULL)
        goto err;

    X509_free(ctx->srvCert);
    ctx->srvCert = NULL;

    if (cert == NULL)
        return 1; /* srvCert has been cleared */

    if ((ctx->srvCert = X509_dup((X509 *)cert)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SRVCERT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SRVCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set the X509 name of the recipient. Set in the PKIHeader.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_recipient(OSSL_CMP_CTX *ctx, const X509_NAME *name)
{
    if (ctx == NULL || name == NULL)
        goto err;

    X509_NAME_free(ctx->recipient);
    ctx->recipient = NULL;

    if ((ctx->recipient = X509_NAME_dup((X509_NAME *)name)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_RECIPIENT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_RECIPIENT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Store the X509 name of the expected sender in the PKIHeader of responses.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_expected_sender(OSSL_CMP_CTX *ctx, const X509_NAME *name)
{
    if (ctx == NULL)
        goto err;

    X509_NAME_free(ctx->expected_sender);
    ctx->expected_sender = NULL;

    if (name == NULL)
        return 1;

    if ((ctx->expected_sender = X509_NAME_dup((X509_NAME *)name)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXPECTED_SENDER, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXPECTED_SENDER, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set the X509 name of the issuer. Set in the PKIHeader.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_issuer(OSSL_CMP_CTX *ctx, const X509_NAME *name)
{
    if (ctx == NULL || name == NULL)
        goto err;

    X509_NAME_free(ctx->issuer);
    ctx->issuer = NULL;

    if ((ctx->issuer = X509_NAME_dup( (X509_NAME*)name)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_ISSUER, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_ISSUER, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set the subject name that will be placed in the certificate
 * request. This will be the subject name on the received certificate.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_subjectName(OSSL_CMP_CTX *ctx, const X509_NAME *name)
{
    if (ctx == NULL || name == NULL)
        goto err;

    X509_NAME_free(ctx->subjectName);
    ctx->subjectName = NULL;

    if ((ctx->subjectName = X509_NAME_dup((X509_NAME *)name)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SUBJECTNAME, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SUBJECTNAME, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * sets the X.509v3 certificate request extensions to be used in IR/CR/KUR
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET0_REQEXTENSIONS, CMP_R_NULL_ARGUMENT);
        goto err;
    }
    if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0 && exts != NULL &&
        X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1) >= 0) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET0_REQEXTENSIONS, CMP_R_MULTIPLE_SAN_SOURCES);
        goto err;
    }
    ctx->reqExtensions = exts;
    return 1;

 err:
    return 0;
}

/*
 * sets the X.509v3 certificate request extensions to be used in IR/CR/KUR
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts)
{
    int res;
    X509_EXTENSIONS *exts_copy = CMP_exts_dup((X509_EXTENSIONS *)exts);
    if (exts_copy == NULL)
        return 0;
    res = OSSL_CMP_CTX_set0_reqExtensions(ctx, exts_copy);
    if (res == 0)
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return res;
}

/* returns 1 if ctx contains a Subject Alternative Name extension, else 0 */
int OSSL_CMP_CTX_reqExtensions_have_SAN(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL || ctx->reqExtensions == NULL)
        return 0;
    return X509v3_get_ext_by_NID(ctx->reqExtensions,
                                 NID_subject_alt_name, -1) >= 0;
}

/*
 * Add a GENERAL_NAME structure that will be added to the CRMF
 * request's extensions field to request subject alternative names.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_subjectAltName_push1(OSSL_CMP_CTX *ctx,
                                      const GENERAL_NAME *name)
{
    if (ctx == NULL || name == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if (OSSL_CMP_CTX_reqExtensions_have_SAN(ctx)) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1,
               CMP_R_MULTIPLE_SAN_SOURCES);
        goto err;
    }

    if ((ctx->subjectAltNames == NULL &&
         (ctx->subjectAltNames = sk_GENERAL_NAME_new_null()) == NULL) ||
         !sk_GENERAL_NAME_push(ctx->subjectAltNames,
         GENERAL_NAME_dup((GENERAL_NAME *)name))) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1, CMP_R_OUT_OF_MEMORY);
        goto err;
    }
    return 1;

 err:
    return 0;
}

/*
 * Set our own client certificate, used for example in KUR and when
 * doing the IR with existing certificate.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_clCert(OSSL_CMP_CTX *ctx, const X509 *cert)
{
    if (ctx == NULL || cert == NULL)
        goto err;

    X509_free(ctx->clCert);
    ctx->clCert = NULL;

    if ((ctx->clCert = X509_dup((X509 *)cert)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_CLCERT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_CLCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set the old certificate that we are updating in KUR
 * or the certificate to be revoked in RR, respectively.
 * Also used as reference cert (defaulting to clCert) for deriving subject DN
 * and SANs. Its issuer is used as default recipient in the CMP message header.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_oldClCert(OSSL_CMP_CTX *ctx, const X509 *cert)
{
    if (ctx == NULL || cert == NULL)
        goto err;

    X509_free(ctx->oldClCert);
    ctx->oldClCert = NULL;

    if ((ctx->oldClCert = X509_dup((X509 *)cert)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_OLDCLCERT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_OLDCLCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set the PKCS#10 CSR to be sent in P10CR
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_p10CSR(OSSL_CMP_CTX *ctx, const X509_REQ *csr)
{
    if (ctx == NULL || csr == NULL)
        goto err;

    X509_REQ_free(ctx->p10CSR);
    ctx->p10CSR = NULL;

    if ((ctx->p10CSR = X509_REQ_dup((X509_REQ *)csr)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_P10CSR, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_P10CSR, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * sets the (newly received in IP/KUP/CP) client Certificate to the context
 * returns 1 on success, 0 on error
 * TODO: this only permits for one client cert to be received...
 */
int OSSL_CMP_CTX_set1_newClCert(OSSL_CMP_CTX *ctx, const X509 *cert)
{
    if (ctx == NULL || cert == NULL)
        goto err;

    X509_free(ctx->newClCert);
    ctx->newClCert = NULL;

    if (!X509_up_ref((X509 *)cert))
        goto err;
    ctx->newClCert = (X509 *)cert;
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_NEWCLCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Get the (newly received in IP/KUP/CP) client certificate from the context
 * TODO: this only permits for one client cert to be received...
 */
X509 *OSSL_CMP_CTX_get0_newClCert(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->newClCert;
}

/*
 * Set the client's private key. This creates a duplicate of the key
 * so the given pointer is not used directly.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_pkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey)
{
    if (ctx == NULL || pkey == NULL)
        goto err;

    if (!EVP_PKEY_up_ref((EVP_PKEY *)pkey))
        return 0;
    if (OSSL_CMP_CTX_set0_pkey(ctx, pkey))
        return 1;
    EVP_PKEY_free((EVP_PKEY *)pkey); /* down ref */
    return 0;

 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_PKEY, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set the client's current private key. NOTE: this version uses
 * the given pointer directly!
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_pkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey)
{
    if (ctx == NULL || pkey == NULL)
        goto err;

    EVP_PKEY_free(ctx->pkey);
    ctx->pkey = NULL;

    ctx->pkey = (EVP_PKEY *)pkey;
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET0_PKEY, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set new key pair. Used for example when doing Key Update.
 * The key is duplicated so the original pointer is not directly used.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_newPkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey)
{
    if (ctx == NULL || pkey == NULL)
        goto err;

    if (!EVP_PKEY_up_ref((EVP_PKEY *)pkey))
        return 0;
    if (OSSL_CMP_CTX_set0_newPkey(ctx, pkey))
       return 1;
    EVP_PKEY_free((EVP_PKEY *)pkey); /* down ref */
    return 0;

 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_NEWPKEY, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set new key pair. Used e.g. when doing Key Update.
 * NOTE: uses the pointer directly!
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_newPkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey)
{
    if (ctx == NULL || pkey == NULL)
        goto err;

    EVP_PKEY_free(ctx->newPkey);
    ctx->newPkey = NULL;

    ctx->newPkey = (EVP_PKEY *)pkey;
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET0_NEWPKEY, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * gets the newPkey from the context, or NULL on error
 */
EVP_PKEY *OSSL_CMP_CTX_get0_newPkey(const OSSL_CMP_CTX *ctx)
{
    return ctx == NULL ? NULL : ctx->newPkey;
}

/*
 * sets the given transactionID to the context
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_transactionID(OSSL_CMP_CTX *ctx,
                                    const ASN1_OCTET_STRING *id)
{
    if (ctx == NULL)
        goto err;

    return OSSL_CMP_ASN1_OCTET_STRING_set1(&ctx->transactionID, id);
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_TRANSACTIONID, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * gets the transactionID from the context
 * returns a pointer to the transactionID on success, NULL on error
 */
ASN1_OCTET_STRING *OSSL_CMP_CTX_get0_transactionID(OSSL_CMP_CTX *ctx)
{
    return ctx == NULL ? NULL : ctx->transactionID;
}

/*
 * sets the given nonce to be used for the recipNonce in the next message to be
 * created.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_recipNonce(OSSL_CMP_CTX *ctx,
                                 const ASN1_OCTET_STRING *nonce)
{
    if (ctx == NULL || nonce == NULL)
        goto err;

    return OSSL_CMP_ASN1_OCTET_STRING_set1(&ctx->recipNonce, nonce);

 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_RECIPNONCE, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * gets the recipNonce of the given context
 * returns a pointer to the nonce on success, NULL on error
 */
ASN1_OCTET_STRING *OSSL_CMP_CTX_get0_recipNonce(OSSL_CMP_CTX *ctx)
{
    return ctx == NULL ? NULL : ctx->recipNonce;
}

/*
 * stores the given nonce as the last senderNonce sent out
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_last_senderNonce(OSSL_CMP_CTX *ctx,
                                       const ASN1_OCTET_STRING *nonce)
{
    if (ctx == NULL || nonce == NULL)
        goto err;

    return OSSL_CMP_ASN1_OCTET_STRING_set1(&ctx->last_senderNonce, nonce);

 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_LAST_SENDERNONCE, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * gets the sender nonce of the last message sent
 * returns a pointer to the nonce on success, NULL on error
 */
ASN1_OCTET_STRING *OSSL_CMP_CTX_get0_last_senderNonce(OSSL_CMP_CTX *ctx)
{
    return ctx == NULL ? NULL : ctx->last_senderNonce;
}

/*
 * Set the host name of the (HTTP) proxy server to use for all connections
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_proxyName(OSSL_CMP_CTX *ctx, const char *name)
{
    if (ctx == NULL || name == NULL)
        goto err;

    OPENSSL_free(ctx->proxyName);
    ctx->proxyName = NULL;

    ctx->proxyName = BUF_strdup(name);
    if (ctx->proxyName == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_PROXYNAME, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_PROXYNAME, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Set the (HTTP) host name of the CA server
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_serverName(OSSL_CMP_CTX *ctx, const char *name)
{
    if (ctx == NULL || name == NULL)
        goto err;

    OPENSSL_free(ctx->serverName);
    ctx->serverName = NULL;

    ctx->serverName = BUF_strdup(name);
    if (!ctx->serverName) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SERVERNAME, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SERVERNAME, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * sets the (HTTP) proxy port to be used
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_proxyPort(OSSL_CMP_CTX *ctx, int port)
{
    if (ctx == NULL)
        goto err;

    ctx->proxyPort = port;
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET_PROXYPORT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * sets the http connect/disconnect callback function to be used for HTTP(S)
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_http_cb_t cb)
{
    if (ctx == NULL)
        goto err;

    ctx->http_cb = cb;
    return 1;
 err:
    return 0;
}

/*
 * Set argument optionally to be used by the http connect/disconnect callback
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_http_cb_arg(OSSL_CMP_CTX *ctx, void *arg)
{
    if (ctx == NULL)
        goto err;

    ctx->http_cb_arg = arg;
    return 1;
 err:
    return 0;
}

/*
 * Get argument optionally to be used by the http connect/disconnect callback
 * returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_http_cb_arg(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->http_cb_arg;
}

/*
 * Set callback function for sending CMP request and receiving response.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_transfer_cb_t cb)
{
    if (ctx == NULL)
        goto err;

    ctx->transfer_cb = cb;
    return 1;
 err:
    return 0;
}

/*
 * Set argument optionally to be used by the transfer callback
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_transfer_cb_arg(OSSL_CMP_CTX *ctx, void *arg)
{
    if (ctx == NULL)
        goto err;

    ctx->transfer_cb_arg = arg;
    return 1;
 err:
    return 0;
}

/*
 * Get argument optionally to be used by the transfer callback
 * returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_transfer_cb_arg(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->transfer_cb_arg;
}

/*
 * sets the (HTTP) server port to be used
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_serverPort(OSSL_CMP_CTX *ctx, int port)
{
    if (ctx == NULL)
        goto err;

    ctx->serverPort = port;
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET_SERVERPORT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Sets the HTTP path to be used on the server (e.g "pkix/")
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_serverPath(OSSL_CMP_CTX *ctx, const char *path)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SERVERPATH, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    /* clear the old value */
    OPENSSL_free(ctx->serverPath);
    ctx->serverPath = NULL;

    if (path == NULL) {
        /* clear the serverPath */
        ctx->serverPath = OPENSSL_zalloc(1);
        if (ctx->serverPath == NULL)
            goto oom;
        return 1;
    }

    ctx->serverPath = BUF_strdup(path);
    if (ctx->serverPath == NULL)
        goto oom;

    return 1;
 oom:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SERVERPATH, CMP_R_OUT_OF_MEMORY);
    return 0;
}

/*
 * Set the failInfo error code bits in OSSL_CMP_CTX based on the given
 * OSSL_CMP_PKIFAILUREINFO structure, which is allowed to be NULL
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_failInfoCode(OSSL_CMP_CTX *ctx,
                                  OSSL_CMP_PKIFAILUREINFO *failInfo)
{
    int i;

    if (ctx == NULL)
        return 0;
    if (failInfo == NULL)
        return 1;

    ctx->failInfoCode = 0;
    for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++)
        if (ASN1_BIT_STRING_get_bit(failInfo, i))
            ctx->failInfoCode |= 1UL << i;

    return 1;
}

/*
 * Get the failinfo error code bits in OSSL_CMP_CTX
 * returns bit string in ulong on success, -1 on error
 */
unsigned long OSSL_CMP_CTX_failInfoCode_get(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return -1;
    return ctx->failInfoCode;
}

#if 0
/*
 * pushes a given 0-terminated character string to ctx->freeText
 * this is intended for human consumption
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_push_freeText(OSSL_CMP_CTX *ctx, const char *text)
{
    if (ctx == NULL)
        goto err;

    ctx->freeText = CMP_PKIFREETEXT_push_str(ctx->freeText, text);
    return ctx->freeText != NULL;

 err:
    CMPerr(CMP_F_OSSL_CMP_CTX_PUSH_FREETEXT, CMP_R_NULL_ARGUMENT);
    return 0;
}
#endif

/*
 * sets a BOOLEAN or INT option of the context to the "val" arg
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, const int opt, const int val) {
    if (ctx == NULL)
        goto err;
    switch (opt) {
    case OSSL_CMP_CTX_OPT_IMPLICITCONFIRM:
        ctx->implicitConfirm = val;
        break;
    /* to cope with broken server ignoring implicit confirmation */
    case OSSL_CMP_CTX_OPT_DISABLECONFIRM:
        ctx->disableConfirm = val;
        break;
    case OSSL_CMP_CTX_OPT_UNPROTECTED_SEND:
        ctx->unprotectedSend = val;
        break;
    case OSSL_CMP_CTX_OPT_UNPROTECTED_ERRORS:
        ctx->unprotectedErrors = val;
        break;
    case OSSL_CMP_CTX_OPT_VALIDITYDAYS:
        ctx->days = val;
        break;
    case OSSL_CMP_CTX_OPT_SUBJECTALTNAME_NODEFAULT:
        ctx->SubjectAltName_nodefault = val;
        break;
    case OSSL_CMP_CTX_OPT_SUBJECTALTNAME_CRITICAL:
        ctx->setSubjectAltNameCritical = val;
        break;
    case OSSL_CMP_CTX_OPT_POLICIES_CRITICAL:
        ctx->setPoliciesCritical = val;
        break;
    case OSSL_CMP_CTX_OPT_IGNORE_KEYUSAGE:
        ctx->ignore_keyusage = val;
        break;
    case OSSL_CMP_CTX_OPT_POPOMETHOD:
        ctx->popoMethod = val;
        break;
    case OSSL_CMP_CTX_OPT_DIGEST_ALGNID:
        ctx->digest = val;
        break;
    case OSSL_CMP_CTX_OPT_MSGTIMEOUT:
        ctx->msgtimeout = val;
        break;
    case OSSL_CMP_CTX_OPT_TOTALTIMEOUT:
        ctx->totaltimeout = val;
        break;
    case OSSL_CMP_CTX_PERMIT_TA_IN_EXTRACERTS_FOR_IR:
        ctx->permitTAInExtraCertsForIR = val;
        break;
    case OSSL_CMP_CTX_OPT_REVOCATION_REASON:
        ctx->revocationReason = val;
        break;
    default:
        goto err;
    }

    return 1;
  err:
    return 0;
}

int OSSL_CMP_log_init(void)
{
    return 1;
}

void OSSL_CMP_log_close(void)
{
    ;
}

/* prints log messages to given stream fd */
static int CMP_log_fd(const char *file, int lineno,
                      OSSL_CMP_severity level, const char *msg, FILE *fd)
{
    char sep;
    char *lvl = NULL;
    int msg_len = strlen(msg);
    int msg_nl = msg_len > 0 && msg[msg_len-1] == '\n';
    int len = 0;

#ifdef NDEBUG
    if (level == LOG_DEBUG)
        return 1;
#else
    if (file == NULL) {
#endif
        len += fprintf(fd, "CMP");
        sep = ' ';
#ifndef NDEBUG
    } else {
        len += fprintf(fd, "%s:%d", file, lineno);
        sep = ':';
    }
#endif

    switch(level) {
    case LOG_EMERG: lvl = "EMERGENCY"; break;
    case LOG_ALERT: lvl = "ALERT"; break;
    case LOG_CRIT : lvl = "CRITICAL" ; break;
    case LOG_ERROR: lvl = "ERROR"; break;
    case LOG_WARN : lvl = "WARNING" ; break;
    case LOG_NOTE : lvl = "NOTICE" ; break;
    case LOG_INFO : lvl = "INFO" ; break;
#ifndef NDEBUG
    case LOG_DEBUG: lvl = "DEBUG"; break;
#endif
    default: break;
    }

    if (lvl != NULL)
        len += fprintf(fd, "%c%s", sep, lvl);
    len += fprintf(fd, ": %s%s", msg, msg_nl != 0 ? "" : "\n");

    return fflush(fd) != EOF && len >= 0;
}

/* prints errors and warnings to stderr, info and debug messages to stdout */
int OSSL_CMP_puts(const char *file, int lineno,
             OSSL_CMP_severity level, const char *msg)
{
    FILE *fd = level <= LOG_WARN ? stderr : stdout;
    return CMP_log_fd(file, lineno, level, msg, fd);
}

/*
 * Function used for outputting error/warn/debug messages depending on callback.
 * By default or if the callback is NULL the function OSSL_CMP_puts() is used.
 */
int OSSL_CMP_printf(const OSSL_CMP_CTX *ctx, const char *file, int lineno,
                    OSSL_CMP_severity level, const char *fmt, ...)
{
    va_list arg_ptr;
    char buf[1024];
    int res;
    OSSL_cmp_log_cb_t log_fn =
        ctx == NULL || ctx->log_cb == NULL ? OSSL_CMP_puts : ctx->log_cb;

    va_start(arg_ptr, fmt);
    BIO_vsnprintf(buf, sizeof(buf), fmt, arg_ptr);
    res = (*log_fn)(file, lineno, level, buf);
    va_end(arg_ptr);
    return res;
}

#ifdef OSSL_CMP_POOR_LOG
/*
 * simple function for error/warn/debug messages, to be used via CMP_LOG((args))
 */
int CMP_log_printf(const char *file, int line,
                   OSSL_CMP_severity level, const char *fmt, ...)
{
    va_list arg_ptr;
    char buf[1024];
    int res;

    va_start(arg_ptr, fmt);
    BIO_vsnprintf(buf, sizeof(buf), fmt, arg_ptr);
    res = OSSL_CMP_puts(file, line, level, buf);
    va_end(arg_ptr);
    return res;
}
#endif

/*
 * This callback is used to print out the OpenSSL error queue via
 * ERR_print_errors_cb() to the ctx->log_cb() function set by the user
 * returns 1 on success, 0 on error
 */
int CMP_CTX_error_cb(const char *str, size_t len, void *u) {
    OSSL_CMP_CTX *ctx = (OSSL_CMP_CTX *)u;
    OSSL_cmp_log_cb_t log_fn =
        ctx == NULL || ctx->log_cb == NULL ? OSSL_CMP_puts : ctx->log_cb;
    while (*str != '\0' && *str != ':') /* skip pid */
        str++;
    if (*str != '\0') /* skip ':' */
        str++;
    while (*str != '\0' && *str != ':') /* skip 'error' */
        str++;
    if (*str != '\0') /* skip ':' */
        str++;
    return (*log_fn)(NULL, 0, LOG_ERROR, str);
}
