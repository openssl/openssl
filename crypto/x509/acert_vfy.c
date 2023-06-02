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

int TARGET_CERT_cmp (TARGET_CERT* a, TARGET_CERT* b);
int ossl_x509_check_targeting (TARGET *asserted, TARGETING_INFORMATION *tinfo);

/*-
 * Check attribute certificate validity times.
 * Make second argument NULL to evaluate against the current time.
 */
int ossl_x509_check_acert_time(X509_ACERT *acert, time_t* as_of)
{
    int i;

    i = X509_cmp_time(X509_ACERT_get0_notBefore(acert), as_of);
    if (i == 0)
        return X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
    if (i > 0)
        return X509_V_ERR_CERT_NOT_YET_VALID;

    i = X509_cmp_time(X509_ACERT_get0_notAfter(acert), as_of);
    if (i == 0)
        return X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
    if (i < 0)
        return X509_V_ERR_CERT_HAS_EXPIRED;

    return X509_V_OK;
}

/* Returns 0 if they are equal, != 0 otherwise. certDigestInfo is not checked. */
int TARGET_CERT_cmp (TARGET_CERT* a, TARGET_CERT* b) {
    int a_name_num, b_name_num, i, j;
    GENERAL_NAMES *a_names, *b_names;
    GENERAL_NAME *a_name, *b_name;
    if (!ASN1_INTEGER_cmp(&a->targetCertificate->serial,
        &b->targetCertificate->serial)) {
        return 1;
    }
    a_names = a->targetCertificate->issuer;
    b_names = b->targetCertificate->issuer;
    a_name_num = sk_GENERAL_NAME_num(a_names);
    b_name_num = sk_GENERAL_NAME_num(b_names);
    for (i = 0; i < a_name_num; i++) {
        for (j = 0; j < b_name_num; j++) {
            a_name = sk_GENERAL_NAME_value(a_names, i);
            b_name = sk_GENERAL_NAME_value(b_names, j);
            if (!GENERAL_NAME_cmp(a_name, b_name)) {
                return 0;
            }
        }
    }
    return 2;
}

int ossl_x509_check_targeting (TARGET *asserted, TARGETING_INFORMATION *tinfo) {
    int i, j, targets_num, target_num;
    TARGETS* tgts;
    TARGET* tgt;
    GENERAL_NAME *gn, *asserted_gn;
    TARGET_CERT *tc, *asserted_tc;
    targets_num = sk_TARGETS_num(tinfo);
    for (i = 0; i < targets_num; i++) {
        tgts = sk_TARGETS_value(tinfo, i);
        target_num = sk_TARGET_num(tgts);
        for (j = 0; j < target_num; j++) {
            tgt = sk_TARGET_value(tgts, j);
            if (tgt->type != asserted->type) {
                continue;
            }
            switch (tgt->type) {
                case (TGT_TARGET_NAME): {
                    gn = tgt->choice.targetName;
                    asserted_gn = asserted->choice.targetName;
                    if (!GENERAL_NAME_cmp(gn, asserted_gn)) {
                        return 1;
                    }
                    break;
                }
                case (TGT_TARGET_GROUP): {
                    // TODO: Define a group lookup callback?
                    // gn = tgt->choice.targetGroup;
                    /* Currently unrecognized. */
                    break;
                }
                case (TGT_TARGET_CERT): {
                    tc = tgt->choice.targetCert;
                    asserted_tc = asserted->choice.targetCert;
                    if (TARGET_CERT_cmp(asserted_tc, tc)) {
                        continue;
                    }
                    /* The targetName field of TargetCert is not explained. My
                    assumption is that, if it is present in the certificate, it
                    further constrains the asserted targetName to an exact
                    match, and without it, any targetName is acceptable as long
                    as the target's IssuerSerial matches. */
                    if (tc->targetName != NULL) {
                        if (asserted_tc->targetName != NULL) {
                            continue;
                        }
                        if (!GENERAL_NAME_cmp(tc->targetName,
                                              asserted_tc->targetName)) {
                            return 1;
                        }
                    }
                    break;
                }
            }
        }
    }
    return 0;
}

int ossl_x509_check_acert_exts(X509_ACERT *acert, TARGET *tgt,
                               int asserted_before)
{
    int i, critical, nid;
    X509_EXTENSION *current_ext;
    ASN1_OBJECT *oid;
    TARGETING_INFORMATION *tinfo;
    int n = X509_acert_get_ext_count(acert);

    for (i = 0; i < n; i++) {
        current_ext = X509_acert_get_ext(acert, i);
        if (current_ext == NULL)
            break;
        oid = X509_EXTENSION_get_object(current_ext);
        nid = OBJ_obj2nid(oid);
        switch (nid) {
            case NID_no_assertion:
                return X509_V_ERR_NO_ASSERTION;
            case NID_single_use: {
                if (asserted_before)
                    return X509_V_ERR_SINGLE_USE;
                break;
            }
            case NID_target_information: {
                if (tgt != NULL) {
                    tinfo = X509V3_EXT_d2i(current_ext);
                    if (!ossl_x509_check_targeting(tgt, tinfo))
                        return X509_V_ERR_INVALID_TARGET;
                }
                break;
            }
            default: {
                /* You have to use this function, because X509_EXTENSION defaults the
                critical field to -1 which evaluates truthy! */
                critical = X509_EXTENSION_get_critical(current_ext);
                if (critical) {
                    return X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION;
                }
            }
        }
    }
    return X509_V_OK;
}

/* This DOES NOT verify the issuer or holder certificates. Those must be
verified separately. */
int X509_attr_cert_verify_ex(X509_ACERT *acert, X509 *issuer, X509 *holder,
                             TARGET *tgt, int asserted_before) {
    int rc, holder_verified;
    EVP_PKEY *pkey;
    AUTHORITY_KEYID *akid;
    OSSL_ISSUER_SERIAL *basecertid;
    GENERAL_NAMES *holder_ent;

    if (X509_ALGOR_cmp(&acert->sig_alg, &acert->acinfo->signature) != 0)
        return X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH;

    if (holder != NULL) {
        /*
        * Check that holder cert matches attribute cert holder field.
        * This can be done withi *either* the baseCertificateId or the
        * entityName.  RFC 5755 recommends that only one option is used
        * for a given AC, but in case both are present, baseCertificateId
        * takes precedence.
        */
        if ((basecertid = X509_ACERT_get0_holder_baseCertId(acert)) != NULL) {
            if (X509_NAME_cmp(OSSL_ISSUER_SERIAL_get0_issuer(basecertid),
                            X509_get_issuer_name(holder)) != 0
                || ASN1_STRING_cmp(OSSL_ISSUER_SERIAL_get0_serial(basecertid),
                                X509_get0_serialNumber(holder)) != 0) {
                return X509_V_ERR_ISSUER_HOLDER_MISMATCH;
            }
            holder_verified = 1;
        }

        if (holder_verified == 0
            && (holder_ent = X509_ACERT_get0_holder_entityName(acert)) != NULL
            && sk_GENERAL_NAME_num(holder_ent) >= 1) {
            GENERAL_NAMES *holderAltNames;
            GENERAL_NAME *entName = sk_GENERAL_NAME_value(holder_ent, 0);
            int i;

            if (entName->type == GEN_DIRNAME
                && X509_NAME_cmp(entName->d.directoryName, X509_get_subject_name(holder)) == 0)
                holder_verified = 1;

            if (holder_verified == 0
                && (holderAltNames = X509_get_ext_d2i(holder, NID_subject_alt_name,
                                                    NULL, NULL)) != NULL) {
                for (i = 0; i < sk_GENERAL_NAME_num(holderAltNames); i++) {
                    GENERAL_NAME *name = sk_GENERAL_NAME_value(holderAltNames, i);

                    if (GENERAL_NAME_cmp(name, entName) == 0) {
                        holder_verified = 1;
                        break;
                    }
                }
            }
        }

        if (holder_verified == 0) {
            return X509_V_ERR_ISSUER_HOLDER_MISMATCH;
        }
    }

    akid = X509V3_get_d2i(acert->acinfo->extensions, NID_authority_key_identifier, NULL, NULL);
    if (akid != NULL) {
        rc = X509_check_akid(issuer, akid);
        if (rc != X509_V_OK)
            return rc;
    }
    if ((pkey = X509_get0_pubkey(issuer)) == NULL)
        return X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
    rc = X509_ACERT_verify(acert, pkey);
    if (rc != 1)
        return X509_V_ERR_CERT_SIGNATURE_FAILURE;

    rc = ossl_x509_check_acert_time(acert, NULL);
    if (rc != X509_V_OK)
        return rc;

    /*
     * Check that the issuer satisfies the AC issuer profile in
     * RFC 5755 Section 4.5.  This will also cache the attached
     * X509v3 extensions, which must be done before calling
     * X509_check_akid() and X509_check_ca() to get valid results.
     */
    if ((X509_get_key_usage(issuer) & X509v3_KU_DIGITAL_SIGNATURE) == 0) {
        return X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
    }

    rc = ossl_x509_check_acert_exts(acert, tgt, asserted_before);
    if (rc != X509_V_OK)
        return rc;

    return X509_V_OK;
}

int X509_attr_cert_verify(X509_ACERT *acert, X509 *issuer)
{
    return X509_attr_cert_verify_ex(acert, issuer, NULL, NULL, 0);
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
