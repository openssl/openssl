/*
 * Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2020
 * Copyright Siemens AG 2015-2020
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* CMP functions for PKIMessage checking */

#include "cmp_local.h"
#include <openssl/cmp_util.h>

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

DEFINE_STACK_OF(X509)

/*
 * Verify a message protected by signature according to section 5.1.3.3
 * (sha1+RSA/DSA or any other algorithm supported by OpenSSL).
 *
 * Returns 1 on successful validation and 0 otherwise.
 */
static int verify_signature(const OSSL_CMP_CTX *cmp_ctx,
                            const OSSL_CMP_MSG *msg, X509 *cert)
{
    EVP_MD_CTX *ctx = NULL;
    OSSL_CMP_PROTECTEDPART prot_part;
    int digest_nid, pk_nid;
    const EVP_MD *digest = NULL;
    EVP_PKEY *pubkey = NULL;
    int len;
    size_t prot_part_der_len = 0;
    unsigned char *prot_part_der = NULL;
    BIO *bio = BIO_new(BIO_s_mem()); /* may be NULL */
    int res = 0;

    if (!ossl_assert(cmp_ctx != NULL && msg != NULL && cert != NULL))
        return 0;

    /* verify that keyUsage, if present, contains digitalSignature */
    if (!cmp_ctx->ignore_keyusage
            && (X509_get_key_usage(cert) & X509v3_KU_DIGITAL_SIGNATURE) == 0) {
        CMPerr(0, CMP_R_MISSING_KEY_USAGE_DIGITALSIGNATURE);
        goto sig_err;
    }

    pubkey = X509_get_pubkey(cert);
    if (pubkey == NULL) {
        CMPerr(0, CMP_R_FAILED_EXTRACTING_PUBKEY);
        goto sig_err;
    }

    /* create the DER representation of protected part */
    prot_part.header = msg->header;
    prot_part.body = msg->body;

    len = i2d_OSSL_CMP_PROTECTEDPART(&prot_part, &prot_part_der);
    if (len < 0 || prot_part_der == NULL)
        goto end;
    prot_part_der_len = (size_t) len;

    /* verify signature of protected part */
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(msg->header->protectionAlg->algorithm),
                             &digest_nid, &pk_nid)
            || digest_nid == NID_undef || pk_nid == NID_undef
            || (digest = EVP_get_digestbynid(digest_nid)) == NULL) {
        CMPerr(0, CMP_R_ALGORITHM_NOT_SUPPORTED);
        goto sig_err;
    }

    /* check msg->header->protectionAlg is consistent with public key type */
    if (EVP_PKEY_type(pk_nid) != EVP_PKEY_base_id(pubkey)) {
        CMPerr(0, CMP_R_WRONG_ALGORITHM_OID);
        goto sig_err;
    }
    if ((ctx = EVP_MD_CTX_new()) == NULL)
        goto end;
    if (EVP_DigestVerifyInit(ctx, NULL, digest, NULL, pubkey)
            && EVP_DigestVerify(ctx, msg->protection->data,
                                msg->protection->length,
                                prot_part_der, prot_part_der_len) == 1) {
        res = 1;
        goto end;
    }

 sig_err:
    res = x509_print_ex_brief(bio, cert, X509_FLAG_NO_EXTENSIONS);
    CMPerr(0, CMP_R_ERROR_VALIDATING_PROTECTION);
    if (res)
        ERR_add_error_mem_bio("\n", bio);
    res = 0;

 end:
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(prot_part_der);
    EVP_PKEY_free(pubkey);
    BIO_free(bio);

    return res;
}

/* Verify a message protected with PBMAC */
static int verify_PBMAC(const OSSL_CMP_MSG *msg,
                        const ASN1_OCTET_STRING *secret)
{
    ASN1_BIT_STRING *protection = NULL;
    int valid = 0;

    /* generate expected protection for the message */
    if ((protection = ossl_cmp_calc_protection(msg, secret, NULL)) == NULL)
        return 0; /* failed to generate protection string! */

    valid = msg->protection != NULL && msg->protection->length >= 0
            && msg->protection->type == protection->type
            && msg->protection->length == protection->length
            && CRYPTO_memcmp(msg->protection->data, protection->data,
                             protection->length) == 0;
    ASN1_BIT_STRING_free(protection);
    if (!valid)
        CMPerr(0, CMP_R_WRONG_PBM_VALUE);

    return valid;
}

/*
 * Attempt to validate certificate and path using any given store with trusted
 * certs (possibly including CRLs and a cert verification callback function)
 * and non-trusted intermediate certs from the given ctx.
 *
 * Returns 1 on successful validation and 0 otherwise.
 */
int OSSL_CMP_validate_cert_path(OSSL_CMP_CTX *ctx, X509_STORE *trusted_store,
                                X509 *cert)
{
    int valid = 0;
    X509_STORE_CTX *csc = NULL;
    int err;

    if (ctx == NULL || cert == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (trusted_store == NULL) {
        CMPerr(0, CMP_R_MISSING_TRUST_STORE);
        return 0;
    }

    if ((csc = X509_STORE_CTX_new()) == NULL
            || !X509_STORE_CTX_init(csc, trusted_store,
                                    cert, ctx->untrusted_certs))
        goto err;

    valid = X509_verify_cert(csc) > 0;

    /* make sure suitable error is queued even if callback did not do */
    err = ERR_peek_last_error();
    if (!valid && ERR_GET_REASON(err) != CMP_R_POTENTIALLY_INVALID_CERTIFICATE)
        CMPerr(0, CMP_R_POTENTIALLY_INVALID_CERTIFICATE);

 err:
    /* directly output any fresh errors, needed for check_msg_find_cert() */
    OSSL_CMP_CTX_print_errors(ctx);
    X509_STORE_CTX_free(csc);
    return valid;
}

/* Return 0 if expect_name != NULL and there is no matching actual_name */
static int check_name(OSSL_CMP_CTX *ctx,
                      const char *actual_desc, const X509_NAME *actual_name,
                      const char *expect_desc, const X509_NAME *expect_name)
{
    char *str;

    if (expect_name == NULL)
        return 1; /* no expectation, thus trivially fulfilled */

    /* make sure that a matching name is there */
    if (actual_name == NULL) {
        ossl_cmp_log1(WARN, ctx, "missing %s", actual_desc);
        return 0;
    }
    if (X509_NAME_cmp(actual_name, expect_name) == 0)
        return 1;

    if ((str = X509_NAME_oneline(actual_name, NULL, 0)) != NULL)
        ossl_cmp_log2(INFO, ctx, " actual name in %s = %s", actual_desc, str);
    OPENSSL_free(str);
    if ((str = X509_NAME_oneline(expect_name, NULL, 0)) != NULL)
        ossl_cmp_log2(INFO, ctx, " does not match %s = %s", expect_desc, str);
    OPENSSL_free(str);
    return 0;
}

/* Return 0 if skid != NULL and there is no matching subject key ID in cert */
static int check_kid(OSSL_CMP_CTX *ctx,
                     X509 *cert, const ASN1_OCTET_STRING *skid)
{
    char *actual, *expect;
    const ASN1_OCTET_STRING *ckid = X509_get0_subject_key_id(cert);

    if (skid == NULL)
        return 1; /* no expectation, thus trivially fulfilled */

    /* make sure that the expected subject key identifier is there */
    if (ckid == NULL) {
        ossl_cmp_warn(ctx, "missing Subject Key Identifier in certificate");
        return 0;
    }
    if (ASN1_OCTET_STRING_cmp(ckid, skid) == 0)
        return 1;

    if ((actual = OPENSSL_buf2hexstr(ckid->data, ckid->length)) != NULL)
        ossl_cmp_log1(INFO, ctx, " cert Subject Key Identifier = %s", actual);
    if ((expect = OPENSSL_buf2hexstr(skid->data, skid->length)) != NULL)
        ossl_cmp_log1(INFO, ctx, " does not match senderKID    = %s", expect);
    OPENSSL_free(expect);
    OPENSSL_free(actual);
    return 0;
}

static int already_checked(X509 *cert, const STACK_OF(X509) *already_checked)
{
    int i;

    for (i = sk_X509_num(already_checked /* may be NULL */); i > 0; i--)
        if (X509_cmp(sk_X509_value(already_checked, i - 1), cert) == 0)
            return 1;
    return 0;
}

/*
 * Check if the given cert is acceptable as sender cert of the given message.
 * The subject DN must match, the subject key ID as well if present in the msg,
 * and the cert must be current (checked if ctx->trusted is not NULL).
 * Note that cert revocation etc. is checked by OSSL_CMP_validate_cert_path().
 *
 * Returns 0 on error or not acceptable, else 1.
 */
static int cert_acceptable(OSSL_CMP_CTX *ctx,
                           const char *desc1, const char *desc2, X509 *cert,
                           const STACK_OF(X509) *already_checked1,
                           const STACK_OF(X509) *already_checked2,
                           const OSSL_CMP_MSG *msg)
{
    X509_STORE *ts = ctx->trusted;
    int self_issued = X509_check_issued(cert, cert) == X509_V_OK;
    char *str;
    X509_VERIFY_PARAM *vpm = ts != NULL ? X509_STORE_get0_param(ts) : NULL;
    int time_cmp;

    ossl_cmp_log3(INFO, ctx, " considering %s%s %s with..",
                  self_issued ? "self-issued ": "", desc1, desc2);
    if ((str = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0)) != NULL)
        ossl_cmp_log1(INFO, ctx, "  subject = %s", str);
    OPENSSL_free(str);
    if (!self_issued) {
        str = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        if (str != NULL)
            ossl_cmp_log1(INFO, ctx, "  issuer  = %s", str);
        OPENSSL_free(str);
    }

    if (already_checked(cert, already_checked1)
            || already_checked(cert, already_checked2)) {
        ossl_cmp_info(ctx, " cert has already been checked");
        return 0;
    }

    time_cmp = X509_cmp_timeframe(vpm, X509_get0_notBefore(cert),
                                  X509_get0_notAfter(cert));
    if (time_cmp != 0) {
        ossl_cmp_warn(ctx, time_cmp > 0 ? "cert has expired"
                                        : "cert is not yet valid");
        return 0;
    }

    if (!check_name(ctx,
                    "cert subject", X509_get_subject_name(cert),
                    "sender field", msg->header->sender->d.directoryName))
        return 0;

    if (!check_kid(ctx, cert, msg->header->senderKID))
        return 0;
    /* acceptable also if there is no senderKID in msg header */
    ossl_cmp_info(ctx, " cert seems acceptable");
    return 1;
}

static int check_msg_valid_cert(OSSL_CMP_CTX *ctx, X509_STORE *store,
                                X509 *scrt, const OSSL_CMP_MSG *msg)
{
    if (!verify_signature(ctx, msg, scrt)) {
        ossl_cmp_warn(ctx, "msg signature verification failed");
        return 0;
    }
    if (OSSL_CMP_validate_cert_path(ctx, store, scrt))
        return 1;

    ossl_cmp_warn(ctx,
                  "msg signature validates but cert path validation failed");
    return 0;
}

/*
 * Exceptional handling for 3GPP TS 33.310 [3G/LTE Network Domain Security
 * (NDS); Authentication Framework (AF)], only to use for IP messages
 * and if the ctx option is explicitly set: use self-issued certificates
 * from extraCerts as trust anchor to validate sender cert and msg -
 * provided it also can validate the newly enrolled certificate
 */
static int check_msg_valid_cert_3gpp(OSSL_CMP_CTX *ctx, X509 *scrt,
                                     const OSSL_CMP_MSG *msg)
{
    int valid = 0;
    X509_STORE *store;

    if (!ctx->permitTAInExtraCertsForIR)
        return 0;

    if ((store = X509_STORE_new()) == NULL
            || !ossl_cmp_X509_STORE_add1_certs(store, msg->extraCerts,
                                               1 /* self-issued only */))
        goto err;

    /* store does not include CRLs */
    valid = OSSL_CMP_validate_cert_path(ctx, store, scrt);
    if (!valid) {
        ossl_cmp_warn(ctx,
                      "also exceptional 3GPP mode cert path validation failed");
    } else {
        /*
         * verify that the newly enrolled certificate (which assumed rid ==
         * OSSL_CMP_CERTREQID) can also be validated with the same trusted store
         */
        EVP_PKEY *privkey = OSSL_CMP_CTX_get0_newPkey(ctx, 1);
        OSSL_CMP_CERTRESPONSE *crep =
            ossl_cmp_certrepmessage_get0_certresponse(msg->body->value.ip,
                                                      OSSL_CMP_CERTREQID);
        X509 *newcrt = ossl_cmp_certresponse_get1_certificate(privkey, crep);
        /*
         * maybe better use get_cert_status() from cmp_client.c, which catches
         * errors
         */
        valid = OSSL_CMP_validate_cert_path(ctx, store, newcrt);
        X509_free(newcrt);
    }

 err:
    X509_STORE_free(store);
    return valid;
}

/*
 * Try all certs in given list for verifying msg, normally or in 3GPP mode.
 * If already_checked1 == NULL then certs are assumed to be the msg->extraCerts.
 */
static int check_msg_with_certs(OSSL_CMP_CTX *ctx, STACK_OF(X509) *certs,
                                const char *desc,
                                const STACK_OF(X509) *already_checked1,
                                const STACK_OF(X509) *already_checked2,
                                const OSSL_CMP_MSG *msg, int mode_3gpp)
{
    int in_extraCerts = already_checked1 == NULL;
    int n_acceptable_certs = 0;
    int i;

    if (sk_X509_num(certs) <= 0) {
        ossl_cmp_log1(WARN, ctx, "no %s", desc);
        return 0;
    }

    for (i = 0; i < sk_X509_num(certs); i++) { /* certs may be NULL */
        X509 *cert = sk_X509_value(certs, i);

        if (!ossl_assert(cert != NULL))
            return 0;
        if (!cert_acceptable(ctx, "cert from", desc, cert,
                             already_checked1, already_checked2, msg))
            continue;
        n_acceptable_certs++;
        if (mode_3gpp ? check_msg_valid_cert_3gpp(ctx, cert, msg)
                      : check_msg_valid_cert(ctx, ctx->trusted, cert, msg)) {
            /* store successful sender cert for further msgs in transaction */
            if (!X509_up_ref(cert))
                return 0;
            if (!ossl_cmp_ctx_set0_validatedSrvCert(ctx, cert)) {
                X509_free(cert);
                return 0;
            }
            return 1;
        }
    }
    if (in_extraCerts && n_acceptable_certs == 0)
        ossl_cmp_warn(ctx, "no acceptable cert in extraCerts");
    return 0;
}

/*
 * Verify msg trying first ctx->untrusted_certs, which should include extraCerts
 * at its front, then trying the trusted certs in truststore (if any) of ctx.
 */
static int check_msg_all_certs(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg,
                               int mode_3gpp)
{
    int ret = 0;

    if (mode_3gpp
            && ((!ctx->permitTAInExtraCertsForIR
                     || ossl_cmp_msg_get_bodytype(msg) != OSSL_CMP_PKIBODY_IP)))
        return 0;

    ossl_cmp_info(ctx,
                  mode_3gpp ? "normal mode failed; trying now 3GPP mode trusting extraCerts"
                            : "trying first normal mode using trust store");
    if (check_msg_with_certs(ctx, msg->extraCerts, "extraCerts",
                             NULL, NULL, msg, mode_3gpp))
        return 1;
    if (check_msg_with_certs(ctx, ctx->untrusted_certs, "untrusted certs",
                             msg->extraCerts, NULL, msg, mode_3gpp))
        return 1;

    if (ctx->trusted == NULL) {
        ossl_cmp_warn(ctx, mode_3gpp ? "no self-issued extraCerts"
                                     : "no trusted store");
    } else {
        STACK_OF(X509) *trusted = X509_STORE_get1_all_certs(ctx->trusted);
        ret = check_msg_with_certs(ctx, trusted,
                                   mode_3gpp ? "self-issued extraCerts"
                                             : "certs in trusted store",
                                   msg->extraCerts, ctx->untrusted_certs,
                                   msg, mode_3gpp);
        sk_X509_pop_free(trusted, X509_free);
    }
    return ret;
}

static int no_log_cb(const char *func, const char *file, int line,
                     OSSL_CMP_severity level, const char *msg)
{
    return 1;
}

/* verify message signature with any acceptable and valid candidate cert */
static int check_msg_find_cert(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg)
{
    X509 *scrt = ctx->validatedSrvCert; /* previous successful sender cert */
    GENERAL_NAME *sender = msg->header->sender;
    char *sname = NULL;
    char *skid_str = NULL;
    const ASN1_OCTET_STRING *skid = msg->header->senderKID;
    OSSL_CMP_log_cb_t backup_log_cb = ctx->log_cb;
    int res = 0;

    if (sender == NULL || msg->body == NULL)
        return 0; /* other NULL cases already have been checked */
    if (sender->type != GEN_DIRNAME) {
        CMPerr(0, CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
        return 0;
    }

    /* dump any hitherto errors to avoid confusion when printing further ones */
    OSSL_CMP_CTX_print_errors(ctx);

    /*
     * try first cached scrt, used successfully earlier in same transaction,
     * for validating this and any further msgs where extraCerts may be left out
     */
    if (scrt != NULL) {
        (void)ERR_set_mark();
        ossl_cmp_info(ctx,
                      "trying to verify msg signature with previously validated cert");
        if (cert_acceptable(ctx, "previously validated", "sender cert", scrt,
                            NULL, NULL, msg)
                && (check_msg_valid_cert(ctx, ctx->trusted, scrt, msg)
                    || check_msg_valid_cert_3gpp(ctx, scrt, msg))) {
            (void)ERR_pop_to_mark();
            return 1;
        }
        (void)ERR_pop_to_mark();
        /* cached sender cert has shown to be no more successfully usable */
        (void)ossl_cmp_ctx_set0_validatedSrvCert(ctx, NULL);
    }

    /* enable clearing irrelevant errors in attempts to validate sender certs */
    (void)ERR_set_mark();
    ctx->log_cb = no_log_cb; /* temporarily disable logging */
    res = check_msg_all_certs(ctx, msg, 0 /* using ctx->trusted */)
            || check_msg_all_certs(ctx, msg, 1 /* 3gpp */);
    ctx->log_cb = backup_log_cb;
    if (res) {
        /* discard any diagnostic information on trying to use certs */
        (void)ERR_pop_to_mark();
        goto end;
    }
    /* failed finding a sender cert that verifies the message signature */
    (void)ERR_clear_last_mark();

    sname = X509_NAME_oneline(sender->d.directoryName, NULL, 0);
    skid_str = skid == NULL ? NULL
                            : OPENSSL_buf2hexstr(skid->data, skid->length);
    if (ctx->log_cb != NULL) {
        ossl_cmp_info(ctx, "trying to verify msg signature with a valid cert that..");
        if (sname != NULL)
            ossl_cmp_log1(INFO, ctx, "matches msg sender    = %s", sname);
        if (skid_str != NULL)
            ossl_cmp_log1(INFO, ctx, "matches msg senderKID = %s", skid_str);
        else
            ossl_cmp_info(ctx, "while msg header does not contain senderKID");
        /* re-do the above checks (just) for adding diagnostic information */
        check_msg_all_certs(ctx, msg, 0 /* using ctx->trusted */);
        check_msg_all_certs(ctx, msg, 1 /* 3gpp */);
    }

    CMPerr(0, CMP_R_NO_SUITABLE_SENDER_CERT);
    if (sname != NULL) {
        ERR_add_error_txt(NULL, "for msg sender name = ");
        ERR_add_error_txt(NULL, sname);
    }
    if (skid_str != NULL) {
        ERR_add_error_txt(" and ", "for msg senderKID = ");
        ERR_add_error_txt(NULL, skid_str);
    }

 end:
    OPENSSL_free(sname);
    OPENSSL_free(skid_str);
    return res;
}

/*
 * Validate the protection of the given PKIMessage using either password-
 * based mac (PBM) or a signature algorithm. In the case of signature algorithm,
 * the sender certificate can have been pinned by providing it in ctx->srvCert,
 * else it is searched in msg->extraCerts, ctx->untrusted_certs, in ctx->trusted
 * (in this order) and is path is validated against ctx->trusted.
 *
 * If ctx->permitTAInExtraCertsForIR is true and when validating a CMP IP msg,
 * the trust anchor for validating the IP msg may be taken from msg->extraCerts
 * if a self-issued certificate is found there that can be used to
 * validate the enrolled certificate returned in the IP.
 * This is according to the need given in 3GPP TS 33.310.
 *
 * Returns 1 on success, 0 on error or validation failed.
 */
int OSSL_CMP_validate_msg(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg)
{
    X509_ALGOR *alg;
    int nid = NID_undef, pk_nid = NID_undef;
    const ASN1_OBJECT *algorOID = NULL;
    X509 *scrt;

    if (ctx == NULL || msg == NULL
            || msg->header == NULL || msg->body == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if ((alg = msg->header->protectionAlg) == NULL /* unprotected message */
            || msg->protection == NULL || msg->protection->data == NULL) {
        CMPerr(0, CMP_R_MISSING_PROTECTION);
        return 0;
    }

    /* determine the nid for the used protection algorithm */
    X509_ALGOR_get0(&algorOID, NULL, NULL, alg);
    nid = OBJ_obj2nid(algorOID);

    switch (nid) {
        /* 5.1.3.1.  Shared Secret Information */
    case NID_id_PasswordBasedMAC:
        if (ctx->secretValue == 0) {
            CMPerr(0, CMP_R_CHECKING_PBM_NO_SECRET_AVAILABLE);
            break;
        }

        if (verify_PBMAC(msg, ctx->secretValue)) {
            /*
             * RFC 4210, 5.3.2: 'Note that if the PKI Message Protection is
             * "shared secret information", then any certificate transported in
             * the caPubs field may be directly trusted as a root CA
             * certificate by the initiator.'
             */
            switch (ossl_cmp_msg_get_bodytype(msg)) {
            case -1:
                return 0;
            case OSSL_CMP_PKIBODY_IP:
            case OSSL_CMP_PKIBODY_CP:
            case OSSL_CMP_PKIBODY_KUP:
            case OSSL_CMP_PKIBODY_CCP:
                if (ctx->trusted != NULL) {
                    STACK_OF(X509) *certs = msg->body->value.ip->caPubs;
                    /* value.ip is same for cp, kup, and ccp */

                    if (!ossl_cmp_X509_STORE_add1_certs(ctx->trusted, certs, 0))
                        /* adds both self-issued and not self-issued certs */
                        return 0;
                }
                break;
            default:
                break;
            }
            return 1;
        }
        break;

        /*
         * 5.1.3.2 DH Key Pairs
         * Not yet supported
         */
    case NID_id_DHBasedMac:
        CMPerr(0, CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC);
        break;

        /*
         * 5.1.3.3.  Signature
         */
    default:
        if (!OBJ_find_sigid_algs(OBJ_obj2nid(alg->algorithm), NULL, &pk_nid)
                || pk_nid == NID_undef) {
            CMPerr(0, CMP_R_UNKNOWN_ALGORITHM_ID);
            break;
        }
        /* validate sender name of received msg */
        if (msg->header->sender->type != GEN_DIRNAME) {
            CMPerr(0, CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
            break; /* FR#42: support for more than X509_NAME */
        }
        /*
         * Compare actual sender name of response with expected sender name.
         * Expected name can be set explicitly or the subject of ctx->srvCert.
         * Mitigates risk to accept misused certificate of an unauthorized
         * entity of a trusted hierarchy.
         */
        if (!check_name(ctx, "sender DN field",
                        msg->header->sender->d.directoryName,
                        "expected sender", ctx->expected_sender))
            break;
        /* Note: if recipient was NULL-DN it could be learned here if needed */

        scrt = ctx->srvCert;
        if (scrt == NULL) {
            if (check_msg_find_cert(ctx, msg))
                return 1;
        } else { /* use pinned sender cert */
            /* use ctx->srvCert for signature check even if not acceptable */
            if (verify_signature(ctx, msg, scrt))
                return 1;
            /* call cert_acceptable() for adding diagnostic information */
            (void)cert_acceptable(ctx, "explicitly set", "sender cert", scrt,
                                  NULL, NULL, msg);
            ossl_cmp_warn(ctx, "msg signature verification failed");
            CMPerr(0, CMP_R_SRVCERT_DOES_NOT_VALIDATE_MSG);
        }
        break;
    }
    return 0;
}


/*-
 * Check received message (i.e., response by server or request from client)
 * Any msg->extraCerts are prepended to ctx->untrusted_certs
 *
 * Ensures that:
 * it has a valid body type
 * its protection is valid (or invalid/absent, but only if a callback function
 *     is present and yields a positive result using also the supplied argument)
 * its transaction ID matches the previous transaction ID stored in ctx (if any)
 * its recipNonce matches the previous senderNonce stored in the ctx (if any)
 *
 * If everything is fine:
 * learns the senderNonce from the received message,
 * learns the transaction ID if it is not yet in ctx.
 *
 * returns body type (which is >= 0) of the message on success, -1 on error
 */
int ossl_cmp_msg_check_received(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg,
                                ossl_cmp_allow_unprotected_cb_t cb, int cb_arg)
{
    int rcvd_type;

    if (!ossl_assert(ctx != NULL && msg != NULL))
        return -1;

    if (sk_X509_num(msg->extraCerts) > 10)
        ossl_cmp_warn(ctx,
                      "received CMP message contains more than 10 extraCerts");

    /* validate message protection */
    if (msg->header->protectionAlg != 0) {
        /* detect explicitly permitted exceptions for invalid protection */
        if (!OSSL_CMP_validate_msg(ctx, msg)
                && (cb == NULL || (*cb)(ctx, msg, 1, cb_arg) <= 0)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            CMPerr(0, CMP_R_ERROR_VALIDATING_PROTECTION);
            return -1;
#endif
        }
    } else {
        /* detect explicitly permitted exceptions for missing protection */
        if (cb == NULL || (*cb)(ctx, msg, 0, cb_arg) <= 0) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            CMPerr(0, CMP_R_MISSING_PROTECTION);
            return -1;
#endif
        }
    }

    /* check CMP version number in header */
    if (ossl_cmp_hdr_get_pvno(OSSL_CMP_MSG_get0_header(msg)) != OSSL_CMP_PVNO) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        CMPerr(0, CMP_R_UNEXPECTED_PVNO);
        return -1;
#endif
    }

    if ((rcvd_type = ossl_cmp_msg_get_bodytype(msg)) < 0) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        CMPerr(0, CMP_R_PKIBODY_ERROR);
        return -1;
#endif
    }

    /* compare received transactionID with the expected one in previous msg */
    if (ctx->transactionID != NULL
            && (msg->header->transactionID == NULL
                || ASN1_OCTET_STRING_cmp(ctx->transactionID,
                                         msg->header->transactionID) != 0)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        CMPerr(0, CMP_R_TRANSACTIONID_UNMATCHED);
        return -1;
#endif
    }

    /* compare received nonce with the one we sent */
    if (ctx->senderNonce != NULL
            && (msg->header->recipNonce == NULL
                || ASN1_OCTET_STRING_cmp(ctx->senderNonce,
                                         msg->header->recipNonce) != 0)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        CMPerr(0, CMP_R_RECIPNONCE_UNMATCHED);
        return -1;
#endif
    }

    /*
     * RFC 4210 section 5.1.1 states: the recipNonce is copied from
     * the senderNonce of the previous message in the transaction.
     * --> Store for setting in next message
     */
    if (!ossl_cmp_ctx_set1_recipNonce(ctx, msg->header->senderNonce))
        return -1;

    /* if not yet present, learn transactionID */
    if (ctx->transactionID == NULL
        && !OSSL_CMP_CTX_set1_transactionID(ctx, msg->header->transactionID))
        return -1;

    /*
     * Store any provided extraCerts in ctx for future use,
     * such that they are available to ctx->certConf_cb and
     * the peer does not need to send them again in the same transaction.
     * For efficiency, the extraCerts are prepended so they get used first.
     */
    if (!ossl_cmp_sk_X509_add1_certs(ctx->untrusted_certs, msg->extraCerts,
                                     0 /* this allows self-issued certs */,
                                     1 /* no_dups */, 1 /* prepend */))
        return -1;

    return rcvd_type;
}

int ossl_cmp_verify_popo(const OSSL_CMP_MSG *msg, int accept_RAVerified)
{
    if (!ossl_assert(msg != NULL && msg->body != NULL))
        return 0;
    switch (msg->body->type) {
    case OSSL_CMP_PKIBODY_P10CR:
        {
            X509_REQ *req = msg->body->value.p10cr;

            if (X509_REQ_verify(req, X509_REQ_get0_pubkey(req)) <= 0) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
                CMPerr(0, CMP_R_REQUEST_NOT_ACCEPTED);
                return 0;
#endif
            }
        }
        break;
    case OSSL_CMP_PKIBODY_IR:
    case OSSL_CMP_PKIBODY_CR:
    case OSSL_CMP_PKIBODY_KUR:
        if (!OSSL_CRMF_MSGS_verify_popo(msg->body->value.ir, OSSL_CMP_CERTREQID,
                                        accept_RAVerified)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            return 0;
#endif
        }
        break;
    default:
        CMPerr(0, CMP_R_PKIBODY_ERROR);
        return 0;
    }
    return 1;
}
