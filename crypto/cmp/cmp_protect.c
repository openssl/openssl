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

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/*
 * This function is also used for verification from cmp_vfy.
 *
 * Calculate protection for given PKImessage utilizing the given credentials
 * and the algorithm parameters set inside the message header's protectionAlg.
 *
 * Either secret or pkey must be set, the other must be NULL. Attempts doing
 * PBMAC in case 'secret' is set and signature if 'pkey' is set - but will only
 * do the protection already marked in msg->header->protectionAlg.
 *
 * returns ptr to ASN1_BIT_STRING containing protection on success, else NULL
 */
ASN1_BIT_STRING *ossl_cmp_calc_protection(const OSSL_CMP_MSG *msg,
                                          const ASN1_OCTET_STRING *secret,
                                          EVP_PKEY *pkey)
{
    ASN1_BIT_STRING *prot = NULL;
    CMP_PROTECTEDPART prot_part;
    const ASN1_OBJECT *algorOID = NULL;
    int len;
    size_t prot_part_der_len;
    unsigned char *prot_part_der = NULL;
    size_t sig_len;
    unsigned char *protection = NULL;
    const void *ppval = NULL;
    int pptype = 0;
    OSSL_CRMF_PBMPARAMETER *pbm = NULL;
    ASN1_STRING *pbm_str = NULL;
    const unsigned char *pbm_str_uc = NULL;
    EVP_MD_CTX *evp_ctx = NULL;
    int md_NID;
    const EVP_MD *md = NULL;

    if (!ossl_assert(msg != NULL))
        return NULL;

    /* construct data to be signed */
    prot_part.header = msg->header;
    prot_part.body = msg->body;

    len = i2d_CMP_PROTECTEDPART(&prot_part, &prot_part_der);
    if (len < 0 || prot_part_der == NULL) {
        CMPerr(0, CMP_R_ERROR_CALCULATING_PROTECTION);
        goto end;
    }
    prot_part_der_len = (size_t) len;

    if (msg->header->protectionAlg == NULL) {
        CMPerr(0, CMP_R_UNKNOWN_ALGORITHM_ID);
        goto end;
    }
    X509_ALGOR_get0(&algorOID, &pptype, &ppval, msg->header->protectionAlg);

    if (secret != NULL && pkey == NULL) {
        if (ppval == NULL) {
            CMPerr(0, CMP_R_ERROR_CALCULATING_PROTECTION);
            goto end;
        }
        if (NID_id_PasswordBasedMAC != OBJ_obj2nid(algorOID)) {
            CMPerr(0, CMP_R_WRONG_ALGORITHM_OID);
            goto end;
        }
        pbm_str = (ASN1_STRING *)ppval;
        pbm_str_uc = pbm_str->data;
        pbm = d2i_OSSL_CRMF_PBMPARAMETER(NULL, &pbm_str_uc, pbm_str->length);
        if (pbm == NULL) {
            CMPerr(0, CMP_R_WRONG_ALGORITHM_OID);
            goto end;
        }

        if (!OSSL_CRMF_pbm_new(pbm, prot_part_der, prot_part_der_len,
                               secret->data, secret->length,
                               &protection, &sig_len))
            goto end;
    } else if (secret == NULL && pkey != NULL) {
        /* TODO combine this with large parts of CRMF_poposigningkey_init() */
        /* EVP_DigestSignInit() checks that pkey type is correct for the alg */

        if (!OBJ_find_sigid_algs(OBJ_obj2nid(algorOID), &md_NID, NULL)
                || (md = EVP_get_digestbynid(md_NID)) == NULL
                || (evp_ctx = EVP_MD_CTX_new()) == NULL) {
            CMPerr(0, CMP_R_UNKNOWN_ALGORITHM_ID);
            goto end;
        }
        if (EVP_DigestSignInit(evp_ctx, NULL, md, NULL, pkey) <= 0
                || EVP_DigestSignUpdate(evp_ctx, prot_part_der,
                                        prot_part_der_len) <= 0
                || EVP_DigestSignFinal(evp_ctx, NULL, &sig_len) <= 0
                || (protection = OPENSSL_malloc(sig_len)) == NULL
                || EVP_DigestSignFinal(evp_ctx, protection, &sig_len) <= 0) {
            CMPerr(0, CMP_R_ERROR_CALCULATING_PROTECTION);
            goto end;
        }
    } else {
        CMPerr(0, CMP_R_INVALID_ARGS);
        goto end;
    }

    if ((prot = ASN1_BIT_STRING_new()) == NULL)
        goto end;
    /* OpenSSL defaults all bit strings to be encoded as ASN.1 NamedBitList */
    prot->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    if (!ASN1_BIT_STRING_set(prot, protection, sig_len)) {
        ASN1_BIT_STRING_free(prot);
        prot = NULL;
    }

 end:
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    EVP_MD_CTX_free(evp_ctx);
    OPENSSL_free(protection);
    OPENSSL_free(prot_part_der);
    return prot;
}

int ossl_cmp_msg_add_extraCerts(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)
{
    if (!ossl_assert(ctx != NULL && msg != NULL))
        return 0;

    if (msg->extraCerts == NULL
            && (msg->extraCerts = sk_X509_new_null()) == NULL)
        return 0;

    if (ctx->clCert != NULL) {
        /* Make sure that our own cert gets sent, in the first position */
        if (!X509_up_ref(ctx->clCert))
            return 0;
        if (!sk_X509_push(msg->extraCerts, ctx->clCert)) {
            X509_free(ctx->clCert);
            return 0;
        }
        /* if we have untrusted store, try to add intermediate certs */
        if (ctx->untrusted_certs != NULL) {
            STACK_OF(X509) *chain =
                ossl_cmp_build_cert_chain(ctx->untrusted_certs, ctx->clCert);
            int res = ossl_cmp_sk_X509_add1_certs(msg->extraCerts, chain,
                                                  1 /* no self-signed */,
                                                  1 /* no duplicates */, 0);
            sk_X509_pop_free(chain, X509_free);
            if (res == 0)
                return 0;
        }
    }

    /* add any additional certificates from ctx->extraCertsOut */
    if (!ossl_cmp_sk_X509_add1_certs(msg->extraCerts, ctx->extraCertsOut, 0,
                                     1 /* no duplicates */, 0))
        return 0;

    /* if none was found avoid empty ASN.1 sequence */
    if (sk_X509_num(msg->extraCerts) == 0) {
        sk_X509_free(msg->extraCerts);
        msg->extraCerts = NULL;
    }
    return 1;
}

/*
 * Create an X509_ALGOR structure for PasswordBasedMAC protection based on
 * the pbm settings in the context
 * returns pointer to X509_ALGOR on success, NULL on error
 */
static X509_ALGOR *create_pbmac_algor(OSSL_CMP_CTX *ctx)
{
    X509_ALGOR *alg = NULL;
    OSSL_CRMF_PBMPARAMETER *pbm = NULL;
    unsigned char *pbm_der = NULL;
    int pbm_der_len;
    ASN1_STRING *pbm_str = NULL;

    if (!ossl_assert(ctx != NULL))
        return NULL;

    alg = X509_ALGOR_new();
    pbm = OSSL_CRMF_pbmp_new(ctx->pbm_slen, ctx->pbm_owf, ctx->pbm_itercnt,
                             ctx->pbm_mac);
    pbm_str = ASN1_STRING_new();
    if (alg == NULL || pbm == NULL || pbm_str == NULL)
        goto err;

    if ((pbm_der_len = i2d_OSSL_CRMF_PBMPARAMETER(pbm, &pbm_der)) < 0)
        goto err;

    if (!ASN1_STRING_set(pbm_str, pbm_der, pbm_der_len))
        goto err;
    OPENSSL_free(pbm_der);

    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_id_PasswordBasedMAC),
                    V_ASN1_SEQUENCE, pbm_str);
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    return alg;

 err:
    ASN1_STRING_free(pbm_str);
    X509_ALGOR_free(alg);
    OPENSSL_free(pbm_der);
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    return NULL;
}

int ossl_cmp_msg_protect(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)
{
    if (!ossl_assert(ctx != NULL && msg != NULL))
        return 0;

    if (ctx->unprotectedSend)
        return 1;

    /* use PasswordBasedMac according to 5.1.3.1 if secretValue is given */
    if (ctx->secretValue != NULL) {
        if ((msg->header->protectionAlg = create_pbmac_algor(ctx)) == NULL)
            goto err;
        if (ctx->referenceValue != NULL
                && !ossl_cmp_hdr_set1_senderKID(msg->header,
                                                ctx->referenceValue))
            goto err;

        /*
         * add any additional certificates from ctx->extraCertsOut
         * while not needed to validate the signing cert, the option to do
         * this might be handy for certain use cases
         */
        if (!ossl_cmp_msg_add_extraCerts(ctx, msg))
            goto err;

        if ((msg->protection =
             ossl_cmp_calc_protection(msg, ctx->secretValue, NULL)) == NULL)
            goto err;
    } else {
        /*
         * use MSG_SIG_ALG according to 5.1.3.3 if client Certificate and
         * private key is given
         */
        if (ctx->clCert != NULL && ctx->pkey != NULL) {
            const ASN1_OCTET_STRING *subjKeyIDStr = NULL;
            int algNID = 0;
            ASN1_OBJECT *alg = NULL;

            /* make sure that key and certificate match */
            if (!X509_check_private_key(ctx->clCert, ctx->pkey)) {
                CMPerr(0, CMP_R_CERT_AND_KEY_DO_NOT_MATCH);
                goto err;
            }

            if (msg->header->protectionAlg == NULL)
                if ((msg->header->protectionAlg = X509_ALGOR_new()) == NULL)
                    goto err;

            if (!OBJ_find_sigid_by_algs(&algNID, ctx->digest,
                                        EVP_PKEY_id(ctx->pkey))) {
                CMPerr(0, CMP_R_UNSUPPORTED_KEY_TYPE);
                goto err;
            }
            if ((alg = OBJ_nid2obj(algNID)) == NULL)
                goto err;
            if (!X509_ALGOR_set0(msg->header->protectionAlg,
                                 alg, V_ASN1_UNDEF, NULL)) {
                ASN1_OBJECT_free(alg);
                goto err;
            }

            /*
             * set senderKID to keyIdentifier of the used certificate according
             * to section 5.1.1
             */
            subjKeyIDStr = X509_get0_subject_key_id(ctx->clCert);
            if (subjKeyIDStr != NULL
                    && !ossl_cmp_hdr_set1_senderKID(msg->header, subjKeyIDStr))
                goto err;

            /*
             * Add ctx->clCert followed, if possible, by its chain built
             * from ctx->untrusted_certs, and then ctx->extraCertsOut
             */
            if (!ossl_cmp_msg_add_extraCerts(ctx, msg))
                goto err;

            if ((msg->protection =
                 ossl_cmp_calc_protection(msg, NULL, ctx->pkey)) == NULL)
                goto err;
        } else {
            CMPerr(0, CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION);
            goto err;
        }
    }

    return 1;
 err:
    CMPerr(0, CMP_R_ERROR_PROTECTING_MESSAGE);
    return 0;
}
