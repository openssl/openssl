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

 /* NAMING
  * The 0 version uses the supplied structure pointer directly in the parent and
  * it will be freed up when the parent is freed. In the above example crl would
  * be freed but rev would not.
  *
  * The 1 function uses a copy of the supplied structure pointer (or in some
  * cases increases its link count) in the parent and so both (x and obj above)
  * should be freed up.
  */

/*
 * In this file are the functions which set the individual items inside
 * the CMP structures
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>

#include <time.h>
#include <string.h>

#include "cmp_int.h"


/* TODO DvO push this functions upstream to crypto/err (PR #add_error_txt) */
/*
 * Appends text to the extra error data field of the last error message in
 * OpenSSL's error queue, after adding the given separator string. Note that,
 * in contrast, ERR_add_error_data() simply overwrites the previous contents
 * of the error data.
 */
void CMP_add_error_txt(const char *separator, const char *txt)
{
    const char *file;
    int line;
    const char *data;
    int flags;

    unsigned long err = ERR_peek_last_error();
    if (err == 0) {
        ERR_PUT_error(ERR_LIB_CMP, 0, err, "", 0);
    }

#define MAX_DATA_LEN 4096-100 /* workaround for ERR_print_errors_cb() limit */
    do {
        const char *curr, *next;
        int len;
        char *tmp;
        ERR_peek_last_error_line_data(&file, &line, &data, &flags);
        if (!(flags & ERR_TXT_STRING))
            data = "";
        len = (int)strlen(data);
        curr = next = txt;
        while (*next != '\0' &&
               len + strlen(separator) + (next - txt) < MAX_DATA_LEN) {
            curr = next;
            if (*separator != '\0') {
                next = strstr(curr, separator);
                if (next != NULL)
                    next += strlen(separator);
                else
                    next = curr + strlen(curr);
            } else
                next = curr + 1;
        }
        if (*next != '\0') { /* split error msg if error data gets too long */
            if (curr != txt) {
                tmp = OPENSSL_strndup(txt, curr - txt);
                ERR_add_error_data(3, data, separator, tmp);
                OPENSSL_free(tmp);
            }
            ERR_PUT_error(ERR_LIB_CMP, 0/* func */, err, file, line);
            txt = curr;
        } else {
            ERR_add_error_data(3, data, separator, txt);
            txt = next;
        }
    } while (*txt != '\0');
}

/* returns the header of the given CMP message or NULL on error */
OSSL_CMP_HDR *OSSL_CMP_MSG_get0_header(const OSSL_CMP_MSG *msg)
{
    return msg != NULL ? msg->header : NULL;
}

/* returns the pvno (as long int) of the given PKIHeader or NULL on error */
long OSSL_CMP_HDR_get_pvno(const OSSL_CMP_HDR *hdr)
{
    return hdr != NULL ? ASN1_INTEGER_get(hdr->pvno) : 0;
}

/* returns the transactionID of the given PKIHeader or NULL on error */
ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_transactionID(const OSSL_CMP_HDR *hdr)
{
    return hdr != NULL ? hdr->transactionID : NULL;
}

/* returns the senderNonce of the given PKIHeader or NULL on error */
ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_senderNonce(const OSSL_CMP_HDR *hdr)
{
    return hdr != NULL ? hdr->senderNonce : NULL;
}

/* returns the recipNonce of the given PKIHeader or NULL on error */
ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_recipNonce(const OSSL_CMP_HDR *hdr)
{
    return hdr != NULL ? hdr->recipNonce : NULL;
}

/*
 * Sets the protocol version number in PKIHeader.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set_version(OSSL_CMP_HDR *hdr, int version)
{
    if (hdr == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_SET_VERSION, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if (!ASN1_INTEGER_set(hdr->pvno, version)) {
        CMPerr(CMP_F_OSSL_CMP_HDR_SET_VERSION, CMP_R_OUT_OF_MEMORY);
        goto err;
    }

    return 1;

 err:
    return 0;
}


static int set1_general_name(GENERAL_NAME **tgt, const X509_NAME *src)
{
    GENERAL_NAME *gen = NULL;

    if (tgt == NULL) {
        CMPerr(CMP_F_SET1_GENERAL_NAME, CMP_R_NULL_ARGUMENT);
        goto err;
    }
    if ((gen = GENERAL_NAME_new()) == NULL)
        goto oom;

    gen->type = GEN_DIRNAME;

    if (src == NULL) { /* NULL DN */
        if ((gen->d.directoryName = X509_NAME_new()) == NULL)
            goto oom;
    } else if (!(X509_NAME_set(&gen->d.directoryName, (X509_NAME *)src))) {
    oom:
        CMPerr(CMP_F_SET1_GENERAL_NAME, CMP_R_OUT_OF_MEMORY);
        goto err;
    }

    GENERAL_NAME_free(*tgt);
    *tgt = gen;

    return 1;

 err:
    GENERAL_NAME_free(gen);
    return 0;
}

/*
 * Set the recipient name of PKIHeader.
 * when nm is NULL, recipient is set to an empty string
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set1_recipient(OSSL_CMP_HDR *hdr, const X509_NAME *nm)
{
    if (hdr == NULL)
        return 0;

    return set1_general_name(&hdr->recipient, nm);
}

/*
 * Set the sender name in PKIHeader.
 * when nm is NULL, sender is set to an empty string
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set1_sender(OSSL_CMP_HDR *hdr, const X509_NAME *nm)
{
    if (hdr == NULL)
        return 0;

    return set1_general_name(&hdr->sender, nm);
}

/*
 * free any previous value of the variable referenced via tgt
 * and assign either a copy of the src ASN1_OCTET_STRING or NULL.
 * returns 1 on success, 0 on error.
 */
int OSSL_CMP_ASN1_OCTET_STRING_set1(ASN1_OCTET_STRING **tgt,
                               const ASN1_OCTET_STRING *src)
{
    if (tgt == NULL) {
        CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1, CMP_R_NULL_ARGUMENT);
        goto err;
    }
    if (*tgt == src) /* self-assignment */
        return 1;
    ASN1_OCTET_STRING_free(*tgt);

    if (src != NULL) {
        if (!(*tgt = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)src))) {
            CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1, CMP_R_OUT_OF_MEMORY);
            goto err;
        }
    } else
        *tgt = NULL;

    return 1;
 err:
    return 0;
}

/*
 * free any previous value of the variable referenced via tgt
 * and assign either a copy of the byte string (with given length) or NULL.
 * returns 1 on success, 0 on error.
 */
int OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes, size_t len)
{
    ASN1_OCTET_STRING *new = NULL;
    int res = 0;

    if (tgt == NULL) {
        CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1_BYTES, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if (bytes != NULL) {
        if (!(new = ASN1_OCTET_STRING_new()) ||
            !(ASN1_OCTET_STRING_set(new, bytes, (int)len))) {
            CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1_BYTES,
                   CMP_R_OUT_OF_MEMORY);
            goto err;
        }

    }
    res = OSSL_CMP_ASN1_OCTET_STRING_set1(tgt, new);

 err:
    ASN1_OCTET_STRING_free(new);
    return res;
}

static int set1_aostr_else_random(ASN1_OCTET_STRING **tgt,
                                  const ASN1_OCTET_STRING *src, int len)
{
    unsigned char *bytes = NULL;
    int res = 0;

    if (src == NULL) { /* generate a random value if src == NULL */
        if ((bytes = (unsigned char *)OPENSSL_malloc(len)) == NULL) {
            CMPerr(CMP_F_SET1_AOSTR_ELSE_RANDOM, CMP_R_OUT_OF_MEMORY);
            goto err;
        }
        if (RAND_bytes(bytes, len) <= 0) {
            CMPerr(CMP_F_SET1_AOSTR_ELSE_RANDOM,CMP_R_FAILURE_OBTAINING_RANDOM);
            goto err;
        }
        res = OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(tgt, bytes, len);
    } else {
        res = OSSL_CMP_ASN1_OCTET_STRING_set1(tgt, src);
    }

 err:
    OPENSSL_free(bytes);
    return res;
}

/*
 * (re-)set given senderKID to given header
 *
 * senderKID: keyIdentifier of the sender's certificate or PBMAC reference value
 *       -- the reference number which the CA has previously issued
 *       -- to the end entity (together with the MACing key)
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set1_senderKID(OSSL_CMP_HDR *hdr,
                                const ASN1_OCTET_STRING *senderKID)
{
    if (hdr == NULL)
        return 0;
    return OSSL_CMP_ASN1_OCTET_STRING_set1(&hdr->senderKID, senderKID);
}

/*
 * (re-)set the messageTime to the current system time
 *
 * as in 5.1.1:
 *
 * The messageTime field contains the time at which the sender created
 * the message.  This may be useful to allow end entities to
 * correct/check their local time for consistency with the time on a
 * central system.
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set_messageTime(OSSL_CMP_HDR *hdr)
{
    if (hdr == NULL)
        goto err;

    if (hdr->messageTime == NULL)
        if ((hdr->messageTime = ASN1_GENERALIZEDTIME_new()) == NULL)
            goto err;

    if (ASN1_GENERALIZEDTIME_set(hdr->messageTime, time(NULL)) == NULL)
        goto err;
    return 1;

 err:
    CMPerr(CMP_F_OSSL_CMP_HDR_SET_MESSAGETIME, CMP_R_OUT_OF_MEMORY);
    return 0;
}

/*
 * push given ASN1_UTF8STRING to hdr->freeText and consume the given pointer
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_push0_freeText(OSSL_CMP_HDR *hdr, ASN1_UTF8STRING *text)
{
    if (hdr == NULL)
        goto err;
    if (text == NULL)
        goto err;

    if (hdr->freeText == NULL)
        if ((hdr->freeText = sk_ASN1_UTF8STRING_new_null()) == NULL)
            goto err;

    if (!(sk_ASN1_UTF8STRING_push(hdr->freeText, text)))
        goto err;

    return 1;

 err:
    CMPerr(CMP_F_OSSL_CMP_HDR_PUSH0_FREETEXT, CMP_R_OUT_OF_MEMORY);
    return 0;
}

/*
 * push an ASN1_UTF8STRING to hdr->freeText and don't consume the given pointer
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_push1_freeText(OSSL_CMP_HDR *hdr, ASN1_UTF8STRING *text)
{
    if (hdr == NULL || text == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_PUSH1_FREETEXT, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    hdr->freeText = CMP_PKIFREETEXT_push_str(hdr->freeText, (char *)text->data);
    return hdr->freeText != NULL;
}

/*
 * Pushes the given text string (unless it is NULL) to the given ft or to a
 * newly allocated freeText if ft is NULL.
 * Returns the new/updated freeText. On error frees ft and returns NULL
 */
OSSL_CMP_PKIFREETEXT *CMP_PKIFREETEXT_push_str(OSSL_CMP_PKIFREETEXT *ft,
                                               const char *text)
{
    ASN1_UTF8STRING *utf8string = NULL;

    if (text == NULL) {
        return ft;
    }

    if (ft == NULL && (ft = sk_ASN1_UTF8STRING_new_null()) == NULL)
        goto oom;
    if ((utf8string = ASN1_UTF8STRING_new()) == NULL)
        goto oom;
    if (!ASN1_STRING_set(utf8string, text, (int)strlen(text)))
        goto oom;
    if (!(sk_ASN1_UTF8STRING_push(ft, utf8string)))
        goto oom;
    return ft;

 oom:
    CMPerr(CMP_F_CMP_PKIFREETEXT_PUSH_STR, CMP_R_OUT_OF_MEMORY);
    sk_ASN1_UTF8STRING_pop_free(ft, ASN1_UTF8STRING_free);
    ASN1_UTF8STRING_free(utf8string);
    return NULL;
}

/*
 * Initialize the given PkiHeader structure with values set in the OSSL_CMP_CTX
 * This starts a new transaction in case ctx->transactionID is NULL.
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_init(OSSL_CMP_CTX *ctx, OSSL_CMP_HDR *hdr)
{
    X509_NAME *sender;
    X509_NAME *rcp = NULL;

    if (ctx == NULL || hdr == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_INIT, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    /* set the CMP version */
    if (!OSSL_CMP_HDR_set_version(hdr, OSSL_CMP_VERSION))
        goto err;

    /*
     * if neither client cert nor subject name given, sender name is not known
     * to the client and in that case set to NULL-DN
     */
    sender = ctx->clCert != NULL ?
        X509_get_subject_name(ctx->clCert) : ctx->subjectName;
    if (sender == NULL && ctx->referenceValue == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_INIT, CMP_R_NO_SENDER_NO_REFERENCE);
        goto err;
    }
    if (!OSSL_CMP_HDR_set1_sender(hdr, sender))
        goto err;

    /* determine recipient entry in PKIHeader */
    if (ctx->srvCert != NULL) {
        rcp = X509_get_subject_name(ctx->srvCert);
        /* set also as expected_sender of responses unless set explicitly */
        if (ctx->expected_sender == NULL && rcp != NULL &&
            !OSSL_CMP_CTX_set1_expected_sender(ctx, rcp))
        goto err;
    }
    else if (ctx->recipient != NULL)
        rcp = ctx->recipient;
    else if (ctx->issuer != NULL)
        rcp = ctx->issuer;
    else if (ctx->oldClCert != NULL)
        rcp = X509_get_issuer_name(ctx->oldClCert);
    else if (ctx->clCert != NULL)
        rcp = X509_get_issuer_name(ctx->clCert);
    if (!OSSL_CMP_HDR_set1_recipient(hdr, rcp))
        goto err;

    /* set current time as message time */
    if (!OSSL_CMP_HDR_set_messageTime(hdr))
        goto err;

    if (ctx->recipNonce != NULL)
        if (!OSSL_CMP_ASN1_OCTET_STRING_set1(&hdr->recipNonce, ctx->recipNonce))
            goto err;

    /*
     * set ctx->transactionID in CMP header
     * if ctx->transactionID is NULL, a random one is created with 128 bit
     * according to section 5.1.1:
     *
     * It is RECOMMENDED that the clients fill the transactionID field with
     * 128 bits of (pseudo-) random data for the start of a transaction to
     * reduce the probability of having the transactionID in use at the server.
     */
    if (ctx->transactionID == NULL &&
        !set1_aostr_else_random(&ctx->transactionID,NULL,
                                OSSL_CMP_TRANSACTIONID_LENGTH))
        goto err;
    if (!OSSL_CMP_ASN1_OCTET_STRING_set1(&hdr->transactionID,
                                         ctx->transactionID))
        goto err;

    /*
     * set random senderNonce
     * according to section 5.1.1:
     *
     * senderNonce                  present
     *         -- 128 (pseudo-)random bits
     * The senderNonce and recipNonce fields protect the PKIMessage against
     * replay attacks.      The senderNonce will typically be 128 bits of
     * (pseudo-) random data generated by the sender, whereas the recipNonce
     * is copied from the senderNonce of the previous message in the
     * transaction.
     */
    if (!set1_aostr_else_random(&hdr->senderNonce, NULL,
                                OSSL_CMP_SENDERNONCE_LENGTH))
        goto err;

    /* store senderNonce - for cmp with recipNonce in next outgoing msg */
    OSSL_CMP_CTX_set1_last_senderNonce(ctx, hdr->senderNonce);

#if 0
    /*
       freeText                [7] PKIFreeText                         OPTIONAL,
       -- this may be used to indicate context-specific instructions
       -- (this field is intended for human consumption)
     */
    if (ctx->freeText != NULL)
        if (!OSSL_CMP_HDR_push1_freeText(hdr, ctx->freeText))
            goto err;
#endif

    return 1;

 err:
    return 0;
}

/*
 * also used for verification from cmp_vfy
 *
 * calculate protection for given PKImessage utilizing the given credentials
 * and the algorithm parameters set inside the message header's protectionAlg.
 *
 * Either secret or pkey must be set, the other must be NULL. Attempts doing
 * PBMAC in case 'secret' is set and signature if 'pkey' is set - but will only
 * do the protection already marked in msg->header->protectionAlg.
 *
 * returns pointer to ASN1_BIT_STRING containing protection on success, NULL on
 * error
 */
ASN1_BIT_STRING *CMP_calc_protection(const OSSL_CMP_MSG *msg,
                                     const ASN1_OCTET_STRING *secret,
                                     const EVP_PKEY *pkey)
{
    ASN1_BIT_STRING *prot = NULL;
    CMP_PROTECTEDPART prot_part;
    OPENSSL_CMP_CONST ASN1_OBJECT *algorOID = NULL;

    int l;
    size_t prot_part_der_len;
    unsigned int mac_len;
    unsigned char *prot_part_der = NULL;
    unsigned char *mac = NULL;

    OPENSSL_CMP_CONST void *ppval = NULL;
    int pptype = 0;

    OSSL_CRMF_PBMPARAMETER *pbm = NULL;
    ASN1_STRING *pbm_str = NULL;
    const unsigned char *pbm_str_uc = NULL;

    EVP_MD_CTX *evp_ctx = NULL;
    int md_NID;
    const EVP_MD *md = NULL;


    /* construct data to be signed */
    prot_part.header = msg->header;
    prot_part.body = msg->body;

    l = i2d_CMP_PROTECTEDPART(&prot_part, &prot_part_der);
    if (l < 0 || prot_part_der == NULL)
        goto err;
    prot_part_der_len = (size_t) l;

    X509_ALGOR_get0(&algorOID, &pptype, &ppval, msg->header->protectionAlg);

    if (secret != NULL && pkey == NULL) {
        if (NID_id_PasswordBasedMAC == OBJ_obj2nid(algorOID)) {
            if (ppval == NULL)
                goto err;

            pbm_str = (ASN1_STRING *)ppval;
            pbm_str_uc = (unsigned char *)pbm_str->data;
            pbm = d2i_OSSL_CRMF_PBMPARAMETER(NULL, &pbm_str_uc, pbm_str->length);

            if (!(OSSL_CRMF_passwordBasedMac_new(pbm, prot_part_der,
                                                 prot_part_der_len,
                                                 secret->data, secret->length,
                                                 &mac, &mac_len)))
                goto err;
        } else {
            CMPerr(CMP_F_CMP_CALC_PROTECTION, CMP_R_WRONG_ALGORITHM_OID);
            goto err;
        }
    } else if (secret == NULL && pkey != NULL) {
        /* EVP_SignFinal() will check that pkey type is correct for the alg */

        if (OBJ_find_sigid_algs(OBJ_obj2nid(algorOID), &md_NID, NULL)
            && (md = EVP_get_digestbynid(md_NID))) {
            mac = OPENSSL_malloc(EVP_PKEY_size((EVP_PKEY *)pkey));
            if (mac == NULL)
                goto err;

            evp_ctx = EVP_MD_CTX_create();
            if (evp_ctx == NULL)
                goto err;
            if (!(EVP_SignInit_ex(evp_ctx, md, NULL)))
                goto err;
            if (!(EVP_SignUpdate(evp_ctx, prot_part_der, prot_part_der_len)))
                goto err;
            if (!(EVP_SignFinal(evp_ctx, mac, &mac_len, (EVP_PKEY *)pkey)))
                goto err;
        } else {
            CMPerr(CMP_F_CMP_CALC_PROTECTION, CMP_R_UNKNOWN_ALGORITHM_ID);
            goto err;
        }
    } else {
        CMPerr(CMP_F_CMP_CALC_PROTECTION, CMP_R_INVALID_ARGS);
        goto err;
    }

    if ((prot = ASN1_BIT_STRING_new()) == NULL)
        goto err;
    /* OpenSSL defaults all bit strings to be encoded as ASN.1 NamedBitList */
    prot->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    ASN1_BIT_STRING_set(prot, mac, mac_len);

 err:
    if (prot == NULL)
        CMPerr(CMP_F_CMP_CALC_PROTECTION, CMP_R_ERROR_CALCULATING_PROTECTION);

    /* cleanup */
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    EVP_MD_CTX_destroy(evp_ctx);
    OPENSSL_free(mac);
    OPENSSL_free(prot_part_der);
    return prot;
}

/*
 * internal function
 * Create an X509_ALGOR structure for PasswordBasedMAC protection based on
 * the pbm settings in the context
 * returns pointer to X509_ALGOR on success, NULL on error
 */
static X509_ALGOR *CMP_create_pbmac_algor(OSSL_CMP_CTX *ctx)
{
    X509_ALGOR *alg = NULL;
    OSSL_CRMF_PBMPARAMETER *pbm = NULL;
    unsigned char *pbm_der = NULL;
    int pbm_der_len;
    ASN1_STRING *pbm_str = NULL;

    if ((alg = X509_ALGOR_new()) == NULL)
        goto err;
    if ((pbm = OSSL_CRMF_pbmp_new(ctx->pbm_slen, ctx->pbm_owf,
                                  ctx->pbm_itercnt, ctx->pbm_mac)) == NULL)
        goto err;
    if ((pbm_str = ASN1_STRING_new()) == NULL)
        goto err;

    pbm_der_len = i2d_OSSL_CRMF_PBMPARAMETER(pbm, &pbm_der);

    ASN1_STRING_set(pbm_str, pbm_der, pbm_der_len);
    OPENSSL_free(pbm_der);

    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_id_PasswordBasedMAC),
                    V_ASN1_SEQUENCE, pbm_str);

    OSSL_CRMF_PBMPARAMETER_free(pbm);
    return alg;
 err:
    X509_ALGOR_free(alg);
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    return NULL;
}

/*
 * Determines which kind of protection should be created, based on the ctx.
 * Sets this into the protectionAlg field in the message header.
 * Calculates the protection and sets it in the protection field.
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_MSG_protect(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)
{
    if (ctx == NULL)
        goto err;
    if (msg == NULL)
        goto err;
    if (ctx->unprotectedSend)
        return 1;

    /* use PasswordBasedMac according to 5.1.3.1 if secretValue is given */
    if (ctx->secretValue != NULL) {
        if ((msg->header->protectionAlg = CMP_create_pbmac_algor(ctx)) == NULL)
            goto err;
        if (ctx->referenceValue != NULL &&
            !OSSL_CMP_HDR_set1_senderKID(msg->header, ctx->referenceValue))
            goto err;

        /*
         * add any additional certificates from ctx->extraCertsOut
         * while not needed to validate the signing cert, the option to do
         * this might be handy for certain use cases
         */
        OSSL_CMP_MSG_add_extraCerts(ctx, msg);

        if ((msg->protection =
             CMP_calc_protection(msg, ctx->secretValue, NULL)) == NULL)

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
                CMPerr(CMP_F_OSSL_CMP_MSG_PROTECT,
                       CMP_R_CERT_AND_KEY_DO_NOT_MATCH);
                goto err;
            }

            if (msg->header->protectionAlg == NULL)
                msg->header->protectionAlg = X509_ALGOR_new();

            if (!OBJ_find_sigid_by_algs(&algNID, ctx->digest,
                        EVP_PKEY_id(ctx->pkey))) {
                CMPerr(CMP_F_OSSL_CMP_MSG_PROTECT,
                       CMP_R_UNSUPPORTED_KEY_TYPE);
                goto err;
            }
            alg = OBJ_nid2obj(algNID);
            X509_ALGOR_set0(msg->header->protectionAlg, alg, V_ASN1_UNDEF,NULL);

            /*
             * set senderKID to  keyIdentifier of the used certificate according
             * to section 5.1.1
             */
            subjKeyIDStr = X509_get0_subject_key_id(ctx->clCert);
            if (subjKeyIDStr != NULL &&
                !OSSL_CMP_HDR_set1_senderKID(msg->header, subjKeyIDStr))
                goto err;

            /* Add ctx->clCert followed, if possible, by its chain built
             * from ctx->untrusted_certs, and then ctx->extraCertsOut */
            OSSL_CMP_MSG_add_extraCerts(ctx, msg);

            if ((msg->protection =
                 CMP_calc_protection(msg, NULL, ctx->pkey)) == NULL)
                goto err;
        } else {
            CMPerr(CMP_F_OSSL_CMP_MSG_PROTECT,
                   CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION);
            goto err;
        }
    }

    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_MSG_PROTECT, CMP_R_ERROR_PROTECTING_MESSAGE);
    return 0;
}

/*
 * Adds the certificates to the extraCerts field in the given message. For
 * this it tries to build the certificate chain of our client cert (ctx->clCert)
 * by using certificates in ctx->untrusted_certs. If no untrusted certs are set,
 * it will at least place the client certificate into extraCerts.
 * In any case all the certificates explicitly specified to be sent out
 * (i.e., ctx->extraCertsOut) are added.
 *
 * Note: it will NOT add the trust anchor (unless it is part of extraCertsOut).
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_MSG_add_extraCerts(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)
{
    int res = 0;

    if (ctx == NULL || msg == NULL)
        goto err;
    if (msg->extraCerts == NULL && !(msg->extraCerts = sk_X509_new_null()))
        goto err;

    res = 1;
    if (ctx->clCert != NULL) {
        /* Make sure that our own cert gets sent, in the first position */
        res = sk_X509_push(msg->extraCerts, ctx->clCert)
            && X509_up_ref(ctx->clCert);

        /*
         * if we have untrusted store, try to add intermediate certs
         */
        if (res != 0 && ctx->untrusted_certs != NULL) {
            STACK_OF(X509) *chain =
                OSSL_CMP_build_cert_chain(ctx->untrusted_certs, ctx->clCert);
            res = OSSL_CMP_sk_X509_add1_certs(msg->extraCerts, chain,
                                              1/* no self-signed */,
                                              1/* no dups */);
            sk_X509_pop_free(chain, X509_free);
        }
    }

    /* add any additional certificates from ctx->extraCertsOut */
    OSSL_CMP_sk_X509_add1_certs(msg->extraCerts, ctx->extraCertsOut, 0,
                                1/*no dups*/);

    /* if none was found avoid empty ASN.1 sequence */
    if (sk_X509_num(msg->extraCerts) == 0) {
        sk_X509_free(msg->extraCerts);
        msg->extraCerts = NULL;
    }
 err:
    return res;
}

/*
 * set certificate Hash in certStatus of certConf messages according to 5.3.18.
 *
 * returns 1 on success, 0 on error
 */
int CMP_CERTSTATUS_set_certHash(OSSL_CMP_CERTSTATUS *certStatus,
                                const X509 *cert)
{
    unsigned int len;
    unsigned char hash[EVP_MAX_MD_SIZE];
    int md_NID;
    const EVP_MD *md = NULL;

    if (certStatus == NULL || cert == NULL)
        goto err;

    /*
     * select hash algorithm, as stated in Appendix F.  Compilable ASN.1
     * Definitions:
     * -- the hash of the certificate, using the same hash algorithm
     * -- as is used to create and verify the certificate signature
     */
    if (OBJ_find_sigid_algs(X509_get_signature_nid(cert), &md_NID, NULL)
        && (md = EVP_get_digestbynid(md_NID))) {
        if (!X509_digest(cert, md, hash, &len))
            goto err;
        if (!OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(&certStatus->certHash,
                                                   hash, len))
            goto err;
    } else {
        CMPerr(CMP_F_CMP_CERTSTATUS_SET_CERTHASH,
               CMP_R_UNSUPPORTED_ALGORITHM);
        goto err;
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_CERTSTATUS_SET_CERTHASH, CMP_R_ERROR_SETTING_CERTHASH);
    return 0;
}

/*
 * sets implicitConfirm in the generalInfo field of the PKIMessage header
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_MSG_set_implicitConfirm(OSSL_CMP_MSG *msg)
{
    OSSL_CMP_ITAV *itav = NULL;

    if (msg == NULL)
        goto err;

    if ((itav = OSSL_CMP_ITAV_gen(OBJ_nid2obj(NID_id_it_implicitConfirm),
                                  (const ASN1_TYPE *)ASN1_NULL_new())) == NULL)
        goto err;
    if (!OSSL_CMP_HDR_generalInfo_item_push0(msg->header, itav))
        goto err;
    return 1;
 err:
    OSSL_CMP_ITAV_free(itav);
    return 0;
}

/*
 * checks if implicitConfirm in the generalInfo field of the header is set
 *
 * returns 1 if it is set, 0 if not
 */
int OSSL_CMP_MSG_check_implicitConfirm(OSSL_CMP_MSG *msg)
{
    int itavCount;
    int i;
    OSSL_CMP_ITAV *itav = NULL;

    if (msg == NULL)
        return 0;

    itavCount = sk_OSSL_CMP_ITAV_num(msg->header->generalInfo);

    for (i = 0; i < itavCount; i++) {
        itav = sk_OSSL_CMP_ITAV_value(msg->header->generalInfo, i);
        if (OBJ_obj2nid(itav->infoType) == NID_id_it_implicitConfirm)
            return 1;
    }

    return 0;
}

/*
 * push given itav to message header
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_generalInfo_item_push0(OSSL_CMP_HDR *hdr,
                                         const OSSL_CMP_ITAV *itav)
{
    if (hdr == NULL)
        goto err;

    if (!OSSL_CMP_ITAV_stack_item_push0(&hdr->generalInfo, itav))
        goto err;
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_HDR_GENERALINFO_ITEM_PUSH0,
           CMP_R_ERROR_PUSHING_GENERALINFO_ITEM);
    return 0;
}


int OSSL_CMP_MSG_generalInfo_items_push1(OSSL_CMP_MSG *msg,
                                         STACK_OF(OSSL_CMP_ITAV) *itavs)
{
    int i;
    OSSL_CMP_ITAV *itav = NULL;

    if (msg == NULL)
        goto err;

    for (i = 0; i < sk_OSSL_CMP_ITAV_num(itavs); i++) {
        itav = OSSL_CMP_ITAV_dup(sk_OSSL_CMP_ITAV_value(itavs,i));
        if (!OSSL_CMP_HDR_generalInfo_item_push0(msg->header, itav)) {
            OSSL_CMP_ITAV_free(itav);
            goto err;
        }
    }

    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_MSG_GENERALINFO_ITEMS_PUSH1,
           CMP_R_ERROR_PUSHING_GENERALINFO_ITEMS);
    return 0;
}

/*
 * push given InfoTypeAndValue item to the stack in a general message (GenMsg).
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_MSG_genm_item_push0(OSSL_CMP_MSG *msg,
                                 const OSSL_CMP_ITAV *itav)
{
    int bodytype;
    if (msg == NULL)
        goto err;
    bodytype = OSSL_CMP_MSG_get_bodytype(msg);
    if (bodytype != OSSL_CMP_PKIBODY_GENM && bodytype != OSSL_CMP_PKIBODY_GENP)
        goto err;

    if (!OSSL_CMP_ITAV_stack_item_push0(&msg->body->value.genm, itav))
        goto err;
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_MSG_GENM_ITEM_PUSH0,
           CMP_R_ERROR_PUSHING_GENERALINFO_ITEM);
    return 0;
}

/*
 * push a copy of the given itav stack the body of a general message (GenMsg).
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_MSG_genm_items_push1(OSSL_CMP_MSG *msg,
                                  STACK_OF(OSSL_CMP_ITAV) *itavs)
{
    int i;
    OSSL_CMP_ITAV *itav = NULL;

    if (msg == NULL)
        goto err;

    for (i = 0; i < sk_OSSL_CMP_ITAV_num(itavs); i++) {
        itav = OSSL_CMP_ITAV_dup(sk_OSSL_CMP_ITAV_value(itavs,i));
        if (!OSSL_CMP_MSG_genm_item_push0(msg, itav)) {
            OSSL_CMP_ITAV_free(itav);
            goto err;
        }
    }
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_MSG_GENM_ITEMS_PUSH1, CMP_R_ERROR_PUSHING_GENM_ITEMS);
    return 0;
}

/*
 * push given itav to given stack, creating a new stack if not yet done.
 *
 * @itav: a pointer to the infoTypeAndValue item to push on the stack.
 *                If NULL it will only made sure the stack exists, that might be
 *                needed for creating an empty general message
 *
 * returns 1 on success, 0 on error
 */
int CMP_ITAV_stack_item_push0(STACK_OF(OSSL_CMP_ITAV) **itav_sk_p,
                              const OSSL_CMP_ITAV *itav)
{
    int created = 0;

    if (itav_sk_p == NULL)
        goto err;

    if (*itav_sk_p == NULL) {
        /* not yet created */
        if ((*itav_sk_p = sk_OSSL_CMP_ITAV_new_null()) == NULL)
            goto err;
        created = 1;
    }
    if (itav != NULL) {
        if (!sk_OSSL_CMP_ITAV_push(*itav_sk_p, (OSSL_CMP_ITAV *)itav))
            goto err;
    }
    return 1;
 err:
    if (created) {
        sk_OSSL_CMP_ITAV_pop_free(*itav_sk_p, OSSL_CMP_ITAV_free);
        *itav_sk_p = NULL;
    }
    return 0;
}


/*
 * Creates a new OSSL_CMP_ITAV structure and fills it in
 * returns a pointer to the structure on success, NULL on error
 */
OSSL_CMP_ITAV *OSSL_CMP_ITAV_gen(const ASN1_OBJECT *type,
                                 const ASN1_TYPE *value)
{
    OSSL_CMP_ITAV *itav;
    if (type == NULL || (itav = OSSL_CMP_ITAV_new()) == NULL)
        return NULL;
    OSSL_CMP_ITAV_set(itav, type, value);
    return itav;
}

/*
 * Creates a new PKIStatusInfo structure and fills it in
 * returns a pointer to the structure on success, NULL on error
 * note: strongly overlaps with TS_RESP_CTX_set_status_info()
 *       and TS_RESP_CTX_add_failure_info() in ../ts/ts_rsp_sign.c
 */
OSSL_CMP_PKISI *OSSL_CMP_statusInfo_new(int status, unsigned long failInfo,
                                        const char *text)
{
    OSSL_CMP_PKISI *si = NULL;
    ASN1_UTF8STRING *utf8_text = NULL;
    int failure;

    if ((si = OSSL_CMP_PKISI_new()) == NULL)
        goto err;
    if (!ASN1_INTEGER_set(si->status, status))
        goto err;

    if (text != NULL) {
        if ((utf8_text = ASN1_UTF8STRING_new()) == NULL ||
            !ASN1_STRING_set(utf8_text, text, (int)strlen(text)))
            goto err;
        if (si->statusString == NULL &&
            (si->statusString = sk_ASN1_UTF8STRING_new_null()) == NULL)
            goto err;
        if (!sk_ASN1_UTF8STRING_push(si->statusString, utf8_text))
            goto err;
        /* Ownership is lost. */
        utf8_text = NULL;
    }

    for (failure = 0; failure <= OSSL_CMP_PKIFAILUREINFO_MAX; failure++) {
        if ((failInfo & (1 << failure)) != 0) {
            if (si->failInfo == NULL &&
                (si->failInfo = ASN1_BIT_STRING_new()) == NULL)
                goto err;
            if (!ASN1_BIT_STRING_set_bit(si->failInfo, failure, 1))
                goto err;
        }
    }
    return si;

 err:
    OSSL_CMP_PKISI_free(si);
    ASN1_UTF8STRING_free(utf8_text);
    return NULL;
}

/*
 * returns the PKIStatus of the given PKIStatusInfo
 * returns -1 on error
 */
long OSSL_CMP_PKISI_PKIStatus_get(OSSL_CMP_PKISI *si)
{
    if (si == NULL || si->status == NULL) {
        CMPerr(CMP_F_OSSL_CMP_PKISI_PKISTATUS_GET,
               CMP_R_ERROR_PARSING_PKISTATUS);
        return -1;
    }
    return ASN1_INTEGER_get(si->status);
}

/*
 * returns the FailureInfo bits of the given PKIStatusInfo
 * returns -1 on error
 */
long OSSL_CMP_PKISI_PKIFailureInfo_get(OSSL_CMP_PKISI *si)
{
    int i;
    long res = 0;
    if (si == NULL || si->failInfo == NULL) {
        CMPerr(CMP_F_OSSL_CMP_PKISI_PKIFAILUREINFO_GET,
               CMP_R_ERROR_PARSING_PKISTATUS);
        return -1;
    }
    for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++)
        if (ASN1_BIT_STRING_get_bit(si->failInfo, i))
            res |= 1 << i;
    return res;
}

/*
 * internal function
 *
 * convert PKIStatus to human-readable string
 *
 * returns pointer to character array containing a sting representing the
 * PKIStatus of the given PKIStatusInfo
 * returns NULL on error
 */
static char *CMP_PKISI_PKIStatus_get_string(OSSL_CMP_PKISI *si)
{
    long PKIStatus;

    if ((PKIStatus = OSSL_CMP_PKISI_PKIStatus_get(si)) < 0)
        return NULL;
    switch (PKIStatus) {
    case OSSL_CMP_PKISTATUS_accepted:
        return "PKIStatus: accepted";
    case OSSL_CMP_PKISTATUS_grantedWithMods:
        return "PKIStatus: granted with mods";
    case OSSL_CMP_PKISTATUS_rejection:
        return "PKIStatus: rejection";
    case OSSL_CMP_PKISTATUS_waiting:
        return "PKIStatus: waiting";
    case OSSL_CMP_PKISTATUS_revocationWarning:
        return "PKIStatus: revocation warning";
    case OSSL_CMP_PKISTATUS_revocationNotification:
        return "PKIStatus: revocation notification";
    case OSSL_CMP_PKISTATUS_keyUpdateWarning:
        return "PKIStatus: key update warning";
    default:
        CMPerr(CMP_F_CMP_PKISI_PKISTATUS_GET_STRING,
               CMP_R_ERROR_PARSING_PKISTATUS);
    }
    return NULL;
}

/*
 * internal function
 * convert PKIFailureInfo bit to human-readable string or empty string if not set
 *
 * returns pointer to static string
 * returns NULL on error
 */
static char *OSSL_CMP_PKIFAILUREINFO_get_string(OSSL_CMP_PKIFAILUREINFO *fi,
                                                int i)
{
    if (fi == NULL)
        return NULL;
    if (0 <= i && i <= OSSL_CMP_PKIFAILUREINFO_MAX) {
        if (ASN1_BIT_STRING_get_bit(fi, i)) {
            switch (i) {
            case OSSL_CMP_PKIFAILUREINFO_badAlg:
                return "PKIFailureInfo: badAlg";
            case OSSL_CMP_PKIFAILUREINFO_badMessageCheck:
                return "PKIFailureInfo: badMessageCheck";
            case OSSL_CMP_PKIFAILUREINFO_badRequest:
                return "PKIFailureInfo: badRequest";
            case OSSL_CMP_PKIFAILUREINFO_badTime:
                return "PKIFailureInfo: badTime";
            case OSSL_CMP_PKIFAILUREINFO_badCertId:
                return "PKIFailureInfo: badCertId";
            case OSSL_CMP_PKIFAILUREINFO_badDataFormat:
                return "PKIFailureInfo: badDataFormat";
            case OSSL_CMP_PKIFAILUREINFO_wrongAuthority:
                return "PKIFailureInfo: wrongAuthority";
            case OSSL_CMP_PKIFAILUREINFO_incorrectData:
                return "PKIFailureInfo: incorrectData";
            case OSSL_CMP_PKIFAILUREINFO_missingTimeStamp:
                return "PKIFailureInfo: missingTimeStamp";
            case OSSL_CMP_PKIFAILUREINFO_badPOP:
                return "PKIFailureInfo: badPOP";
            case OSSL_CMP_PKIFAILUREINFO_certRevoked:
                return "PKIFailureInfo: certRevoked";
            case OSSL_CMP_PKIFAILUREINFO_certConfirmed:
                return "PKIFailureInfo: certConfirmed";
            case OSSL_CMP_PKIFAILUREINFO_wrongIntegrity:
                return "PKIFailureInfo: wrongIntegrity";
            case OSSL_CMP_PKIFAILUREINFO_badRecipientNonce:
                return "PKIFailureInfo: badRecipientNonce";
            case OSSL_CMP_PKIFAILUREINFO_timeNotAvailable:
                return "PKIFailureInfo: timeNotAvailable";
            case OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy:
                return "PKIFailureInfo: unacceptedPolicy";
            case OSSL_CMP_PKIFAILUREINFO_unacceptedExtension:
                return "PKIFailureInfo: unacceptedExtension";
            case OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable:
                return "PKIFailureInfo: addInfoNotAvailable";
            case OSSL_CMP_PKIFAILUREINFO_badSenderNonce:
                return "PKIFailureInfo: badSenderNonce";
            case OSSL_CMP_PKIFAILUREINFO_badCertTemplate:
                return "PKIFailureInfo: badCertTemplate";
            case OSSL_CMP_PKIFAILUREINFO_signerNotTrusted:
                return "PKIFailureInfo: signerNotTrusted";
            case OSSL_CMP_PKIFAILUREINFO_transactionIdInUse:
                return "PKIFailureInfo: transactionIdInUse";
            case OSSL_CMP_PKIFAILUREINFO_unsupportedVersion:
                return "PKIFailureInfo: unsupportedVersion";
            case OSSL_CMP_PKIFAILUREINFO_notAuthorized:
                return "PKIFailureInfo: notAuthorized";
            case OSSL_CMP_PKIFAILUREINFO_systemUnavail:
                return "PKIFailureInfo: systemUnavail";
            case OSSL_CMP_PKIFAILUREINFO_systemFailure:
                return "PKIFailureInfo: systemFailure";
            case OSSL_CMP_PKIFAILUREINFO_duplicateCertReq:
                return "PKIFailureInfo: duplicateCertReq";
            }
        } else {
            return ""; /* bit is not set */
        }
    }
    return NULL; /* illegal bit position */
}

/*
 * returns the status field of the RevRepContent with the given
 * request/sequence id inside a revocation response.
 * RevRepContent has the revocation statuses in same order as they were sent in
 * RevReqContent.
 * returns NULL on error
 */
OSSL_CMP_PKISI *CMP_REVREPCONTENT_PKIStatusInfo_get(OSSL_CMP_REVREPCONTENT *rrep,
                                                    long rsid)
{
    OSSL_CMP_PKISI *status = NULL;
    if (rrep == NULL)
        return NULL;

    if ((status = sk_OSSL_CMP_PKISI_value(rrep->status, rsid)) != NULL) {
        return status;
    }

    CMPerr(CMP_F_CMP_REVREPCONTENT_PKISTATUSINFO_GET,
           CMP_R_PKISTATUSINFO_NOT_FOUND);
    return NULL;
}

/*
 * checks PKIFailureInfo bits in a given PKIStatusInfo
 * returns 1 if a given bit is set, 0 if not, -1 on error
 */
int OSSL_CMP_PKISI_PKIFailureInfo_check(OSSL_CMP_PKISI *si, int codeBit)
{
    ASN1_BIT_STRING *failInfo = OSSL_CMP_PKISI_failInfo_get0(si);
    if (failInfo == NULL) /* this can also indicate si == NULL */
        return -1;
    if ((codeBit < 0) || (codeBit > OSSL_CMP_PKIFAILUREINFO_MAX))
        return -1;

    return ASN1_BIT_STRING_get_bit(failInfo, codeBit);
}

/*
 * returns a pointer to the failInfo contained in a PKIStatusInfo
 * returns NULL on error
 */
OSSL_CMP_PKIFAILUREINFO *OSSL_CMP_PKISI_failInfo_get0(OSSL_CMP_PKISI *si)
{
    return si == NULL ? NULL : si->failInfo;
}

/*
 * returns a pointer to the statusString contained in a PKIStatusInfo
 * returns NULL on error
 */
OSSL_CMP_PKIFREETEXT *OSSL_CMP_PKISI_statusString_get0(OSSL_CMP_PKISI *si)
{
    return si == NULL ? NULL : si->statusString;
}

/*
 * returns a pointer to the PollResponse with the given CertReqId
 * (or the first one in case -1) inside a PollRepContent
 * returns NULL on error or if no suitable PollResponse available
 */
/* cannot factor overlap with CERTREPMESSAGE_certResponse_get0 due to typing */
OSSL_CMP_POLLREP *CMP_POLLREPCONTENT_pollRep_get0(OSSL_CMP_POLLREPCONTENT *prc,
                                                  long rid)
{
    OSSL_CMP_POLLREP *pollRep = NULL;
    int i;
    char str[DECIMAL_SIZE(rid)+1];
 
    if (prc == NULL) {
        CMPerr(CMP_F_CMP_POLLREPCONTENT_POLLREP_GET0, CMP_R_INVALID_ARGS);
        return NULL;
    }

    for (i = 0; i < sk_OSSL_CMP_POLLREP_num(prc); i++) {
        pollRep = sk_OSSL_CMP_POLLREP_value(prc, i);
        /* is it the right CertReqId? */
        if (rid == -1 || rid == ASN1_INTEGER_get(pollRep->certReqId))
            return pollRep;
    }

    CMPerr(CMP_F_CMP_POLLREPCONTENT_POLLREP_GET0, CMP_R_CERTRESPONSE_NOT_FOUND);
    BIO_snprintf(str, sizeof(str), "%ld", rid);
    ERR_add_error_data(2, "expected certReqId = ", str);
    return NULL;
}

/*
 * returns a pointer to the CertResponse with the given CertReqId
 * (or the first one in case -1) inside a CertRepMessage
 * returns NULL on error or if no suitable CertResponse available
 */
/* cannot factor overlap with POLLREPCONTENT_pollResponse_get0 due to typing */
OSSL_CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0(
                                     OSSL_CMP_CERTREPMESSAGE *crepmsg, long rid)
{
    OSSL_CMP_CERTRESPONSE *crep = NULL;
    int i;
    char str[DECIMAL_SIZE(rid)+1];

    if (crepmsg == NULL || crepmsg->response == NULL) {
        CMPerr(CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0, CMP_R_INVALID_ARGS);
        return NULL;
    }

    for (i = 0; i < sk_OSSL_CMP_CERTRESPONSE_num(crepmsg->response); i++) {
        crep = sk_OSSL_CMP_CERTRESPONSE_value(crepmsg->response, i);
        /* is it the right CertReqId? */
        if (rid == -1 || rid == ASN1_INTEGER_get(crep->certReqId))
            return crep;
    }

    CMPerr(CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0,
           CMP_R_CERTRESPONSE_NOT_FOUND);
    BIO_snprintf(str, sizeof(str), "%ld", rid);
    ERR_add_error_data(2, "expected certReqId = ", str);
    return NULL;
}

/*
 * returns 1 on success
 * returns 0 on error
 */
int OSSL_CMP_MSG_set_bodytype(OSSL_CMP_MSG *msg, int type)
{
    if (msg == NULL || msg->body == NULL)
        return 0;

    msg->body->type = type;

    return 1;
}

/*
 * returns the body type of the given CMP message
 * returns -1 on error
 */
int OSSL_CMP_MSG_get_bodytype(const OSSL_CMP_MSG *msg)
{
    if (msg == NULL || msg->body == NULL)
        return -1;

    return msg->body->type;
}

/*
 * place human-readable error string created from PKIStatusInfo in given buffer
 * returns pointer to the same buffer containing the string, or NULL on error
 */
char *OSSL_CMP_PKISI_snprint(OSSL_CMP_PKISI *si, char *buf, int bufsize)
{
    const char *status, *failure;
    int i;
    int n = 0;

    if (si == NULL ||
        (status = CMP_PKISI_PKIStatus_get_string(si)) == NULL)
        return NULL;
    BIO_snprintf(buf, bufsize, "%s; ", status);

    /* PKIFailure is optional and may be empty */
    if (si->failInfo != NULL) {
        for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++) {
            failure = OSSL_CMP_PKIFAILUREINFO_get_string(si->failInfo, i);
            if (failure == NULL)
                return NULL;
            if (failure[0] != '\0')
                BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "%s%s",
                             n > 0 ? ", " : "", failure);
            n += (int)strlen(failure);
        }
    }
    if (n == 0)
        BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "<no failure info>");

    /* StatusString sequence is optional and may be empty */
    n = sk_ASN1_UTF8STRING_num(si->statusString);
    if (n > 0) {
        BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf),
                     "; StatusString%s: ", n > 1 ? "s" : "");
        for (i = 0; i < n; i++) {
            ASN1_UTF8STRING *text = sk_ASN1_UTF8STRING_value(si->statusString, i);
            BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "\"%s\"%s",
                         ASN1_STRING_get0_data(text), i < n-1 ? ", " : "");
        }
    }
    return buf;
}

/*
 * Retrieve a copy of the certificate, if any, from the given CertResponse.
 * returns NULL if not found or on error
 */
X509 *CMP_CERTRESPONSE_get_certificate(OSSL_CMP_CTX *ctx,
                                       OSSL_CMP_CERTRESPONSE *crep)
{
    OSSL_CMP_CERTORENCCERT *coec;
    X509 *crt = NULL;

    if (ctx == NULL || crep == NULL) {
        CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE,
               CMP_R_INVALID_ARGS);
        goto err;
    }
    if (crep->certifiedKeyPair &&
        (coec = crep->certifiedKeyPair->certOrEncCert)) {
        switch (coec->type) {
        case OSSL_CMP_CERTORENCCERT_CERTIFICATE:
            crt = X509_dup(coec->value.certificate);
            break;
        case OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT:
        /* cert encrypted for indirect PoP; RFC 4210, 5.2.8.2 */
            crt = OSSL_CRMF_ENCRYPTEDVALUE_encCert_get1(coec->value.encryptedCert,
                                                   ctx->newPkey);
            break;
        default:
            CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE,
                   CMP_R_UNKNOWN_CERT_TYPE);
            goto err;
        }
        if (crt == NULL) {
            CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE,
                   CMP_R_CERTIFICATE_NOT_FOUND);
            goto err;
        }
    }
    return crt;

 err:
    return NULL;
}

/*
 * Builds up the certificate chain of certs as high up as possible using
 * the given list of certs containing all possible intermediate certificates and
 * optionally the (possible) trust anchor(s). See also ssl_add_cert_chain().
 *
 * Intended use of this function is to find all the certificates above the trust
 * anchor needed to verify an EE's own certificate.  Those are supposed to be
 * included in the ExtraCerts field of every first sent message of a transaction
 * when MSG_SIG_ALG is utilized.
 *
 * NOTE: This allocates a stack and increments the reference count of each cert,
 * so when not needed any more the stack and all its elements should be freed.
 * NOTE: in case there is more than one possibility for the chain,
 * OpenSSL seems to take the first one, check X509_verify_cert() for details.
 *
 * returns a pointer to a stack of (up_ref'ed) X509 certificates containing:
 *      - the EE certificate given in the function arguments (cert)
 *      - all intermediate certificates up the chain toward the trust anchor
 *      - the (self-signed) trust anchor is not included
 *      returns NULL on error
 */
STACK_OF(X509) *OSSL_CMP_build_cert_chain(const STACK_OF(X509) *certs,
                                          const X509 *cert)
{
    STACK_OF(X509) *chain = NULL, *result = NULL;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *csc = NULL;

    if (certs == NULL || cert == NULL || store == NULL)
        goto err;

    csc = X509_STORE_CTX_new();
    if (csc == NULL)
        goto err;

    OSSL_CMP_X509_STORE_add1_certs(store, (STACK_OF(X509) *)certs, 0);
    if (!X509_STORE_CTX_init(csc, store, (X509 *)cert, NULL))
        goto err;

    (void)ERR_set_mark();
    /*
     * ignore return value as it would fail without trust anchor given in store
     */
    (void)X509_verify_cert(csc);

    /* don't leave any new errors in the queue */
    (void)ERR_pop_to_mark();

    chain = X509_STORE_CTX_get0_chain(csc);

    /* result list to store the up_ref'ed not self-signed certificates */
    if ((result = sk_X509_new_null()) == NULL)
        goto err;
    OSSL_CMP_sk_X509_add1_certs(result, chain, 1/* no self-signed */,
                                1/* no dups */);

 err:
    X509_STORE_free(store);
    X509_STORE_CTX_free(csc);
    return result;
}

/*
 * Add certificate to given stack, optionally only if not already contained
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_sk_X509_add1_cert(STACK_OF(X509) *sk, X509 *cert,
                               int not_duplicate)
{
    if (not_duplicate) {
        /* not using sk_X509_set_cmp_func() and sk_X509_find()
           because this re-orders the certs on the stack */
        int i;
        for (i = 0; i < sk_X509_num(sk); i++)
            if (X509_cmp(sk_X509_value(sk, i), cert) == 0)
                return 1;
    }
    if (!sk_X509_push(sk, cert))
        return 0;
    return X509_up_ref(cert);
}

/*
 * Add certificates from 'certs' to given stack,
 * optionally only if not self-signed and
 * optionally only if not already contained* certs parameter may be NULL.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, const STACK_OF(X509) *certs,
                                int no_self_signed, int no_duplicates)
{
    int i;

    if (sk == NULL)
        return 0;

    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        if (!no_self_signed || X509_check_issued(cert, cert) != X509_V_OK) {
            if (!OSSL_CMP_sk_X509_add1_cert(sk, cert, no_duplicates))
                return 0;
        }
    }
    return 1;
}

/*
 * Add all or self-signed certificates from the given stack to given store.
 * certs parameter may be NULL.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                                   int only_self_signed)
{
    int i;

    if (store == NULL)
        return 0;

    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        if (!only_self_signed || X509_check_issued(cert, cert) == X509_V_OK)
            if (!X509_STORE_add_cert(store, cert)) /* ups cert ref counter */
                return 0;
    }
    return 1;
}

/*
 * Retrieves a copy of all certificates in the given store.
 * returns NULL on error
 */
STACK_OF(X509) *OSSL_CMP_X509_STORE_get1_certs(const X509_STORE *store)
{
    int i;
    STACK_OF(X509) *sk;
    STACK_OF(X509_OBJECT) *objs;

    if (store == NULL)
        return NULL;
    if ((sk = sk_X509_new_null()) == NULL)
        return NULL;
    objs = X509_STORE_get0_objects((X509_STORE *)store);
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
        if (cert != NULL) {
            if (!sk_X509_push(sk, cert)) {
                sk_X509_pop_free(sk, X509_free);
                return NULL;
            }
            X509_up_ref(cert);
        }
    }
    return sk;
}

/*
 * Checks received message (i.e., response by server or request from client)
 *
 * Ensures that:
 * it has a valid body type,
 * its protection is valid or absent (allowed only if callback function is
 * present and function yields positive result using also supplied argument),
 * its transaction ID matches stored in ctx (if any),
 * and its recipNonce matches the senderNonce in ctx.
 *
 * If everything is fine:
 * learns the senderNonce from the received message,
 * learns the transaction ID if it is not yet in ctx.
 *
 * returns body type (which is >= 0) of the message on success, -1 on error
 */
int OSSL_CMP_MSG_check_received(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg,
                                int callback_arg,
                                int (*allow_unprotected)(const OSSL_CMP_CTX *,
                                                         int,
                                                         const OSSL_CMP_MSG *))
{
    int rcvd_type;

    if (ctx == NULL || msg == NULL)
        return -1;

    if ((rcvd_type = OSSL_CMP_MSG_get_bodytype(msg)) < 0) {
        CMPerr(CMP_F_OSSL_CMP_MSG_CHECK_RECEIVED, CMP_R_PKIBODY_ERROR);
        return -1;
    }

    /* validate message protection */
    if (msg->header->protectionAlg != 0) {
        if (!OSSL_CMP_validate_msg(ctx, msg)) {
            /* validation failed */
             CMPerr(CMP_F_OSSL_CMP_MSG_CHECK_RECEIVED,
                    CMP_R_ERROR_VALIDATING_PROTECTION);
             return -1;
         }
    } else {
        /* detect explicitly permitted exceptions */
        if (allow_unprotected == NULL ||
            !(*allow_unprotected)(ctx, callback_arg, msg)) {
            CMPerr(CMP_F_OSSL_CMP_MSG_CHECK_RECEIVED,
                   CMP_R_MISSING_PROTECTION);
            return -1;
        }
        OSSL_CMP_warn(ctx, "received message is not protected");
    }

    /* compare received transactionID with the expected one in previous msg */
    if (ctx->transactionID != NULL &&
        (msg->header->transactionID == NULL ||
            ASN1_OCTET_STRING_cmp(ctx->transactionID,
                                  msg->header->transactionID) != 0)) {
        CMPerr(CMP_F_OSSL_CMP_MSG_CHECK_RECEIVED,
               CMP_R_TRANSACTIONID_UNMATCHED);
        return -1;
    }

    /* compare received nonce with the one we sent */
    if (ctx->last_senderNonce != NULL &&
        (msg->header->recipNonce == NULL ||
         ASN1_OCTET_STRING_cmp(ctx->last_senderNonce,
                               msg->header->recipNonce) != 0)) {
        CMPerr(CMP_F_OSSL_CMP_MSG_CHECK_RECEIVED,
               CMP_R_RECIPNONCE_UNMATCHED);
        return -1;
    }
    /*
     * RFC 4210 section 5.1.1 states: the recipNonce is copied from
     * the senderNonce of the previous message in the transaction.
     * --> Store for setting in next message */
    if (!OSSL_CMP_CTX_set1_recipNonce(ctx, msg->header->senderNonce))
        return -1;

    /* if not yet present, learn transactionID */
    if (ctx->transactionID == NULL &&
        !OSSL_CMP_CTX_set1_transactionID(ctx, msg->header->transactionID))
        return -1;

    return rcvd_type;
}
