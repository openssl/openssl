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
#include <openssl/crmf.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "crmf_int.h"

/*
 * creates and initializes OSSL_CRMF_PBMPARAMETER (section 4.4)
 * slen SHOULD be > 8    (16 is common)
 * owfnid e.g. NID_sha256
 * itercnt MUST be > 100 (500 is common)
 * macnid e.g. NID_hmac_sha1
 * returns pointer to OSSL_CRMF_PBMPARAMETER on success, NULL on error
 */
OSSL_CRMF_PBMPARAMETER *OSSL_CRMF_pbmp_new(size_t slen, int owfnid,
                                           long itercnt, int macnid)
{
    OSSL_CRMF_PBMPARAMETER *pbm = NULL;
    unsigned char *salt = NULL;
    int error = CRMF_R_CRMFERROR;

    if ((pbm = OSSL_CRMF_PBMPARAMETER_new()) == NULL) {
        error = CRMF_R_MALLOC_FAILURE;
        goto err;
    }

    /*
     * salt contains a randomly generated value used in computing the key
     * of the MAC process.  The salt SHOULD be at least 8 octets (64
     * bits) long.
     */
    if ((salt = OPENSSL_malloc(slen)) == NULL) {
        error = CRMF_R_MALLOC_FAILURE;
        goto err;
    }
    if (RAND_bytes(salt, (int)slen) <= 0) {
        error = CRMF_R_FAILURE_OBTAINING_RANDOM;
        goto err;
    }
    if (!(ASN1_OCTET_STRING_set(pbm->salt, salt, (int)slen)))
        goto err;

    /*
     * owf identifies the hash algorithm and associated parameters used to
     * compute the key used in the MAC process.  All implementations MUST
     * support SHA-1.
     */
    if (!X509_ALGOR_set0(pbm->owf, OBJ_nid2obj(owfnid), V_ASN1_UNDEF, NULL)) {
        error = CRMF_R_SETTING_OWF_ALGOR_FAILURE;
        goto err;
    }

    /*
     * iterationCount identifies the number of times the hash is applied
     * during the key computation process.  The iterationCount MUST be a
     * minimum of 100.      Many people suggest using values as high as 1000
     * iterations as the minimum value.  The trade off here is between
     * protection of the password from attacks and the time spent by the
     * server processing all of the different iterations in deriving
     * passwords.  Hashing is generally considered a cheap operation but
     * this may not be true with all hash functions in the future.
     */
    if (itercnt < 100) {
        error = CRMF_R_ITERATIONCOUNT_BELOW_100;
        goto err;
    }

    if (!ASN1_INTEGER_set(pbm->iterationCount, itercnt))
        goto err;

    /*
     * mac identifies the algorithm and associated parameters of the MAC
     * function to be used.  All implementations MUST support HMAC-SHA1
     * [HMAC]. All implementations SHOULD support DES-MAC and Triple-
     * DES-MAC [PKCS11].
     */
    if (!X509_ALGOR_set0(pbm->mac, OBJ_nid2obj(macnid), V_ASN1_UNDEF, NULL)) {
        error = CRMF_R_SETTING_MAC_ALGOR_FAILURE;
        goto err;
    }

    OPENSSL_free(salt);
    return pbm;
 err:
    OPENSSL_free(salt);
    OSSL_CRMF_PBMPARAMETER_free(pbm);
    CRMFerr(CRMF_F_OSSL_CRMF_PBMP_NEW, error);
    return NULL;
}

/*
 * calculates the PBM based on the settings of the given OSSL_CRMF_PBMPARAMETER
 * @pbm identifies the algorithms to use
 * @msg message to apply the PBM for
 * @msgLen length of the message
 * @secret key to use
 * @secretLen length of the key
 * @mac pointer to the computed mac, is allocated here, will be freed if not
 *              pointing to NULL
 * @macLen pointer to the length of the mac, will be set
 *
 * returns 1 at success, 0 at error
 */
int OSSL_CRMF_passwordBasedMac_new(const OSSL_CRMF_PBMPARAMETER *pbm,
                                   const unsigned char *msg, size_t msgLen,
                                   const unsigned char *secret,
                                   size_t secretLen,
                                   unsigned char **mac, unsigned int *macLen)
{
    int mac_nid, hmac_md_nid = NID_undef;
    const EVP_MD *m = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char basekey[EVP_MAX_MD_SIZE];
    unsigned int basekeyLen;
    uint64_t iterations;
    int error = CRMF_R_CRMFERROR;

    if (mac == NULL || pbm == NULL || pbm->mac == NULL ||
            pbm->mac->algorithm == NULL || msg == NULL || secret == NULL) {
        error = CRMF_R_NULL_ARGUMENT;
        goto err;
    }
    OPENSSL_free(*mac);
    if ((*mac = OPENSSL_malloc(EVP_MAX_MD_SIZE)) == NULL) {
        error = CRMF_R_MALLOC_FAILURE;
        goto err;
    }

    /*
     * owf identifies the hash algorithm and associated parameters used to
     * compute the key used in the MAC process.  All implementations MUST
     * support SHA-1.
     */
    if ((m = EVP_get_digestbyobj(pbm->owf->algorithm)) == NULL) {
        error = CRMF_R_UNSUPPORTED_ALGORITHM;
        goto err;
    }

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        error = CRMF_R_MALLOC_FAILURE;
        goto err;
    }

    /* compute the basekey of the salted secret */
    if (!(EVP_DigestInit_ex(ctx, m, NULL)))
        goto err;
    /* first the secret */
    if (!EVP_DigestUpdate(ctx, secret, secretLen))
        goto err;
    /* then the salt */
    if (!EVP_DigestUpdate(ctx, pbm->salt->data, pbm->salt->length))
        goto err;
    if (!(EVP_DigestFinal_ex(ctx, basekey, &basekeyLen)))
        goto err;
    if (
        !ASN1_INTEGER_get_uint64(&iterations, pbm->iterationCount)
            || iterations < 100 /* min from RFC */
            || iterations > OSSL_CRMF_PBM_MAX_ITERATION_COUNT) {
        error = CRMF_R_BAD_PBM_ITERATIONCOUNT;
        goto err;
    }

    /* the first iteration was already done above */
    while (--iterations > 0) {
        if (!(EVP_DigestInit_ex(ctx, m, NULL)))
            goto err;
        if (!EVP_DigestUpdate(ctx, basekey, basekeyLen))
            goto err;
        if (!(EVP_DigestFinal_ex(ctx, basekey, &basekeyLen)))
            goto err;
    }

    /*
     * mac identifies the algorithm and associated parameters of the MAC
     * function to be used.  All implementations MUST support HMAC-SHA1
     * [HMAC].      All implementations SHOULD support DES-MAC and Triple-
     * DES-MAC [PKCS11].
     */
    mac_nid = OBJ_obj2nid(pbm->mac->algorithm);

    if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, mac_nid, NULL, &hmac_md_nid, NULL) ||
            ((m = EVP_get_digestbynid(hmac_md_nid)) == NULL)) {
        error = CRMF_R_UNSUPPORTED_ALGORITHM;
        goto err;
    }
    HMAC(m, basekey, basekeyLen, msg, msgLen, *mac, macLen);

    /* cleanup */
    OPENSSL_cleanse(basekey, basekeyLen);
    EVP_MD_CTX_destroy(ctx);

    return 1;
 err:
    if (mac != NULL && *mac != NULL) {
        OPENSSL_free(*mac);
        *mac = NULL;
    }
    CRMFerr(CRMF_F_OSSL_CRMF_PASSWORDBASEDMAC_NEW, error);
    if (pbm != NULL && pbm->mac != NULL) {
        char buf[128];
        if (OBJ_obj2txt(buf, sizeof(buf), pbm->mac->algorithm, 0))
            ERR_add_error_data(1, buf);
    }
    return 0;
}
