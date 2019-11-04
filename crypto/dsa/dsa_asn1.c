/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "dsa_local.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/rand.h>
#include "crypto/asn1_dsa.h"

DSA_SIG *DSA_SIG_new(void)
{
    DSA_SIG *sig = OPENSSL_zalloc(sizeof(*sig));
    if (sig == NULL)
        DSAerr(DSA_F_DSA_SIG_NEW, ERR_R_MALLOC_FAILURE);
    return sig;
}

void DSA_SIG_free(DSA_SIG *sig)
{
    if (sig == NULL)
        return;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    OPENSSL_free(sig);
}

DSA_SIG *d2i_DSA_SIG(DSA_SIG **psig, const unsigned char **ppin, long len)
{
    DSA_SIG *sig;

    if (len < 0)
        return NULL;
    if (psig != NULL && *psig != NULL) {
        sig = *psig;
    } else {
        sig = DSA_SIG_new();
        if (sig == NULL)
            return NULL;
    }
    if (sig->r == NULL)
        sig->r = BN_new();
    if (sig->s == NULL)
        sig->s = BN_new();
    if (decode_der_dsa_sig(sig->r, sig->s, ppin, (size_t)len) == 0) {
        if (psig == NULL || *psig == NULL)
            DSA_SIG_free(sig);
        return NULL;
    }
    if (psig != NULL && *psig == NULL)
        *psig = sig;
    return sig;
}

int i2d_DSA_SIG(const DSA_SIG *sig, unsigned char **ppout)
{
    BUF_MEM *buf = NULL;
    size_t encoded_len;
    WPACKET pkt;

    if (ppout == NULL) {
        if (!WPACKET_init_null(&pkt, 0))
            return -1;
    } else if (*ppout == NULL) {
        if ((buf = BUF_MEM_new()) == NULL
                || !WPACKET_init_len(&pkt, buf, 0)) {
            BUF_MEM_free(buf);
            return -1;
        }
    } else {
        if (!WPACKET_init_static_len(&pkt, *ppout, SIZE_MAX, 0))
            return -1;
    }

    if (!encode_der_dsa_sig(&pkt, sig->r, sig->s)
            || !WPACKET_get_total_written(&pkt, &encoded_len)
            || !WPACKET_finish(&pkt)) {
        BUF_MEM_free(buf);
        WPACKET_cleanup(&pkt);
        return -1;
    }

    if (ppout != NULL) {
        if (*ppout == NULL) {
            *ppout = (unsigned char *)buf->data;
            buf->data = NULL;
            BUF_MEM_free(buf);
        } else {
            *ppout += encoded_len;
        }
    }

    return (int)encoded_len;
}

void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}

int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

/* Override the default free and new methods */
static int dsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)DSA_new();
        if (*pval != NULL)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        DSA_free((DSA *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(DSAPrivateKey, dsa_cb) = {
        ASN1_EMBED(DSA, version, INT32),
        ASN1_SIMPLE(DSA, p, BIGNUM),
        ASN1_SIMPLE(DSA, q, BIGNUM),
        ASN1_SIMPLE(DSA, g, BIGNUM),
        ASN1_SIMPLE(DSA, pub_key, BIGNUM),
        ASN1_SIMPLE(DSA, priv_key, CBIGNUM)
} static_ASN1_SEQUENCE_END_cb(DSA, DSAPrivateKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(DSA, DSAPrivateKey, DSAPrivateKey)

ASN1_SEQUENCE_cb(DSAparams, dsa_cb) = {
        ASN1_SIMPLE(DSA, p, BIGNUM),
        ASN1_SIMPLE(DSA, q, BIGNUM),
        ASN1_SIMPLE(DSA, g, BIGNUM),
} static_ASN1_SEQUENCE_END_cb(DSA, DSAparams)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(DSA, DSAparams, DSAparams)

ASN1_SEQUENCE_cb(DSAPublicKey, dsa_cb) = {
        ASN1_SIMPLE(DSA, pub_key, BIGNUM),
        ASN1_SIMPLE(DSA, p, BIGNUM),
        ASN1_SIMPLE(DSA, q, BIGNUM),
        ASN1_SIMPLE(DSA, g, BIGNUM)
} static_ASN1_SEQUENCE_END_cb(DSA, DSAPublicKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(DSA, DSAPublicKey, DSAPublicKey)

DSA *DSAparams_dup(const DSA *dsa)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(DSAparams), dsa);
}

int DSA_sign(int type, const unsigned char *dgst, int dlen,
             unsigned char *sig, unsigned int *siglen, DSA *dsa)
{
    DSA_SIG *s;

    s = DSA_do_sign(dgst, dlen, dsa);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_DSA_SIG(s, &sig);
    DSA_SIG_free(s);
    return 1;
}

/* data has already been hashed (probably with SHA or SHA-1). */
/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int DSA_verify(int type, const unsigned char *dgst, int dgst_len,
               const unsigned char *sigbuf, int siglen, DSA *dsa)
{
    DSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = DSA_SIG_new();
    if (s == NULL)
        return ret;
    if (d2i_DSA_SIG(&s, &p, siglen) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_DSA_SIG(s, &der);
    if (derlen != siglen || memcmp(sigbuf, der, derlen))
        goto err;
    ret = DSA_do_verify(dgst, dgst_len, s, dsa);
 err:
    OPENSSL_clear_free(der, derlen);
    DSA_SIG_free(s);
    return ret;
}
