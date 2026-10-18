/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "internal/cryptlib.h"
#include "internal/bytestring.h"
#include <openssl/evp.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "crypto/x509.h"

ASN1_SEQUENCE_enc(X509_CINF, enc, 0) = {
    ASN1_EXP_OPT(X509_CINF, version, ASN1_INTEGER, 0),
    ASN1_EMBED(X509_CINF, serialNumber, ASN1_INTEGER),
    ASN1_EMBED(X509_CINF, signature, X509_ALGOR),
    ASN1_SIMPLE(X509_CINF, issuer, X509_NAME),
    ASN1_EMBED(X509_CINF, validity, X509_VAL),
    ASN1_SIMPLE(X509_CINF, subject, X509_NAME),
    ASN1_SIMPLE(X509_CINF, key, X509_PUBKEY),
    ASN1_IMP_OPT(X509_CINF, issuerUID, ASN1_BIT_STRING, 1),
    ASN1_IMP_OPT(X509_CINF, subjectUID, ASN1_BIT_STRING, 2),
    ASN1_EXP_SEQUENCE_OF_OPT(X509_CINF, extensions, X509_EXTENSION, 3)
} ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF)

IMPLEMENT_ASN1_FUNCTIONS(X509_CINF)
/* X509 top level structure needs a bit of customisation */

extern void ossl_policy_cache_free(X509_POLICY_CACHE *cache);

static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
    void *exarg)
{
    X509 *ret = (X509 *)*pval;

    switch (operation) {

    case ASN1_OP_D2I_PRE:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        X509_CERT_AUX_free(ret->aux);
        ASN1_OCTET_STRING_free(ret->skid);
        AUTHORITY_KEYID_free(ret->akid);
        CRL_DIST_POINTS_free(ret->crldp);
        ossl_policy_cache_free(ret->policy_cache);
        GENERAL_NAMES_free(ret->altname);
        NAME_CONSTRAINTS_free(ret->nc);
#ifndef OPENSSL_NO_RFC3779
        sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
        ASIdentifiers_free(ret->rfc3779_asid);
#endif
        ASN1_OCTET_STRING_free(ret->distinguishing_id);

        /* fall through */

    case ASN1_OP_NEW_POST:
        ossl_x509_set0_der(ret, NULL);
        ret->ex_cached = 0;
        ret->ex_kusage = 0;
        ret->ex_xkusage = 0;
        ret->ex_nscert = 0;
        ret->ex_flags = 0;
        ret->ex_pathlen = -1;
        ret->ex_pcpathlen = -1;
        ret->skid = NULL;
        ret->akid = NULL;
        ret->policy_cache = NULL;
        ret->altname = NULL;
        ret->nc = NULL;
#ifndef OPENSSL_NO_RFC3779
        ret->rfc3779_addr = NULL;
        ret->rfc3779_asid = NULL;
#endif
        ret->distinguishing_id = NULL;
        ret->aux = NULL;
        ret->crldp = NULL;
        if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data))
            return 0;
        break;

    case ASN1_OP_FREE_POST:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        X509_CERT_AUX_free(ret->aux);
        ASN1_OCTET_STRING_free(ret->skid);
        AUTHORITY_KEYID_free(ret->akid);
        CRL_DIST_POINTS_free(ret->crldp);
        ossl_policy_cache_free(ret->policy_cache);
        GENERAL_NAMES_free(ret->altname);
        NAME_CONSTRAINTS_free(ret->nc);
#ifndef OPENSSL_NO_RFC3779
        sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
        ASIdentifiers_free(ret->rfc3779_asid);
#endif
        ASN1_OCTET_STRING_free(ret->distinguishing_id);
        ossl_x509_set0_der(ret, NULL);
        OPENSSL_free(ret->propq);
        break;

    case ASN1_OP_DUP_POST: {
        X509 *old = exarg;

        if (!ossl_x509_set0_libctx(ret, old->libctx, old->propq))
            return 0;
        if (old->der != NULL) {
            if (!CRYPTO_BUFFER_up_ref(old->der))
                return 0;
            ret->der = old->der;
            ret->view = old->view;
            ret->has_view = old->has_view;
            if (old->pkey != NULL && !EVP_PKEY_up_ref(old->pkey))
                return 0;
            ret->pkey = old->pkey;
        }
    } break;
    case ASN1_OP_GET0_LIBCTX: {
        OSSL_LIB_CTX **libctx = exarg;

        *libctx = ret->libctx;
    } break;

    case ASN1_OP_GET0_PROPQ: {
        const char **propq = exarg;

        *propq = ret->propq;
    } break;

    default:
        break;
    }

    return 1;
}

ASN1_SEQUENCE_ref(X509, x509_cb) = {
    ASN1_EMBED(X509, cert_info, X509_CINF),
    ASN1_EMBED(X509, sig_alg, X509_ALGOR),
    ASN1_EMBED(X509, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509, X509)

X509 *X509_new(void)
{
    return (X509 *)ASN1_item_new(ASN1_ITEM_rptr(X509));
}

void X509_free(X509 *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509));
}

X509 *d2i_X509(X509 **a, const unsigned char **in, long len)
{
    CRYPTO_BUFFER *der = NULL;
    CBS cbs, cert;
    const unsigned char *p;
    X509 *x = NULL;

    if (in == NULL || *in == NULL || len < 0) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        goto out;
    }
    CBS_init(&cbs, *in, (size_t)len);
    if (!CBS_get_asn1_element(&cbs, &cert, CBS_ASN1_SEQUENCE)) {
        x = (X509 *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
            ASN1_ITEM_rptr(X509));
        goto out;
    }
    if ((der = CRYPTO_BUFFER_new(CBS_data(&cert), CBS_len(&cert), NULL))
        == NULL)
        goto out;

    p = CRYPTO_BUFFER_data(der);
    x = (X509 *)ASN1_item_d2i((ASN1_VALUE **)a, &p,
        (long)CRYPTO_BUFFER_len(der), ASN1_ITEM_rptr(X509));
    if (x == NULL)
        goto out;
    ossl_x509_set0_der(x, der);
    der = NULL;
    *in += CBS_len(&cert);

out:
    CRYPTO_BUFFER_free(der);
    return x;
}

int i2d_X509(const X509 *a, unsigned char **out)
{
    const uint8_t *data;
    size_t len;

    if (a == NULL || a->der == NULL || a->cert_info.enc.modified)
        return ASN1_item_i2d((const ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509));

    data = CRYPTO_BUFFER_data(a->der);
    len = CRYPTO_BUFFER_len(a->der);
    if (len > INT_MAX) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
        return -1;
    }
    if (out == NULL)
        return (int)len;
    if (*out == NULL) {
        if ((*out = OPENSSL_memdup(data, len)) == NULL)
            return -1;
    } else {
        memcpy(*out, data, len);
        *out += len;
    }
    return (int)len;
}

IMPLEMENT_ASN1_DUP_FUNCTION(X509)

void ossl_x509_set_modified(X509 *x)
{
    x->cert_info.enc.modified = 1;
    ossl_x509_set0_der(x, NULL);
}

void ossl_x509_set0_der(X509 *x, CRYPTO_BUFFER *der)
{
    CBS spki;

    CRYPTO_BUFFER_free(x->der);
    EVP_PKEY_free(x->pkey);
    x->der = der;
    x->pkey = NULL;
    x->has_view = der != NULL
        && x509_view_parse(CRYPTO_BUFFER_data(der), CRYPTO_BUFFER_len(der),
            &x->view);
    if (!x->has_view)
        return;
    x509_view_get_spki(&x->view, &spki);
    ERR_set_mark();
    x->pkey = ossl_x509_spki_to_pkey(&spki);
    ERR_pop_to_mark();
}

/*
 * This should only be used if the X509 object was embedded inside another
 * asn1 object and it needs a libctx to operate.
 * Use X509_new_ex() instead if possible.
 */
int ossl_x509_set0_libctx(X509 *x, OSSL_LIB_CTX *libctx, const char *propq)
{
    if (x != NULL) {
        x->libctx = libctx;
        OPENSSL_free(x->propq);
        x->propq = NULL;
        if (propq != NULL) {
            x->propq = OPENSSL_strdup(propq);
            if (x->propq == NULL)
                return 0;
        }
    }
    return 1;
}

X509 *X509_new_ex(OSSL_LIB_CTX *libctx, const char *propq)
{
    X509 *cert = NULL;

    cert = (X509 *)ASN1_item_new_ex(ASN1_ITEM_rptr(X509), libctx, propq);
    if (!ossl_x509_set0_libctx(cert, libctx, propq)) {
        X509_free(cert);
        cert = NULL;
    }
    return cert;
}

int X509_set_ex_data(X509 *r, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&r->ex_data, idx, arg);
}

void *X509_get_ex_data(const X509 *r, int idx)
{
    return CRYPTO_get_ex_data(&r->ex_data, idx);
}

/*
 * X509_AUX ASN1 routines. X509_AUX is the name given to a certificate with
 * extra info tagged on the end. Since these functions set how a certificate
 * is trusted they should only be used when the certificate comes from a
 * reliable source such as local storage.
 */

X509 *d2i_X509_AUX(X509 **a, const unsigned char **pp, long length)
{
    const unsigned char *q;
    X509 *ret;
    int freeret = 0;

    /* Save start position */
    q = *pp;

    if (a == NULL || *a == NULL)
        freeret = 1;
    ret = d2i_X509(a, &q, length);
    /* If certificate unreadable then forget it */
    if (ret == NULL)
        return NULL;
    /* update length */
    length -= (long)(q - *pp);
    if (length > 0 && !d2i_X509_CERT_AUX(&ret->aux, &q, length))
        goto err;
    *pp = q;
    return ret;
err:
    if (freeret) {
        X509_free(ret);
        if (a)
            *a = NULL;
    }
    return NULL;
}

/*
 * Serialize trusted certificate to *pp or just return the required buffer
 * length if pp == NULL.  We ultimately want to avoid modifying *pp in the
 * error path, but that depends on similar hygiene in lower-level functions.
 * Here we avoid compounding the problem.
 */
static int i2d_x509_aux_internal(const X509 *a, unsigned char **pp)
{
    int length, tmplen;
    unsigned char *start = pp != NULL ? *pp : NULL;

    /*
     * This might perturb *pp on error, but fixing that belongs in i2d_X509()
     * not here.  It should be that if a == NULL length is zero, but we check
     * both just in case.
     */
    length = i2d_X509(a, pp);
    if (length <= 0 || a == NULL)
        return length;

    tmplen = i2d_X509_CERT_AUX(a->aux, pp);
    if (tmplen < 0) {
        if (start != NULL)
            *pp = start;
        return tmplen;
    }
    length += tmplen;

    return length;
}

/*
 * Serialize trusted certificate to *pp, or just return the required buffer
 * length if pp == NULL.
 *
 * When pp is not NULL, but *pp == NULL, we allocate the buffer, but since
 * we're writing two ASN.1 objects back to back, we can't have i2d_X509() do
 * the allocation, nor can we allow i2d_X509_CERT_AUX() to increment the
 * allocated buffer.
 */
int i2d_X509_AUX(const X509 *a, unsigned char **pp)
{
    int length;
    unsigned char *tmp;

    /* Buffer provided by caller */
    if (pp == NULL || *pp != NULL)
        return i2d_x509_aux_internal(a, pp);

    /* Obtain the combined length */
    if ((length = i2d_x509_aux_internal(a, NULL)) <= 0)
        return length;

    /* Allocate requisite combined storage */
    *pp = tmp = OPENSSL_malloc(length);
    if (tmp == NULL)
        return -1;

    /* Encode, but keep *pp at the originally malloced pointer */
    length = i2d_x509_aux_internal(a, &tmp);
    if (length <= 0) {
        OPENSSL_free(*pp);
        *pp = NULL;
    }
    return length;
}

int i2d_re_X509_tbs(X509 *x, unsigned char **pp)
{
    ossl_x509_set_modified(x);
    return i2d_X509_CINF(&x->cert_info, pp);
}

void X509_get0_signature(const ASN1_BIT_STRING **psig,
    const X509_ALGOR **palg, const X509 *x)
{
    if (psig)
        *psig = &x->signature;
    if (palg)
        *palg = &x->sig_alg;
}

int X509_get_signature_nid(const X509 *x)
{
    return OBJ_obj2nid(x->sig_alg.algorithm);
}

void X509_set0_distinguishing_id(X509 *x, ASN1_OCTET_STRING *d_id)
{
    ASN1_OCTET_STRING_free(x->distinguishing_id);
    x->distinguishing_id = d_id;
}

const ASN1_OCTET_STRING *X509_get0_distinguishing_id(const X509 *x)
{
    return x->distinguishing_id;
}
