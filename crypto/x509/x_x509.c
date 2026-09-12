/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "crypto/x509.h"
#include "x509_local.h"

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

/*
 * Drop the buffer a certificate was decoded from, along with the saved
 * TBSCertificate encoding that points into it. The strings that point into
 * the buffer do not own their data and are freed as usual.
 */
static void x509_release_buffer(X509 *x)
{
    if (x->buf == NULL)
        return;
    x->cert_info.enc.enc = NULL;
    x->cert_info.enc.len = 0;
    x->cert_info.enc.modified = 1;
    CRYPTO_BUFFER_free(x->buf);
    x->buf = NULL;
}

static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
    void *exarg)
{
    X509 *ret = (X509 *)*pval;

    switch (operation) {

    case ASN1_OP_I2D_PRE:
        /*
         * A certificate that was never signed is encoded as an unsigned
         * certificate (RFC 9925): id-alg-unsigned with no parameters in both
         * signature algorithm fields and an empty signature.
         */
        if (OBJ_obj2nid(ret->sig_alg.algorithm) == NID_undef
            && ret->signature.length == 0) {
            if (!X509_ALGOR_set0(&ret->sig_alg, OBJ_nid2obj(NID_id_alg_unsigned),
                    V_ASN1_UNDEF, NULL)
                || !X509_ALGOR_set0(&ret->cert_info.signature,
                    OBJ_nid2obj(NID_id_alg_unsigned), V_ASN1_UNDEF, NULL))
                return 0;
            ret->cert_info.enc.modified = 1;
        }
        break;

    case ASN1_OP_D2I_PRE:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        X509_CERT_AUX_free(ret->aux);
        ASN1_OCTET_STRING_free(ret->distinguishing_id);
        /*
         * A certificate being decoded from its buffer has no saved encoding
         * yet and keeps the buffer; one with a saved encoding is being decoded
         * from other bytes.
         */
        if (ret->cert_info.enc.enc != NULL)
            x509_release_buffer(ret);

        /* fall through */

    case ASN1_OP_NEW_POST:
        ret->ex_kusage = 0;
        ret->ex_xkusage = 0;
        ret->ex_nscert = 0;
        ret->ex_flags = 0;
        ret->ex_pathlen = -1;
        ret->ex_pcpathlen = -1;
        ret->skid = NULL;
        ret->akid = NULL;
        ret->distinguishing_id = NULL;
        ret->aux = NULL;
        if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data))
            return 0;
        break;

    case ASN1_OP_D2I_POST:
        ossl_x509_finalize(ret);
        break;

    case ASN1_OP_FREE_PRE:
        x509_release_buffer(ret);
        break;

    case ASN1_OP_FREE_POST:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        X509_CERT_AUX_free(ret->aux);
        ASN1_OCTET_STRING_free(ret->distinguishing_id);
        break;

    case ASN1_OP_GET0_LIBCTX:
        ossl_x509_get0_libctx(ret, exarg, NULL);
        break;

    case ASN1_OP_GET0_PROPQ:
        ossl_x509_get0_libctx(ret, NULL, exarg);
        break;

    default:
        break;
    }

    return 1;
}

ASN1_SEQUENCE_ref_nolock(X509, x509_cb) = {
    ASN1_EMBED(X509, cert_info, X509_CINF),
    ASN1_EMBED(X509, sig_alg, X509_ALGOR),
    ASN1_EMBED(X509, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509, X509)

IMPLEMENT_ASN1_FUNCTIONS(X509)
IMPLEMENT_ASN1_DUP_FUNCTION(X509)

void ossl_x509_get0_libctx(const X509 *x, OSSL_LIB_CTX **libctx,
    const char **propq)
{
    if (libctx != NULL)
        *libctx = NULL;
    if (propq != NULL)
        *propq = NULL;
    if (x->cert_info.key != NULL)
        (void)ossl_x509_PUBKEY_get0_libctx(libctx, propq, x->cert_info.key);
}

X509 *X509_new_ex(OSSL_LIB_CTX *libctx, const char *propq)
{
    return (X509 *)ASN1_item_new_ex(ASN1_ITEM_rptr(X509), libctx, propq);
}

int ossl_x509_check_mutable(const X509 *x)
{
    if (x->buf != NULL) {
        ERR_raise(ERR_LIB_X509, X509_R_IMMUTABLE_CERTIFICATE);
        return 0;
    }
    return 1;
}

int ossl_x509_set_modified(X509 *x)
{
    if (!ossl_x509_check_mutable(x))
        return 0;
    ossl_x509_reset_ext_cache(x);
    x->cert_info.enc.modified = 1;
    return 1;
}

X509 *ossl_x509_parse_from_buffer(OSSL_LIB_CTX *libctx, const char *propq,
    CRYPTO_BUFFER *buf)
{
    const unsigned char *p = CRYPTO_BUFFER_data(buf);
    size_t len = CRYPTO_BUFFER_len(buf);
    X509 *x;

    if (len > LONG_MAX) {
        ERR_raise(ERR_LIB_X509, ASN1_R_TOO_LONG);
        return NULL;
    }
    if ((x = X509_new_ex(libctx, propq)) == NULL)
        return NULL;
    if (!CRYPTO_BUFFER_up_ref(buf)) {
        X509_free(x);
        return NULL;
    }
    x->buf = buf;
    /* On failure the decode frees x */
    if (ossl_asn1_item_d2i_borrow((ASN1_VALUE **)&x, &p, (long)len,
            ASN1_ITEM_rptr(X509), NULL, NULL)
        == NULL)
        return NULL;
    if (p != CRYPTO_BUFFER_data(buf) + len) {
        ERR_raise(ERR_LIB_X509, ASN1_R_TOO_LONG);
        X509_free(x);
        return NULL;
    }
    return x;
}

X509 *X509_parse_from_bytes(OSSL_LIB_CTX *libctx, const char *propq,
    const unsigned char *data, size_t len)
{
    CRYPTO_BUFFER *buf;
    X509 *x;

    if (data == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    buf = CRYPTO_BUFFER_new(data, len,
        ossl_lib_ctx_get0_certificate_pool(libctx));
    if (buf == NULL)
        return NULL;
    x = ossl_x509_parse_from_buffer(libctx, propq, buf);
    CRYPTO_BUFFER_free(buf);
    return x;
}

X509 *ossl_x509_parse_from_bytes_aux(OSSL_LIB_CTX *libctx, const char *propq,
    const unsigned char *data, size_t len)
{
    const unsigned char *p = data;
    size_t cert_len = len;
    long content_len;
    int tag, xclass;
    X509 *x;

    if (len > LONG_MAX) {
        ERR_raise(ERR_LIB_X509, ASN1_R_TOO_LONG);
        return NULL;
    }
    /*
     * The certificate is the first definite-length object; the decode reports
     * a malformed header, so one is left for it to report.
     */
    ERR_set_mark();
    if ((ASN1_get_object(&p, &content_len, &tag, &xclass, (long)len) & 0x81) == 0)
        cert_len = (size_t)(p - data) + (size_t)content_len;
    ERR_pop_to_mark();

    if ((x = X509_parse_from_bytes(libctx, propq, data, cert_len)) == NULL)
        return NULL;
    if (cert_len < len) {
        p = data + cert_len;
        if (d2i_X509_CERT_AUX(&x->aux, &p, (long)(len - cert_len)) == NULL) {
            X509_free(x);
            return NULL;
        }
    }
    return x;
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
    x->cert_info.enc.modified = 1;
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
