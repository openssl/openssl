/*
 * Written by Rob Stradling (rob@comodo.com) and Stephen Henson
 * (steve@openssl.org) for the OpenSSL project 2014.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifdef OPENSSL_NO_CT
# error "CT is disabled"
#endif

#include <limits.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/buffer.h>
#include <openssl/ct.h>
#include <openssl/err.h>

#include "ct_locl.h"

int o2i_SCT_signature(SCT *sct, const unsigned char **in, size_t len)
{
    size_t siglen;
    size_t len_remaining = len;
    const unsigned char *p;

    if (sct->version != SCT_VERSION_V1) {
        CTerr(CT_F_O2I_SCT_SIGNATURE, CT_R_UNSUPPORTED_VERSION);
        return -1;
    }
    /*
     * digitally-signed struct header: (1 byte) Hash algorithm (1 byte)
     * Signature algorithm (2 bytes + ?) Signature
     *
     * This explicitly rejects empty signatures: they're invalid for
     * all supported algorithms.
     */
    if (len <= 4) {
        CTerr(CT_F_O2I_SCT_SIGNATURE, CT_R_SCT_INVALID_SIGNATURE);
        return -1;
    }

    p = *in;
    /* Get hash and signature algorithm */
    sct->hash_alg = *p++;
    sct->sig_alg = *p++;
    if (SCT_get_signature_nid(sct) == NID_undef) {
        CTerr(CT_F_O2I_SCT_SIGNATURE, CT_R_SCT_INVALID_SIGNATURE);
        return -1;
    }
    /* Retrieve signature and check it is consistent with the buffer length */
    n2s(p, siglen);
    len_remaining -= (p - *in);
    if (siglen > len_remaining) {
        CTerr(CT_F_O2I_SCT_SIGNATURE, CT_R_SCT_INVALID_SIGNATURE);
        return -1;
    }

    if (SCT_set1_signature(sct, p, siglen) != 1)
        return -1;
    len_remaining -= siglen;
    *in = p + siglen;

    return len - len_remaining;
}

SCT *o2i_SCT(SCT **psct, const unsigned char **in, size_t len)
{
    SCT *sct = NULL;
    const unsigned char *p;

    if (len == 0 || len > MAX_SCT_SIZE) {
        CTerr(CT_F_O2I_SCT, CT_R_SCT_INVALID);
        goto err;
    }

    if ((sct = SCT_new()) == NULL)
        goto err;

    p = *in;

    sct->version = *p;
    if (sct->version == SCT_VERSION_V1) {
        int sig_len;
        size_t len2;
        /*-
         * Fixed-length header:
         *   struct {
         *     Version sct_version;     (1 byte)
         *     log_id id;               (32 bytes)
         *     uint64 timestamp;        (8 bytes)
         *     CtExtensions extensions; (2 bytes + ?)
         *   }
         */
        if (len < 43) {
            CTerr(CT_F_O2I_SCT, CT_R_SCT_INVALID);
            goto err;
        }
        len -= 43;
        p++;
        sct->log_id = BUF_memdup(p, CT_V1_HASHLEN);
        if (sct->log_id == NULL)
            goto err;
        sct->log_id_len = CT_V1_HASHLEN;
        p += CT_V1_HASHLEN;

        n2l8(p, sct->timestamp);

        n2s(p, len2);
        if (len < len2) {
            CTerr(CT_F_O2I_SCT, CT_R_SCT_INVALID);
            goto err;
        }
        if (len2 > 0) {
            sct->ext = BUF_memdup(p, len2);
            if (sct->ext == NULL)
                goto err;
        }
        sct->ext_len = len2;
        p += len2;
        len -= len2;

        sig_len = o2i_SCT_signature(sct, &p, len);
        if (sig_len <= 0) {
            CTerr(CT_F_O2I_SCT, CT_R_SCT_INVALID);
            goto err;
        }
        len -= sig_len;
        *in = p + len;
    } else {
        /* If not V1 just cache encoding */
        sct->sct = BUF_memdup(p, len);
        if (sct->sct == NULL)
            goto err;
        sct->sct_len = len;
        *in = p + len;
    }

    if (psct != NULL) {
        SCT_free(*psct);
        *psct = sct;
    }

    return sct;
err:
    SCT_free(sct);
    return NULL;
}

int i2o_SCT_signature(const SCT *sct, unsigned char **out)
{
    size_t len;
    unsigned char *p = NULL;

    if (!SCT_signature_is_complete(sct)) {
        CTerr(CT_F_I2O_SCT_SIGNATURE, CT_R_SCT_INVALID_SIGNATURE);
        goto err;
    }

    if (sct->version != SCT_VERSION_V1) {
        CTerr(CT_F_I2O_SCT_SIGNATURE, CT_R_UNSUPPORTED_VERSION);
        goto err;
    }

    /*
    * (1 byte) Hash algorithm
    * (1 byte) Signature algorithm
    * (2 bytes + ?) Signature
    */
    len = 4 + sct->sig_len;

    if (out != NULL) {
        if (*out != NULL) {
            p = *out;
            *out += len;
        } else {
            p = OPENSSL_malloc(len);
            if (p == NULL) {
                CTerr(CT_F_I2O_SCT_SIGNATURE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            *out = p;
        }

        *p++ = sct->hash_alg;
        *p++ = sct->sig_alg;
        s2n(sct->sig_len, p);
        memcpy(p, sct->sig, sct->sig_len);
    }

    return len;
err:
    OPENSSL_free(p);
    return -1;
}

int i2o_SCT(const SCT *sct, unsigned char **out)
{
    size_t len;
    unsigned char *p = NULL;

    if (!SCT_is_complete(sct)) {
        CTerr(CT_F_I2O_SCT, CT_R_SCT_NOT_SET);
        goto err;
    }
    /*
     * Fixed-length header: struct { (1 byte) Version sct_version; (32 bytes)
     * log_id id; (8 bytes) uint64 timestamp; (2 bytes + ?) CtExtensions
     * extensions; (1 byte) Hash algorithm (1 byte) Signature algorithm (2
     * bytes + ?) Signature
     */
    if (sct->version == SCT_VERSION_V1)
        len = 43 + sct->ext_len + 4 + sct->sig_len;
    else
        len = sct->sct_len;

    if (out == NULL)
        return len;

    if (*out != NULL) {
        p = *out;
        *out += len;
    } else {
        p = OPENSSL_malloc(len);
        if (p == NULL) {
            CTerr(CT_F_I2O_SCT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        *out = p;
    }

    if (sct->version == SCT_VERSION_V1) {
        *p++ = sct->version;
        memcpy(p, sct->log_id, CT_V1_HASHLEN);
        p += CT_V1_HASHLEN;
        l2n8(sct->timestamp, p);
        s2n(sct->ext_len, p);
        if (sct->ext_len > 0) {
            memcpy(p, sct->ext, sct->ext_len);
            p += sct->ext_len;
        }
        if (i2o_SCT_signature(sct, &p) <= 0)
            goto err;
    } else {
        memcpy(p, sct->sct, len);
    }

    return len;
err:
    OPENSSL_free(p);
    return -1;
}

void SCT_LIST_free(STACK_OF(SCT) *a)
{
    sk_SCT_pop_free(a, SCT_free);
}

STACK_OF(SCT) *o2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
                            size_t len)
{
    STACK_OF(SCT) *sk = NULL;
    size_t list_len, sct_len;

    if (len < 2 || len > MAX_SCT_LIST_SIZE) {
        CTerr(CT_F_O2I_SCT_LIST, CT_R_SCT_LIST_INVALID);
        return NULL;
    }

    n2s(*pp, list_len);
    if (list_len != len - 2) {
        CTerr(CT_F_O2I_SCT_LIST, CT_R_SCT_LIST_INVALID);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        sk = sk_SCT_new_null();
        if (sk == NULL)
            return NULL;
    } else {
        SCT *sct;

        /* Use the given stack, but empty it first. */
        sk = *a;
        while ((sct = sk_SCT_pop(sk)) != NULL)
            SCT_free(sct);
    }

    while (list_len > 0) {
        SCT *sct;

        if (list_len < 2) {
            CTerr(CT_F_O2I_SCT_LIST, CT_R_SCT_LIST_INVALID);
            goto err;
        }
        n2s(*pp, sct_len);
        list_len -= 2;

        if (sct_len == 0 || sct_len > list_len) {
            CTerr(CT_F_O2I_SCT_LIST, CT_R_SCT_LIST_INVALID);
            goto err;
        }
        list_len -= sct_len;

        if ((sct = o2i_SCT(NULL, pp, sct_len)) == NULL)
            goto err;
        if (!sk_SCT_push(sk, sct)) {
            SCT_free(sct);
            goto err;
        }
    }

    if (a != NULL && *a == NULL)
        *a = sk;
    return sk;

 err:
    if (a == NULL || *a == NULL)
        SCT_LIST_free(sk);
    return NULL;
}

int i2o_SCT_LIST(const STACK_OF(SCT) *a, unsigned char **pp)
{
    int len, sct_len, i, is_pp_new = 0;
    size_t len2;
    unsigned char *p = NULL, *p2;

    if (pp != NULL) {
        if (*pp == NULL) {
            if ((len = i2o_SCT_LIST(a, NULL)) == -1) {
                CTerr(CT_F_I2O_SCT_LIST, CT_R_SCT_LIST_INVALID);
                return -1;
            }
            if ((*pp = OPENSSL_malloc(len)) == NULL) {
                CTerr(CT_F_I2O_SCT_LIST, ERR_R_MALLOC_FAILURE);
                return -1;
            }
            is_pp_new = 1;
        }
        p = *pp + 2;
    }

    len2 = 2;
    for (i = 0; i < sk_SCT_num(a); i++) {
        if (pp != NULL) {
            p2 = p;
            p += 2;
            if ((sct_len = i2o_SCT(sk_SCT_value(a, i), &p)) == -1)
                goto err;
            s2n(sct_len, p2);
        } else {
          if ((sct_len = i2o_SCT(sk_SCT_value(a, i), NULL)) == -1)
              goto err;
        }
        len2 += 2 + sct_len;
    }

    if (len2 > MAX_SCT_LIST_SIZE)
        goto err;

    if (pp != NULL) {
        p = *pp;
        s2n(len2 - 2, p);
    }
    if (!is_pp_new)
        *pp += len2;
    return len2;

 err:
    if (is_pp_new) {
        OPENSSL_free(*pp);
        *pp = NULL;
    }
    return -1;
}

STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
                            long len)
{
    ASN1_OCTET_STRING *oct = NULL;
    STACK_OF(SCT) *sk = NULL;
    const unsigned char *p;

    p = *pp;
    if (d2i_ASN1_OCTET_STRING(&oct, &p, len) == NULL)
        return NULL;

    p = oct->data;
    if ((sk = o2i_SCT_LIST(a, &p, oct->length)) != NULL)
        *pp += len;

    ASN1_OCTET_STRING_free(oct);
    return sk;
}

int i2d_SCT_LIST(const STACK_OF(SCT) *a, unsigned char **out)
{
    ASN1_OCTET_STRING oct;
    int len;

    oct.data = NULL;
    if ((oct.length = i2o_SCT_LIST(a, &oct.data)) == -1)
        return -1;

    len = i2d_ASN1_OCTET_STRING(&oct, out);
    OPENSSL_free(oct.data);
    return len;
}
