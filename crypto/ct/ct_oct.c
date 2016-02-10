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
 
#ifndef OPENSSL_NO_CT

# include <limits.h>
# include "internal/cryptlib.h"
# include <openssl/asn1.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include "crypto/include/internal/ct_int.h"

# define n2s(c,s)        ((s=(((unsigned int)((c)[0]))<< 8)| \
                             (((unsigned int)((c)[1]))    )),c+=2)

# define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                           c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

# define n2l8(c,l)       (l =((uint64_t)(*((c)++)))<<56, \
                          l|=((uint64_t)(*((c)++)))<<48, \
                          l|=((uint64_t)(*((c)++)))<<40, \
                          l|=((uint64_t)(*((c)++)))<<32, \
                          l|=((uint64_t)(*((c)++)))<<24, \
                          l|=((uint64_t)(*((c)++)))<<16, \
                          l|=((uint64_t)(*((c)++)))<< 8, \
                          l|=((uint64_t)(*((c)++))))

# define l2n8(l,c)       (*((c)++)=(unsigned char)(((l)>>56)&0xff), \
                          *((c)++)=(unsigned char)(((l)>>48)&0xff), \
                          *((c)++)=(unsigned char)(((l)>>40)&0xff), \
                          *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                          *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                          *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                          *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                          *((c)++)=(unsigned char)(((l)    )&0xff))

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a,
                                   const unsigned char **pp, int len);
static int i2d_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp);
static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent);

static char *i2s_poison(const X509V3_EXT_METHOD *method, void *val)
{
    return OPENSSL_strdup("NULL");
}

const X509V3_EXT_METHOD v3_ct_scts[] = {
    { NID_ct_precert_scts, 0, NULL,
    0, (X509V3_EXT_FREE)SCT_LIST_free,
    (X509V3_EXT_D2I)d2i_SCT_LIST, (X509V3_EXT_I2D)i2d_SCT_LIST,
    0, 0, 0, 0,
    (X509V3_EXT_I2R)i2r_SCT_LIST, 0,
    NULL },

    { NID_ct_precert_poison, 0, ASN1_ITEM_ref(ASN1_NULL),
    0, 0, 0, 0, i2s_poison, 0,
    0, 0, 0, 0, NULL },

    { NID_ct_cert_scts, 0, NULL,
    0, (X509V3_EXT_FREE)SCT_LIST_free,
    (X509V3_EXT_D2I)d2i_SCT_LIST, (X509V3_EXT_I2D)i2d_SCT_LIST,
    0, 0, 0, 0,
    (X509V3_EXT_I2R)i2r_SCT_LIST, 0,
    NULL },
};

int SCT_signature_is_valid(const SCT *sct)
{
    if (sct == NULL) {
        CTerr(CT_F_SCT_SIGNATURE_IS_VALID, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    if (SCT_get_signature_nid(sct) == NID_undef ||
        sct->sig_len == 0 || sct->sig == NULL) {
        return 0;
    }

    return 1;
}


int o2i_SCT_signature(SCT *sct, const unsigned char **in, size_t len)
{
    int ret = -1;
    size_t siglen;
    size_t len_remaining = len;
    const unsigned char *p = *in;

    if (sct == NULL || in == NULL || *in == NULL) {
        CTerr(CT_F_O2I_SCT_SIGNATURE, ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }

    if (sct->version != SCT_V1) {
        CTerr(CT_F_O2I_SCT_SIGNATURE, CT_R_UNSUPPORTED_VERSION);
        goto end;
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
        goto end;
    }

    /* Get hash and signature algorithm */
    sct->hash_alg = *p++;
    sct->sig_alg = *p++;
    if (SCT_get_signature_nid(sct) == NID_undef) {
        CTerr(CT_F_O2I_SCT_SIGNATURE, CT_R_SCT_INVALID_SIGNATURE);
        goto end;
    }
    /* Retrieve signature and check it is consistent with the buffer length */
    n2s(p, siglen);
    len_remaining -= (p - *in);
    if (siglen > len_remaining) {
        CTerr(CT_F_O2I_SCT_SIGNATURE, CT_R_SCT_INVALID_SIGNATURE);
        goto end;
    }

    if (SCT_set1_signature(sct, p, siglen) != 1)
        goto end;
    len_remaining -= siglen;

    *in = p + siglen;
    ret = len - len_remaining;

end:
    return ret;
}

SCT *o2i_SCT(SCT **psct, const unsigned char **in, size_t len)
{
    SCT *sct = NULL;
    const unsigned char *p;

    if (in == NULL || *in == NULL) {
        CTerr(CT_F_O2I_SCT, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    } else if (len > MAX_SCT_SIZE || len == 0) {
        CTerr(CT_F_O2I_SCT, CT_R_SCT_INVALID);
        goto err;
    }

    if ((sct = SCT_new()) == NULL)
        goto err;

    p = *in;

    sct->version = *p;
    if (sct->version == 0) {    /* SCT v1 */
        int sig_len;
        size_t len2;
        /*
         * Fixed-length header: struct { (1 byte) Version sct_version; (32
         * bytes) log_id id; (8 bytes) uint64 timestamp; (2 bytes + ?)
         * CtExtensions extensions;
         */
        if (len < 43) {
            CTerr(CT_F_O2I_SCT, CT_R_SCT_INVALID);
            goto err;
        }
        len -= 43;
        p++;
        sct->log_id = BUF_memdup(p, SCT_V1_HASHLEN);
        if (sct->log_id == NULL)
            goto err;
        sct->log_id_len = SCT_V1_HASHLEN;
        p += SCT_V1_HASHLEN;

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

    if (sct == NULL) {
        CTerr(CT_F_I2O_SCT_SIGNATURE, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    } else if (!SCT_signature_is_valid(sct)) {
        CTerr(CT_F_I2O_SCT_SIGNATURE, CT_R_SCT_INVALID_SIGNATURE);
        goto err;
    }

    if (sct->version != SCT_V1) {
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

    if (sct == NULL) {
        CTerr(CT_F_I2O_SCT, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }
    if (!SCT_is_valid(sct)) {
        CTerr(CT_F_I2O_SCT, CT_R_SCT_NOT_SET);
        goto err;
    }
    /*
     * Fixed-length header: struct { (1 byte) Version sct_version; (32 bytes)
     * log_id id; (8 bytes) uint64 timestamp; (2 bytes + ?) CtExtensions
     * extensions; (1 byte) Hash algorithm (1 byte) Signature algorithm (2
     * bytes + ?) Signature
     */
    if (sct->version == 0)
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

    if (sct->version == 0) {
        *p++ = sct->version;
        memcpy(p, sct->log_id, SCT_V1_HASHLEN);
        p += SCT_V1_HASHLEN;
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

    if (pp == NULL || *pp == NULL) {
        CTerr(CT_F_O2I_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (len < 2 || len > MAX_SCT_LIST_SIZE) {
        CTerr(CT_F_O2I_SCT_LIST, CT_R_SCT_LIST_INVALID);
        return NULL;
    }

    n2s(*pp, list_len);
    if (list_len != len - 2) {
        CTerr(CT_F_O2I_SCT_LIST, CT_R_SCT_LIST_INVALID);
        return NULL;
    }

    if (a != NULL && *a != NULL) {
        SCT *sct;
        sk = *a;
        while ((sct = sk_SCT_pop(sk)) != NULL)
            SCT_free(sct);
    } else if ((sk = sk_SCT_new_null()) == NULL) {
        return NULL;
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

int i2o_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp)
{
    int len, sct_len, i, is_pp_new = 0;
    size_t len2;
    unsigned char *p = NULL, *p2;

    if (a == NULL) {
        CTerr(CT_F_I2O_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

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

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a,
                                   const unsigned char **pp, int len)
{
    ASN1_OCTET_STRING *oct = NULL;
    STACK_OF(SCT) *sk = NULL;
    const unsigned char *p;

    if (pp == NULL || *pp == NULL) {
        CTerr(CT_F_D2I_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    p = *pp;
    if (d2i_ASN1_OCTET_STRING(&oct, &p, len) == NULL)
        return NULL;

    p = oct->data;
    if ((sk = o2i_SCT_LIST(a, &p, oct->length)) != NULL)
        *pp += len;

    ASN1_OCTET_STRING_free(oct);
    return sk;
}

static int i2d_SCT_LIST(STACK_OF(SCT) *a, unsigned char **out)
{
    ASN1_OCTET_STRING oct;
    int len;

    if (a == NULL) {
        CTerr(CT_F_I2D_SCT_LIST, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    oct.data = NULL;
    if ((oct.length = i2o_SCT_LIST(a, &oct.data)) == -1)
        return -1;

    len = i2d_ASN1_OCTET_STRING(&oct, out);
    OPENSSL_free(oct.data);
    return len;
}

static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent)
{
    int i;
    for (i = 0; i < sk_SCT_num(sct_list); ++i) {
        SCT *sct = sk_SCT_value(sct_list, i);
        SCT_print(sct, out, indent);
        if (i < sk_SCT_num(sct_list) - 1)
            BIO_printf(out, "\n");
    }

    return 1;
}

#endif
