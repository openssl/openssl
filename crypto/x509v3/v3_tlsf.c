/* v3_tlsf.c */
/*
 * Written by Rob Stradling (rob@comodo.com) for the OpenSSL project 2015.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/o_str.h"
#include <openssl/asn1t.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

static STACK_OF(CONF_VALUE) *i2v_TLS_FEATURE(const X509V3_EXT_METHOD *method,
                                             TLS_FEATURE *tls_feature,
                                             STACK_OF(CONF_VALUE) *ext_list);
static TLS_FEATURE *v2i_TLS_FEATURE(const X509V3_EXT_METHOD *method,
                                    X509V3_CTX *ctx,
                                    STACK_OF(CONF_VALUE) *nval);

const X509V3_EXT_METHOD v3_tls_feature = {
    NID_tlsfeature, 0,
    ASN1_ITEM_ref(TLS_FEATURE),
    0, 0, 0, 0,
    0, 0,
    (X509V3_EXT_I2V)i2v_TLS_FEATURE,
    (X509V3_EXT_V2I)v2i_TLS_FEATURE,
    0, 0,
    NULL
};

ASN1_ITEM_TEMPLATE(TLS_FEATURE) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, TLS_FEATURE, ASN1_INTEGER)
ASN1_ITEM_TEMPLATE_END(TLS_FEATURE)

IMPLEMENT_ASN1_FUNCTIONS(TLS_FEATURE)

typedef struct {
    long num;
    const char *name;
} TLS_FEATURE_NAME;

static TLS_FEATURE_NAME tls_feature_tbl[] = {
    { 5, "status_request" },
    { 17, "status_request_v2" },
    { -1, NULL }
};

static STACK_OF(CONF_VALUE) *i2v_TLS_FEATURE(const X509V3_EXT_METHOD *method,
                                             TLS_FEATURE *tls_feature,
                                             STACK_OF(CONF_VALUE) *ext_list)
{
    int i, j;
    ASN1_INTEGER *ai;
    long tlsextid;
    for (i = 0; i < sk_ASN1_INTEGER_num(tls_feature); i++) {
        ai = sk_ASN1_INTEGER_value(tls_feature, i);
        tlsextid = ASN1_INTEGER_get(ai);
        for (j = 0; tls_feature_tbl[j].num != -1; j++)
            if (tlsextid == tls_feature_tbl[j].num)
                break;
        if (tls_feature_tbl[j].num != -1)
            X509V3_add_value(NULL, tls_feature_tbl[j].name, &ext_list);
        else
            X509V3_add_value_int(NULL, ai, &ext_list);
    }
    return ext_list;
}

static TLS_FEATURE *v2i_TLS_FEATURE(const X509V3_EXT_METHOD *method,
                                    X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    TLS_FEATURE *tlsf;
    char *extval, *endptr;
    ASN1_INTEGER *ai;
    CONF_VALUE *val;
    int i, j;
    long tlsextid;

    if ((tlsf = sk_ASN1_INTEGER_new_null()) == NULL) {
        X509V3err(X509V3_F_V2I_TLS_FEATURE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (val->value)
            extval = val->value;
        else
            extval = val->name;

        for (j = 0; tls_feature_tbl[j].num != -1; j++)
            if (OPENSSL_strcasecmp(extval, tls_feature_tbl[j].name) == 0)
                break;
        if (tls_feature_tbl[j].num != -1)
            tlsextid = tls_feature_tbl[j].num;
        else {
            tlsextid = strtol(extval, &endptr, 10);
            if (*endptr || (tlsextid < 0) || (tlsextid > 65535)) {
                X509V3err(X509V3_F_V2I_TLS_FEATURE, X509V3_R_INVALID_SYNTAX);
                X509V3_conf_err(val);
                goto err;
            }
        }

        ai = ASN1_INTEGER_new();
        if (ai == NULL) {
            X509V3err(X509V3_F_V2I_TLS_FEATURE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        ASN1_INTEGER_set(ai, tlsextid);
        sk_ASN1_INTEGER_push(tlsf, ai);
    }
    return tlsf;

 err:
    sk_ASN1_INTEGER_pop_free(tlsf, ASN1_INTEGER_free);
    return NULL;
}
