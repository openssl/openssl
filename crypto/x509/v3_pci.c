/*
 * Copyright 2004-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file is dual-licensed and is also available under the following
 * terms:
 *
 * Copyright (c) 2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

static int i2r_pci(X509V3_EXT_METHOD *method, PROXY_CERT_INFO_EXTENSION *ext,
    BIO *out, int indent);
static PROXY_CERT_INFO_EXTENSION *r2i_pci(X509V3_EXT_METHOD *method,
    X509V3_CTX *ctx, char *str);

const X509V3_EXT_METHOD ossl_v3_pci = {
    NID_proxyCertInfo,
    0,
    ASN1_ITEM_ref(PROXY_CERT_INFO_EXTENSION),
    0,
    0,
    0,
    0,
    0,
    0,
    NULL,
    NULL,
    (X509V3_EXT_I2R)i2r_pci,
    (X509V3_EXT_R2I)r2i_pci,
    NULL,
};

static int i2r_pci(X509V3_EXT_METHOD *method, PROXY_CERT_INFO_EXTENSION *pci,
    BIO *out, int indent)
{
    BIO_printf(out, "%*sPath Length Constraint: ", indent, "");
    if (pci->pcPathLengthConstraint)
        i2a_ASN1_INTEGER(out, pci->pcPathLengthConstraint);
    else
        BIO_printf(out, "infinite");
    BIO_puts(out, "\n");
    BIO_printf(out, "%*sPolicy Language: ", indent, "");
    i2a_ASN1_OBJECT(out, pci->proxyPolicy->policyLanguage);
    if (pci->proxyPolicy->policy != NULL
        && ASN1_STRING_get0_data(pci->proxyPolicy->policy) != NULL)
        BIO_printf(out, "\n%*sPolicy Text: %.*s", indent, "",
            ASN1_STRING_length(pci->proxyPolicy->policy),
            (const char *)ASN1_STRING_get0_data(pci->proxyPolicy->policy));
    return 1;
}

static int process_pci_value(CONF_VALUE *val,
    ASN1_OBJECT **language, ASN1_INTEGER **pathlen,
    ASN1_OCTET_STRING **policy)
{
    int free_policy = 0;

    if (strcmp(val->name, "language") == 0) {
        if (*language) {
            ERR_raise(ERR_LIB_X509V3, X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED);
            X509V3_conf_err(val);
            return 0;
        }
        if ((*language = OBJ_txt2obj(val->value, 0)) == NULL) {
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER);
            X509V3_conf_err(val);
            return 0;
        }
    } else if (strcmp(val->name, "pathlen") == 0) {
        if (*pathlen) {
            ERR_raise(ERR_LIB_X509V3,
                X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED);
            X509V3_conf_err(val);
            return 0;
        }
        if (!X509V3_get_value_int(val, pathlen)) {
            ERR_raise(ERR_LIB_X509V3, X509V3_R_POLICY_PATH_LENGTH);
            X509V3_conf_err(val);
            return 0;
        }
    } else if (strcmp(val->name, "policy") == 0) {
        char *valp = val->value;
        long val_len;

        if (*policy == NULL) {
            *policy = ASN1_OCTET_STRING_new();
            if (*policy == NULL) {
                ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
                X509V3_conf_err(val);
                return 0;
            }
            free_policy = 1;
        }
        if (CHECK_AND_SKIP_PREFIX(valp, "hex:")) {
            unsigned char *tmp_data2 = OPENSSL_hexstr2buf(valp, &val_len);
            int old_len = ASN1_STRING_length(*policy);
            int new_len = old_len + val_len;
            unsigned char *tmp_buf;

            if (!tmp_data2) {
                X509V3_conf_err(val);
                goto err;
            }

            tmp_buf = OPENSSL_malloc(new_len);
            if (tmp_buf == NULL) {
                OPENSSL_free(tmp_data2);
                X509V3_conf_err(val);
                goto err;
            }
            if (old_len > 0)
                memcpy(tmp_buf, ASN1_STRING_get0_data(*policy), old_len);
            memcpy(tmp_buf + old_len, tmp_data2, val_len);
            OPENSSL_free(tmp_data2);
            if (!ASN1_STRING_set(*policy, tmp_buf, new_len)) {
                OPENSSL_free(tmp_buf);
                X509V3_conf_err(val);
                goto err;
            }
            OPENSSL_free(tmp_buf);
        } else if (CHECK_AND_SKIP_PREFIX(valp, "file:")) {
            unsigned char buf[2048];
            int n;
            BIO *b = BIO_new_file(valp, "r");
            if (!b) {
                ERR_raise(ERR_LIB_X509V3, ERR_R_BIO_LIB);
                X509V3_conf_err(val);
                goto err;
            }
            while ((n = BIO_read(b, buf, sizeof(buf))) > 0
                || (n == 0 && BIO_should_retry(b))) {
                int old_len;
                int new_len;
                unsigned char *tmp_buf;

                if (!n)
                    continue;

                old_len = ASN1_STRING_length(*policy);
                new_len = old_len + n;
                tmp_buf = OPENSSL_malloc(new_len);
                if (tmp_buf == NULL) {
                    X509V3_conf_err(val);
                    BIO_free_all(b);
                    goto err;
                }
                if (old_len > 0)
                    memcpy(tmp_buf, ASN1_STRING_get0_data(*policy), old_len);
                memcpy(tmp_buf + old_len, buf, n);
                if (!ASN1_STRING_set(*policy, tmp_buf, new_len)) {
                    OPENSSL_free(tmp_buf);
                    X509V3_conf_err(val);
                    BIO_free_all(b);
                    goto err;
                }
                OPENSSL_free(tmp_buf);
            }
            BIO_free_all(b);

            if (n < 0) {
                ERR_raise(ERR_LIB_X509V3, ERR_R_BIO_LIB);
                X509V3_conf_err(val);
                goto err;
            }
        } else if (CHECK_AND_SKIP_PREFIX(valp, "text:")) {
            int old_len = ASN1_STRING_length(*policy);
            int new_len;
            unsigned char *tmp_buf;

            val_len = (int)strlen(valp);
            new_len = old_len + (int)val_len;
            tmp_buf = OPENSSL_malloc(new_len);
            if (tmp_buf == NULL) {
                X509V3_conf_err(val);
                goto err;
            }
            if (old_len > 0)
                memcpy(tmp_buf, ASN1_STRING_get0_data(*policy), old_len);
            memcpy(tmp_buf + old_len, val->value + 5, val_len);
            if (!ASN1_STRING_set(*policy, tmp_buf, new_len)) {
                OPENSSL_free(tmp_buf);
                X509V3_conf_err(val);
                goto err;
            }
            OPENSSL_free(tmp_buf);
        } else {
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INCORRECT_POLICY_SYNTAX_TAG);
            X509V3_conf_err(val);
            goto err;
        }
    }
    return 1;
err:
    if (free_policy) {
        ASN1_OCTET_STRING_free(*policy);
        *policy = NULL;
    }
    return 0;
}

static PROXY_CERT_INFO_EXTENSION *r2i_pci(X509V3_EXT_METHOD *method,
    X509V3_CTX *ctx, char *value)
{
    PROXY_CERT_INFO_EXTENSION *pci = NULL;
    STACK_OF(CONF_VALUE) *vals;
    ASN1_OBJECT *language = NULL;
    ASN1_INTEGER *pathlen = NULL;
    ASN1_OCTET_STRING *policy = NULL;
    int i, j;

    vals = X509V3_parse_list(value);
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        CONF_VALUE *cnf = sk_CONF_VALUE_value(vals, i);

        if (!cnf->name || (*cnf->name != '@' && !cnf->value)) {
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_PROXY_POLICY_SETTING);
            X509V3_conf_err(cnf);
            goto err;
        }
        if (*cnf->name == '@') {
            STACK_OF(CONF_VALUE) *sect;
            int success_p = 1;

            sect = X509V3_get_section(ctx, cnf->name + 1);
            if (!sect) {
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_SECTION);
                X509V3_conf_err(cnf);
                goto err;
            }
            for (j = 0; success_p && j < sk_CONF_VALUE_num(sect); j++) {
                success_p = process_pci_value(sk_CONF_VALUE_value(sect, j),
                    &language, &pathlen, &policy);
            }
            X509V3_section_free(ctx, sect);
            if (!success_p)
                goto err;
        } else {
            if (!process_pci_value(cnf, &language, &pathlen, &policy)) {
                X509V3_conf_err(cnf);
                goto err;
            }
        }
    }

    /* Language is mandatory */
    if (!language) {
        ERR_raise(ERR_LIB_X509V3,
            X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED);
        goto err;
    }
    i = OBJ_obj2nid(language);
    if ((i == NID_Independent || i == NID_id_ppl_inheritAll) && policy) {
        ERR_raise(ERR_LIB_X509V3,
            X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY);
        goto err;
    }

    pci = PROXY_CERT_INFO_EXTENSION_new();
    if (pci == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
        goto err;
    }

    pci->proxyPolicy->policyLanguage = language;
    language = NULL;
    pci->proxyPolicy->policy = policy;
    policy = NULL;
    pci->pcPathLengthConstraint = pathlen;
    pathlen = NULL;
    goto end;
err:
    ASN1_OBJECT_free(language);
    ASN1_INTEGER_free(pathlen);
    pathlen = NULL;
    ASN1_OCTET_STRING_free(policy);
    policy = NULL;
    PROXY_CERT_INFO_EXTENSION_free(pci);
    pci = NULL;
end:
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return pci;
}
