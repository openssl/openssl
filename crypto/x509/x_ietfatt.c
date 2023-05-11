/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/x509_acert.h>

/*-
 * Definition of IetfAttrSyntax from RFC 5755 4.4
 *
 * IetfAttrSyntax ::= SEQUENCE {
 *   policyAuthority [0] GeneralNames    OPTIONAL,
 *   values          SEQUENCE OF CHOICE {
 *                     octets    OCTET STRING,
 *                     oid       OBJECT IDENTIFIER,
 *                     string    UTF8String
 *                   }
 * }
 *
 * Section 4.4.2 states that all values in the sequence MUST use the
 * same choice of value (octect, oid or string).  This restriction is
 * not explicitly enforced by the current implementation.
 */

struct OSSL_IETF_ATTR_SYNTAX_VALUE_st {
    int type;
    union {
        ASN1_OCTET_STRING *octets;
        ASN1_OBJECT *oid;
        ASN1_UTF8STRING *string;
    } u;
};

struct OSSL_IETF_ATTR_SYNTAX_st {
    GENERAL_NAMES *policyAuthority;
    STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *values;
};

ASN1_CHOICE(OSSL_IETF_ATTR_SYNTAX_VALUE) = {
    ASN1_SIMPLE(OSSL_IETF_ATTR_SYNTAX_VALUE, u.octets, ASN1_OCTET_STRING),
    ASN1_SIMPLE(OSSL_IETF_ATTR_SYNTAX_VALUE, u.oid, ASN1_OBJECT),
    ASN1_SIMPLE(OSSL_IETF_ATTR_SYNTAX_VALUE, u.string, ASN1_UTF8STRING),
} ASN1_CHOICE_END(OSSL_IETF_ATTR_SYNTAX_VALUE)

ASN1_SEQUENCE(OSSL_IETF_ATTR_SYNTAX) = {
    ASN1_IMP_SEQUENCE_OF_OPT(OSSL_IETF_ATTR_SYNTAX, policyAuthority, GENERAL_NAME, 0),
    ASN1_SEQUENCE_OF(OSSL_IETF_ATTR_SYNTAX, values, OSSL_IETF_ATTR_SYNTAX_VALUE),
} ASN1_SEQUENCE_END(OSSL_IETF_ATTR_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_IETF_ATTR_SYNTAX)
IMPLEMENT_ASN1_FUNCTIONS(OSSL_IETF_ATTR_SYNTAX_VALUE)

int OSSL_IETF_ATTR_SYNTAX_get_value_num(const OSSL_IETF_ATTR_SYNTAX *a)
{
    if (a->values == NULL)
        return 0;

    return sk_OSSL_IETF_ATTR_SYNTAX_VALUE_num(a->values);
}

const GENERAL_NAMES *
OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(const OSSL_IETF_ATTR_SYNTAX *a)
{
    return a->policyAuthority;
}

void OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(OSSL_IETF_ATTR_SYNTAX *a,
                                           GENERAL_NAMES *names)
{
    GENERAL_NAMES_free(a->policyAuthority);
    a->policyAuthority = names;
}

void *OSSL_IETF_ATTR_SYNTAX_get0_value(const OSSL_IETF_ATTR_SYNTAX *a, int ind, int *type)
{
    OSSL_IETF_ATTR_SYNTAX_VALUE *val;

    val = sk_OSSL_IETF_ATTR_SYNTAX_VALUE_value(a->values, ind);
    if (type != NULL)
        *type = val->type;

    switch (val->type) {
    case OSSL_IETFAS_OCTETS:
        return val->u.octets;
    case OSSL_IETFAS_OID:
        return val->u.oid;
    case OSSL_IETFAS_STRING:
        return val->u.string;
    }

    return NULL;
}

int OSSL_IETF_ATTR_SYNTAX_add1_value(OSSL_IETF_ATTR_SYNTAX *a, int type, void *data)
{
    OSSL_IETF_ATTR_SYNTAX_VALUE *val;

    if (data == NULL)
        return 0;

    if (a->values == NULL) {
        if ((a->values = sk_OSSL_IETF_ATTR_SYNTAX_VALUE_new_null()) == NULL)
            goto oom;
    }

    if ((val = OSSL_IETF_ATTR_SYNTAX_VALUE_new()) == NULL)
        goto oom;

    val->type = type;
    switch (type) {
    case OSSL_IETFAS_OCTETS:
        val->u.octets = data;
        break;
    case OSSL_IETFAS_OID:
        val->u.oid = data;
        break;
    case OSSL_IETFAS_STRING:
        val->u.string = data;
        break;
    }

    if (sk_OSSL_IETF_ATTR_SYNTAX_VALUE_push(a->values, val) <= 0) {
        OSSL_IETF_ATTR_SYNTAX_VALUE_free(val);
        return 0;
    }

    return 1;

oom:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    return 0;
}

int OSSL_IETF_ATTR_SYNTAX_print(BIO *bp, OSSL_IETF_ATTR_SYNTAX *a, int indent)
{
    int i;

    if (a->policyAuthority != NULL) {
        for (i = 0; i < sk_GENERAL_NAME_num(a->policyAuthority); i++) {
            if (BIO_printf(bp, "%*s", indent, "") <= 0)
                goto err;

            if (GENERAL_NAME_print(bp, sk_GENERAL_NAME_value(a->policyAuthority,
                                                             i)) <= 0)
                goto err;

            if (BIO_printf(bp, "\n") <= 0)
                goto err;
        }
    }

    for (i = 0; i < OSSL_IETF_ATTR_SYNTAX_get_value_num(a); i++) {
        char oidstr[80];
        int ietf_type;
        void *attr_value = OSSL_IETF_ATTR_SYNTAX_get0_value(a, i, &ietf_type);

        if (BIO_printf(bp, "%*s", indent, "") <= 0)
            goto err;

        switch (ietf_type) {
        case OSSL_IETFAS_OID:
            OBJ_obj2txt(oidstr, sizeof(oidstr), attr_value, 0);
            BIO_printf(bp, "%.*s", (int) sizeof(oidstr), oidstr);
            break;
        case OSSL_IETFAS_OCTETS:
        case OSSL_IETFAS_STRING:
            ASN1_STRING_print(bp, attr_value);
            break;
        }
    }
    if (BIO_printf(bp, "\n") <= 0)
        goto err;

    return 1;

err:
    return 0;
}
