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
#include <openssl/x509v3.h>

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

struct IETF_ATTR_SYNTAX_VALUE_st {
    int type;
    union {
        ASN1_OCTET_STRING *octets;
        ASN1_OBJECT *oid;
        ASN1_UTF8STRING *string;
    } u;
};

struct IETF_ATTR_SYNTAX_st {
    GENERAL_NAMES *policyAuthority;
    STACK_OF(IETF_ATTR_SYNTAX_VALUE) *values;
};

ASN1_CHOICE(IETF_ATTR_SYNTAX_VALUE) = {
    ASN1_SIMPLE(IETF_ATTR_SYNTAX_VALUE, u.octets, ASN1_OCTET_STRING),
    ASN1_SIMPLE(IETF_ATTR_SYNTAX_VALUE, u.oid, ASN1_OBJECT),
    ASN1_SIMPLE(IETF_ATTR_SYNTAX_VALUE, u.string, ASN1_UTF8STRING),
} ASN1_CHOICE_END(IETF_ATTR_SYNTAX_VALUE)

ASN1_SEQUENCE(IETF_ATTR_SYNTAX) = {
    ASN1_IMP_SEQUENCE_OF_OPT(IETF_ATTR_SYNTAX, policyAuthority, GENERAL_NAME, 0),
    ASN1_SEQUENCE_OF(IETF_ATTR_SYNTAX, values, IETF_ATTR_SYNTAX_VALUE),
} ASN1_SEQUENCE_END(IETF_ATTR_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(IETF_ATTR_SYNTAX)
IMPLEMENT_ASN1_FUNCTIONS(IETF_ATTR_SYNTAX_VALUE)

int IETF_ATTR_SYNTAX_get_value_num(const IETF_ATTR_SYNTAX *a)
{
    return sk_IETF_ATTR_SYNTAX_VALUE_num(a->values);
}

const GENERAL_NAMES *
IETF_ATTR_SYNTAX_get0_policyAuthority(const IETF_ATTR_SYNTAX *a)
{
    return a->policyAuthority;
}

void IETF_ATTR_SYNTAX_set0_policyAuthority(IETF_ATTR_SYNTAX *a,
                                           GENERAL_NAMES *names)
{
    GENERAL_NAMES_free(a->policyAuthority);
    a->policyAuthority = names;
}

void *IETF_ATTR_SYNTAX_get0_value(const IETF_ATTR_SYNTAX *a, int ind, int *type)
{
    IETF_ATTR_SYNTAX_VALUE *val;

    val = sk_IETF_ATTR_SYNTAX_VALUE_value(a->values, ind);
    if (type != NULL)
        *type = val->type;

    switch (val->type) {
    case IETFAS_OCTETS:
        return val->u.octets;
    case IETFAS_OID:
        return val->u.oid;
    case IETFAS_STRING:
        return val->u.string;
    }

    return NULL;
}

int IETF_ATTR_SYNTAX_add1_value(IETF_ATTR_SYNTAX *a, int type, void *data)
{
    IETF_ATTR_SYNTAX_VALUE *val;

    if (data == NULL)
        return 0;

    if (a->values == NULL) {
        if ((a->values = sk_IETF_ATTR_SYNTAX_VALUE_new_null()) == NULL)
            goto oom;
    }

    if ((val = IETF_ATTR_SYNTAX_VALUE_new()) == NULL)
        goto oom;

    val->type = type;
    switch (type) {
    case IETFAS_OCTETS:
        val->u.octets = data;
        break;
    case IETFAS_OID:
        val->u.oid = data;
        break;
    case IETFAS_STRING:
        val->u.string = data;
        break;
    }

    if (sk_IETF_ATTR_SYNTAX_VALUE_push(a->values, val) <= 0) {
        IETF_ATTR_SYNTAX_VALUE_free(val);
        return 0;
    }

    return 1;

oom:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    return 0;
}

int IETF_ATTR_SYNTAX_print(BIO *bp, IETF_ATTR_SYNTAX *a, int indent)
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

    for (i = 0; i < IETF_ATTR_SYNTAX_get_value_num(a); i++) {
        char oidstr[80];
        int ietf_type;
        void *attr_value = IETF_ATTR_SYNTAX_get0_value(a, i, &ietf_type);

        if (BIO_printf(bp, "%*s", indent, "") <= 0)
            goto err;

        switch (ietf_type) {
        case IETFAS_OID:
            OBJ_obj2txt(oidstr, sizeof(oidstr), attr_value, 0);
            BIO_printf(bp, "%.*s", (int) sizeof(oidstr), oidstr);
            break;
        case IETFAS_OCTETS:
        case IETFAS_STRING:
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
