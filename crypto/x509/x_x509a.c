/*
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

/*
 * X509_CERT_AUX routines. These are used to encode additional user
 * modifiable data about a certificate. This data is appended to the X509
 * encoding when the *_X509_AUX routines are used. This means that the
 * "traditional" X509 routines will simply ignore the extra data.
 */

static X509_CERT_AUX *aux_get(X509 *x);

ASN1_SEQUENCE(X509_CERT_AUX) = {
        ASN1_SEQUENCE_OF_OPT(X509_CERT_AUX, trust, ASN1_OBJECT),
        ASN1_IMP_SEQUENCE_OF_OPT(X509_CERT_AUX, reject, ASN1_OBJECT, 0),
        ASN1_OPT(X509_CERT_AUX, alias, ASN1_UTF8STRING),
        ASN1_OPT(X509_CERT_AUX, keyid, ASN1_OCTET_STRING),
        ASN1_IMP_SEQUENCE_OF_OPT(X509_CERT_AUX, other, X509_ALGOR, 1)
} ASN1_SEQUENCE_END(X509_CERT_AUX)

IMPLEMENT_ASN1_FUNCTIONS(X509_CERT_AUX)

int X509_trusted(const X509 *x)
{
    return x->aux ? 1 : 0;
}

static X509_CERT_AUX *aux_get(X509 *x)
{
    if (x == NULL)
        return NULL;
    if (x->aux == NULL && (x->aux = X509_CERT_AUX_new()) == NULL)
        return NULL;
    return x->aux;
}

int X509_alias_set1(X509 *x, const unsigned char *name, int len)
{
    X509_CERT_AUX *aux;
    if (!name) {
        if (!x || !x->aux || !x->aux->alias)
            return 1;
        ASN1_UTF8STRING_free(x->aux->alias);
        x->aux->alias = NULL;
        return 1;
    }
    if ((aux = aux_get(x)) == NULL)
        return 0;
    if (aux->alias == NULL && (aux->alias = ASN1_UTF8STRING_new()) == NULL)
        return 0;
    return ASN1_STRING_set(aux->alias, name, len);
}

int X509_keyid_set1(X509 *x, const unsigned char *id, int len)
{
    X509_CERT_AUX *aux;
    if (!id) {
        if (!x || !x->aux || !x->aux->keyid)
            return 1;
        ASN1_OCTET_STRING_free(x->aux->keyid);
        x->aux->keyid = NULL;
        return 1;
    }
    if ((aux = aux_get(x)) == NULL)
        return 0;
    if (aux->keyid == NULL
        && (aux->keyid = ASN1_OCTET_STRING_new()) == NULL)
        return 0;
    return ASN1_STRING_set(aux->keyid, id, len);
}

unsigned char *X509_alias_get0(X509 *x, int *len)
{
    if (!x->aux || !x->aux->alias)
        return NULL;
    if (len)
        *len = x->aux->alias->length;
    return x->aux->alias->data;
}

unsigned char *X509_keyid_get0(X509 *x, int *len)
{
    if (!x->aux || !x->aux->keyid)
        return NULL;
    if (len)
        *len = x->aux->keyid->length;
    return x->aux->keyid->data;
}

int X509_add1_trust_object(X509 *x, const ASN1_OBJECT *obj)
{
    X509_CERT_AUX *aux;
    ASN1_OBJECT *objtmp = NULL;
    if (obj) {
        objtmp = OBJ_dup(obj);
        if (!objtmp)
            return 0;
    }
    if ((aux = aux_get(x)) == NULL)
        goto err;
    if (aux->trust == NULL
        && (aux->trust = sk_ASN1_OBJECT_new_null()) == NULL)
        goto err;
    if (!objtmp || sk_ASN1_OBJECT_push(aux->trust, objtmp))
        return 1;
 err:
    ASN1_OBJECT_free(objtmp);
    return 0;
}

int X509_add1_reject_object(X509 *x, const ASN1_OBJECT *obj)
{
    X509_CERT_AUX *aux;
    ASN1_OBJECT *objtmp;
    int res = 0;

    if ((objtmp = OBJ_dup(obj)) == NULL)
        return 0;
    if ((aux = aux_get(x)) == NULL)
        goto err;
    if (aux->reject == NULL
        && (aux->reject = sk_ASN1_OBJECT_new_null()) == NULL)
        goto err;
    if (sk_ASN1_OBJECT_push(aux->reject, objtmp) > 0)
        res = 1;

 err:
    if (!res)
        ASN1_OBJECT_free(objtmp);
    return res;
}

void X509_trust_clear(X509 *x)
{
    if (x->aux) {
        sk_ASN1_OBJECT_pop_free(x->aux->trust, ASN1_OBJECT_free);
        x->aux->trust = NULL;
    }
}

void X509_reject_clear(X509 *x)
{
    if (x->aux) {
        sk_ASN1_OBJECT_pop_free(x->aux->reject, ASN1_OBJECT_free);
        x->aux->reject = NULL;
    }
}

STACK_OF(ASN1_OBJECT) *X509_get0_trust_objects(X509 *x)
{
    if (x->aux != NULL)
        return x->aux->trust;
    return NULL;
}

STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x)
{
    if (x->aux != NULL)
        return x->aux->reject;
    return NULL;
}

int X509_add1_other_algor(X509 *x, const X509_ALGOR *alg)
{
    X509_CERT_AUX *aux;
    X509_ALGOR *algtmp = NULL;

    if (alg != NULL) {
        algtmp = X509_ALGOR_dup(alg);
        if (!algtmp)
            return 0;
    }
    if ((aux = aux_get(x)) == NULL)
        goto err;
    if (aux->other == NULL
        && (aux->other = sk_X509_ALGOR_new_null()) == NULL)
        goto err;
    if (!algtmp || sk_X509_ALGOR_push(aux->other, algtmp))
        return 1;
 err:
    X509_ALGOR_free(algtmp);
    return 0;
}

void X509_other_clear(X509 *x)
{
    if (x->aux) {
        sk_X509_ALGOR_pop_free(x->aux->other, X509_ALGOR_free);
        x->aux->other = NULL;
    }
}

STACK_OF(X509_ALGOR) *X509_get0_other_algors(X509 *x)
{
    if (x->aux != NULL)
        return x->aux->other;
    return NULL;
}

/* this only returns first member with mathing nid */
X509_ALGOR *X509_get0_other_by_nid(X509 *x, int nid)
{
    int i;

    if (x->aux == NULL)
        return NULL;
    for (i = sk_X509_ALGOR_num(x->aux->other); i >= 0; i--) {
        /* search from top so we get newest one */
        X509_ALGOR *current = sk_X509_ALGOR_value(x->aux->other, i);

        if (current->algorithm != NULL && nid == OBJ_obj2nid(current->algorithm))
            return current;
    }
    return NULL;
}

/* remove every occerance of this nid in aux->other */
int X509_other_clear_nid(X509 *x, int nid)
{
    int i;
    X509_ALGOR *current;

    if (nid == NID_undef)
        return 0;
    if (x->aux == NULL)
        return 1;
    for (i = sk_X509_ALGOR_num(x->aux->other)-1; i >= 0; i--) {
        current = sk_X509_ALGOR_value(x->aux->other, i);
        if (current->algorithm != NULL && OBJ_obj2nid(current->algorithm) == nid)
            sk_X509_ALGOR_delete_ptr(x->aux->other, current);
    }
    return 1;
}

int X509_set0_aux_distrustafterdate(X509 *x, ASN1_GENERALIZEDTIME *time)
{
    X509_ALGOR *dtaft = X509_ALGOR_new();

    if (dtaft == NULL)
        return 0;
    X509_other_clear_nid(x, NID_openssl_distrustafter);
    X509_ALGOR_set0(dtaft, OBJ_nid2obj(NID_openssl_distrustafter), V_ASN1_GENERALIZEDTIME, time);
    X509_add1_other_algor(x, dtaft);
    X509_ALGOR_free(dtaft);
    return 1;
}

ASN1_TIME *X509_get0_aux_distrustafterdate(X509 *x)
{
    X509_ALGOR *alg = X509_get0_other_by_nid(x, NID_openssl_distrustafter);

    if (alg == NULL)
        return NULL;
    if (ASN1_TYPE_get(alg->parameter) != V_ASN1_GENERALIZEDTIME)
        return NULL;
    return alg->parameter->value.generalizedtime;
}
