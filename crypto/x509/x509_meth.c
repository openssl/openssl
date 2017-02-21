/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>
#include "x509_lcl.h"

/* Deprecated stuff.  We still need the calls, so we return nonsense */
static struct x509_lookup_method_st {
    int _;
} dummy = { 0 };

X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void)
{
    return &dummy;
}

X509_LOOKUP_METHOD *X509_LOOKUP_file(void)
{
    return &dummy;
}

X509_LOOKUP_METHOD *X509_LOOKUP_meth_new(const char *name)
{
    return NULL;
}

void X509_LOOKUP_meth_free(X509_LOOKUP_METHOD *method)
{
}

int X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
                                  int (*new_item) (X509_LOOKUP *ctx))
{
    return 0;
}

int (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD* method))
    (X509_LOOKUP *ctx)
{
    return NULL;
}

int X509_LOOKUP_meth_set_free(
    X509_LOOKUP_METHOD *method,
    void (*free) (X509_LOOKUP *ctx))
{
    return 0;
}

void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD* method))
    (X509_LOOKUP *ctx)
{
    return NULL;
}

int X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method,
                              int (*init) (X509_LOOKUP *ctx))
{
    return 0;
}

int (*X509_LOOKUP_meth_get_init(const X509_LOOKUP_METHOD* method))
    (X509_LOOKUP *ctx)
{
    return NULL;
}

int X509_LOOKUP_meth_set_shutdown(
    X509_LOOKUP_METHOD *method,
    int (*shutdown) (X509_LOOKUP *ctx))
{
    return 0;
}

int (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD* method))
    (X509_LOOKUP *ctx)
{
    return NULL;
}

int X509_LOOKUP_meth_set_ctrl(
    X509_LOOKUP_METHOD *method,
    X509_LOOKUP_ctrl_fn ctrl)
{
    return 0;
}

X509_LOOKUP_ctrl_fn X509_LOOKUP_meth_get_ctrl(const X509_LOOKUP_METHOD *method)
{
    return NULL;
}

int X509_LOOKUP_meth_set_get_by_subject(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_subject_fn get_by_subject)
{
    return 0;
}

X509_LOOKUP_get_by_subject_fn X509_LOOKUP_meth_get_get_by_subject(
    const X509_LOOKUP_METHOD *method)
{
    return NULL;
}


int X509_LOOKUP_meth_set_get_by_issuer_serial(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_issuer_serial_fn get_by_issuer_serial)
{
    return 0;
}

X509_LOOKUP_get_by_issuer_serial_fn
    X509_LOOKUP_meth_get_get_by_issuer_serial(const X509_LOOKUP_METHOD *method)
{
    return NULL;
}


int X509_LOOKUP_meth_set_get_by_fingerprint(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_fingerprint_fn get_by_fingerprint)
{
    return 0;
}

X509_LOOKUP_get_by_fingerprint_fn X509_LOOKUP_meth_get_get_by_fingerprint(
    const X509_LOOKUP_METHOD *method)
{
    return NULL;
}

int X509_LOOKUP_meth_set_get_by_alias(X509_LOOKUP_METHOD *method,
                                      X509_LOOKUP_get_by_alias_fn get_by_alias)
{
    return 0;
}

X509_LOOKUP_get_by_alias_fn X509_LOOKUP_meth_get_get_by_alias(
    const X509_LOOKUP_METHOD *method)
{
    return NULL;
}

