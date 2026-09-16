/*
 * Copyright 2000-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "x509_local.h"

#include <crypto/asn1.h>

static void free_decoded(X509_EXTENSION *ex)
{
    if (ex->decoded == NULL)
        return;
    if (ex->method->it != NULL)
        ASN1_item_free(ex->decoded, ASN1_ITEM_ptr(ex->method->it));
    else
        ex->method->ext_free(ex->decoded);
    ex->decoded = NULL;
}

int ossl_x509_extension_decode_value(X509_EXTENSION *ex)
{
    const unsigned char *p = ex->value.data;

    free_decoded(ex);
    ex->method = X509V3_EXT_get(ex);
    if (ex->method == NULL) {
        ex->outcome = ex->critical ? X509_EXT_VALUE_UNKNOWN_CRITICAL
                                   : X509_EXT_VALUE_UNKNOWN;
        return 1;
    }
    ERR_set_mark();
    if (ex->method->it != NULL)
        ex->decoded = ASN1_item_d2i(NULL, &p, ex->value.length,
            ASN1_ITEM_ptr(ex->method->it));
    else
        ex->decoded = ex->method->d2i(NULL, &p, ex->value.length);
    if (ex->decoded != NULL) {
        ex->outcome = X509_EXT_VALUE_DECODED;
        ERR_clear_last_mark();
        return 1;
    }
    /*
     * The errors raised by the decode say why it failed. An allocation
     * failure is reported as ERR_R_MALLOC_FAILURE; any other error is the
     * decoder rejecting the value. A decoder that fails without raising
     * anything (including one that could not allocate the error state to
     * report with) gives no reason, and is treated as an internal failure.
     * The value's own errors are of no further use and are discarded.
     */
    if (ERR_count_to_mark() == 0)
        ex->outcome = X509_EXT_VALUE_ERROR;
    else
        ex->outcome = ex->critical ? X509_EXT_VALUE_INVALID_CRITICAL
                                   : X509_EXT_VALUE_INVALID;
    while (ERR_count_to_mark() > 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == ERR_R_MALLOC_FAILURE)
            ex->outcome = X509_EXT_VALUE_MALLOC_FAILED;
        ERR_pop();
    }
    ERR_clear_last_mark();
    switch (ex->outcome) {
    case X509_EXT_VALUE_MALLOC_FAILED:
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        return 0;
    case X509_EXT_VALUE_ERROR:
        ERR_raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR);
        return 0;
    default:
        return 1;
    }
}

static int ext_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
    void *exarg)
{
    X509_EXTENSION *ex = (X509_EXTENSION *)*pval;

    switch (operation) {
    case ASN1_OP_NEW_POST:
        ex->outcome = X509_EXT_VALUE_UNKNOWN;
        break;

    case ASN1_OP_D2I_POST:
        return ossl_x509_extension_decode_value(ex);

    case ASN1_OP_FREE_POST:
        free_decoded(ex);
        break;

    default:
        break;
    }
    return 1;
}

ASN1_SEQUENCE_cb(X509_EXTENSION, ext_cb) = {
    ASN1_SIMPLE(X509_EXTENSION, object, ASN1_OBJECT),
    ASN1_OPT(X509_EXTENSION, critical, ASN1_FBOOLEAN),
    ASN1_EMBED(X509_EXTENSION, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_cb(X509_EXTENSION, X509_EXTENSION)

ASN1_ITEM_TEMPLATE(X509_EXTENSIONS) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Extension, X509_EXTENSION)
ASN1_ITEM_TEMPLATE_END(X509_EXTENSIONS)

IMPLEMENT_ASN1_FUNCTIONS(X509_EXTENSION)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_EXTENSION)
