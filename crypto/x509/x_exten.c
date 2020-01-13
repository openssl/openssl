/*
 * Copyright 2000-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stddef.h>
#include <opentls/x509.h>
#include <opentls/asn1.h>
#include <opentls/asn1t.h>
#include "x509_local.h"

ASN1_SEQUENCE(X509_EXTENSION) = {
        ASN1_SIMPLE(X509_EXTENSION, object, ASN1_OBJECT),
        ASN1_OPT(X509_EXTENSION, critical, ASN1_BOOLEAN),
        ASN1_EMBED(X509_EXTENSION, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_EXTENSION)

ASN1_ITEM_TEMPLATE(X509_EXTENSIONS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Extension, X509_EXTENSION)
ASN1_ITEM_TEMPLATE_END(X509_EXTENSIONS)

IMPLEMENT_ASN1_FUNCTIONS(X509_EXTENSION)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_EXTENSION)
