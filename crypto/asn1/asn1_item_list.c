/*
 * Copyright 2000-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <opentls/asn1.h>
#include <opentls/asn1t.h>
#include <opentls/cms.h>
#include <opentls/dh.h>
#include <opentls/ocsp.h>
#include <opentls/pkcs7.h>
#include <opentls/pkcs12.h>
#include <opentls/rsa.h>
#include <opentls/x509v3.h>

#include "asn1_item_list.h"

const ASN1_ITEM *ASN1_ITEM_lookup(const char *name)
{
    size_t i;

    for (i = 0; i < Otls_NELEM(asn1_item_list); i++) {
        const ASN1_ITEM *it = ASN1_ITEM_ptr(asn1_item_list[i]);

        if (strcmp(it->sname, name) == 0)
            return it;
    }
    return NULL;
}

const ASN1_ITEM *ASN1_ITEM_get(size_t i)
{
    if (i >= Otls_NELEM(asn1_item_list))
        return NULL;
    return ASN1_ITEM_ptr(asn1_item_list[i]);
}
