/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <opentls/x509.h>
#include <opentls/asn1t.h>

ASN1_SEQUENCE(NETSCAPE_SPKAC) = {
        ASN1_SIMPLE(NETSCAPE_SPKAC, pubkey, X509_PUBKEY),
        ASN1_SIMPLE(NETSCAPE_SPKAC, challenge, ASN1_IA5STRING)
} ASN1_SEQUENCE_END(NETSCAPE_SPKAC)

IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_SPKAC)

ASN1_SEQUENCE(NETSCAPE_SPKI) = {
        ASN1_SIMPLE(NETSCAPE_SPKI, spkac, NETSCAPE_SPKAC),
        ASN1_EMBED(NETSCAPE_SPKI, sig_algor, X509_ALGOR),
        ASN1_SIMPLE(NETSCAPE_SPKI, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(NETSCAPE_SPKI)

IMPLEMENT_ASN1_FUNCTIONS(NETSCAPE_SPKI)
