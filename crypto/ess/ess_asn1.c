/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/cms.h>
#include <openssl/ess.h>
#include <openssl/x509v3.h>
#include "crypto/ess.h"
#include "crypto/cms.h"

/* ASN1 stuff for ESS Structure */

ASN1_SEQUENCE(ESS_ISSUER_SERIAL) = {
        ASN1_SEQUENCE_OF(ESS_ISSUER_SERIAL, issuer, GENERAL_NAME),
        ASN1_SIMPLE(ESS_ISSUER_SERIAL, serial, ASN1_INTEGER)
} static_ASN1_SEQUENCE_END(ESS_ISSUER_SERIAL)

IMPLEMENT_ASN1_FUNCTIONS(ESS_ISSUER_SERIAL)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_ISSUER_SERIAL)

ASN1_SEQUENCE(ESS_CERT_ID) = {
        ASN1_SIMPLE(ESS_CERT_ID, hash, ASN1_OCTET_STRING),
        ASN1_OPT(ESS_CERT_ID, issuer_serial, ESS_ISSUER_SERIAL)
} static_ASN1_SEQUENCE_END(ESS_CERT_ID)

IMPLEMENT_ASN1_FUNCTIONS(ESS_CERT_ID)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_CERT_ID)

ASN1_SEQUENCE(ESS_SIGNING_CERT) = {
        ASN1_SEQUENCE_OF(ESS_SIGNING_CERT, cert_ids, ESS_CERT_ID),
        ASN1_SEQUENCE_OF_OPT(ESS_SIGNING_CERT, policy_info, POLICYINFO)
} static_ASN1_SEQUENCE_END(ESS_SIGNING_CERT)

IMPLEMENT_ASN1_FUNCTIONS(ESS_SIGNING_CERT)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_SIGNING_CERT)

ASN1_SEQUENCE(ESS_CERT_ID_V2) = {
        ASN1_OPT(ESS_CERT_ID_V2, hash_alg, X509_ALGOR),
        ASN1_SIMPLE(ESS_CERT_ID_V2, hash, ASN1_OCTET_STRING),
        ASN1_OPT(ESS_CERT_ID_V2, issuer_serial, ESS_ISSUER_SERIAL)
} static_ASN1_SEQUENCE_END(ESS_CERT_ID_V2)

IMPLEMENT_ASN1_FUNCTIONS(ESS_CERT_ID_V2)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_CERT_ID_V2)

ASN1_SEQUENCE(ESS_SIGNING_CERT_V2) = {
        ASN1_SEQUENCE_OF(ESS_SIGNING_CERT_V2, cert_ids, ESS_CERT_ID_V2),
        ASN1_SEQUENCE_OF_OPT(ESS_SIGNING_CERT_V2, policy_info, POLICYINFO)
} static_ASN1_SEQUENCE_END(ESS_SIGNING_CERT_V2)

IMPLEMENT_ASN1_FUNCTIONS(ESS_SIGNING_CERT_V2)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_SIGNING_CERT_V2)

/* No cms support means no CMS_SignerInfo* definitions */
#ifndef OPENSSL_NO_CMS

/*
 * Returns < 0 if attribute is not found, 1 if found, or 
 * -1 on attribute parsing failure.
 */
int cms_signerinfo_get_signing_cert_v2(CMS_SignerInfo *si,
                                       ESS_SIGNING_CERT_V2 **psc)
{
    ASN1_STRING *str;
    ESS_SIGNING_CERT_V2 *sc;
    ASN1_OBJECT *obj = OBJ_nid2obj(NID_id_smime_aa_signingCertificateV2);

    if (psc != NULL)
        *psc = NULL;
    str = CMS_signed_get0_data_by_OBJ(si, obj, -3, V_ASN1_SEQUENCE);
    if (str == NULL)
        return 0;

    sc = ASN1_item_unpack(str, ASN1_ITEM_rptr(ESS_SIGNING_CERT_V2));
    if (sc == NULL)
        return -1;
    if (psc != NULL)
        *psc = sc;
    else
        ESS_SIGNING_CERT_V2_free(sc);
    return 1;
}

/*
 * Returns < 0 if attribute is not found, 1 if found, or 
 * -1 on attribute parsing failure.
 */
int cms_signerinfo_get_signing_cert(CMS_SignerInfo *si,
                                    ESS_SIGNING_CERT **psc)
{
    ASN1_STRING *str;
    ESS_SIGNING_CERT *sc;
    ASN1_OBJECT *obj = OBJ_nid2obj(NID_id_smime_aa_signingCertificate);

    if (psc != NULL)
        *psc = NULL;
    str = CMS_signed_get0_data_by_OBJ(si, obj, -3, V_ASN1_SEQUENCE);
    if (str == NULL)
        return 0;

    sc = ASN1_item_unpack(str, ASN1_ITEM_rptr(ESS_SIGNING_CERT));
    if (sc == NULL)
        return -1;
    if (psc != NULL)
        *psc = sc;
    else
        ESS_SIGNING_CERT_free(sc);
    return 1;
}
#endif  /* !OPENSSL_NO_CMS */
