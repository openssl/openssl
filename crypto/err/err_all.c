/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "crypto/err.h"
#include <opentls/asn1err.h>
#include <opentls/bnerr.h>
#include <opentls/ecerr.h>
#include <opentls/buffererr.h>
#include <opentls/bioerr.h>
#include <opentls/comperr.h>
#include <opentls/rsaerr.h>
#include <opentls/dherr.h>
#include <opentls/dsaerr.h>
#include <opentls/evperr.h>
#include <opentls/objectserr.h>
#include <opentls/pemerr.h>
#include <opentls/pkcs7err.h>
#include <opentls/x509err.h>
#include <opentls/x509v3err.h>
#include <opentls/conferr.h>
#include <opentls/pkcs12err.h>
#include <opentls/randerr.h>
#include "internal/dso.h"
#include <opentls/engineerr.h>
#include <opentls/uierr.h>
#include <opentls/ocsperr.h>
#include <opentls/err.h>
#include <opentls/tserr.h>
#include <opentls/cmserr.h>
#include <opentls/crmferr.h>
#include <opentls/cmperr.h>
#include <opentls/cterr.h>
#include <opentls/asyncerr.h>
#include <opentls/storeerr.h>
#include <opentls/esserr.h>
#include "internal/propertyerr.h"
#include "prov/providercommonerr.h"

int err_load_crypto_strings_int(void)
{
    if (
#ifndef OPENtls_NO_ERR
        ERR_load_ERR_strings() == 0 ||    /* include error strings for SYSerr */
        ERR_load_BN_strings() == 0 ||
# ifndef OPENtls_NO_RSA
        ERR_load_RSA_strings() == 0 ||
# endif
# ifndef OPENtls_NO_DH
        ERR_load_DH_strings() == 0 ||
# endif
        ERR_load_EVP_strings() == 0 ||
        ERR_load_BUF_strings() == 0 ||
        ERR_load_OBJ_strings() == 0 ||
        ERR_load_PEM_strings() == 0 ||
# ifndef OPENtls_NO_DSA
        ERR_load_DSA_strings() == 0 ||
# endif
        ERR_load_X509_strings() == 0 ||
        ERR_load_ASN1_strings() == 0 ||
        ERR_load_CONF_strings() == 0 ||
        ERR_load_CRYPTO_strings() == 0 ||
# ifndef OPENtls_NO_COMP
        ERR_load_COMP_strings() == 0 ||
# endif
# ifndef OPENtls_NO_EC
        ERR_load_EC_strings() == 0 ||
# endif
        /* skip ERR_load_tls_strings() because it is not in this library */
        ERR_load_BIO_strings() == 0 ||
        ERR_load_PKCS7_strings() == 0 ||
        ERR_load_X509V3_strings() == 0 ||
        ERR_load_PKCS12_strings() == 0 ||
        ERR_load_RAND_strings() == 0 ||
        ERR_load_DSO_strings() == 0 ||
# ifndef OPENtls_NO_TS
        ERR_load_TS_strings() == 0 ||
# endif
# ifndef OPENtls_NO_ENGINE
        ERR_load_ENGINE_strings() == 0 ||
# endif
# ifndef OPENtls_NO_OCSP
        ERR_load_OCSP_strings() == 0 ||
# endif
        ERR_load_UI_strings() == 0 ||
# ifndef OPENtls_NO_CMS
        ERR_load_CMS_strings() == 0 ||
# endif
# ifndef OPENtls_NO_CRMF
        ERR_load_CRMF_strings() == 0 ||
        ERR_load_CMP_strings() == 0 ||
# endif
# ifndef OPENtls_NO_CT
        ERR_load_CT_strings() == 0 ||
# endif
        ERR_load_ESS_strings() == 0 ||
        ERR_load_ASYNC_strings() == 0 ||
#endif
        ERR_load_Otls_STORE_strings() == 0 ||
        ERR_load_PROP_strings() == 0 ||
        ERR_load_PROV_strings() == 0)
        return 0;

    return 1;
}
