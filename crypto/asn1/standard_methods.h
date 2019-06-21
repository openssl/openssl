/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <oqs/oqs.h>

/*
 * This table MUST be kept in ascending order of the NID each method
 * represents (corresponding to the pkey_id field) as OBJ_bsearch
 * is used to search it.
 */
static const EVP_PKEY_ASN1_METHOD *standard_methods[] = {
#ifndef OPENSSL_NO_RSA
    &rsa_asn1_meths[0],
    &rsa_asn1_meths[1],
#endif
#ifndef OPENSSL_NO_DH
    &dh_asn1_meth,
#endif
#ifndef OPENSSL_NO_DSA
    &dsa_asn1_meths[0],
    &dsa_asn1_meths[1],
    &dsa_asn1_meths[2],
    &dsa_asn1_meths[3],
    &dsa_asn1_meths[4],
#endif
#ifndef OPENSSL_NO_EC
    &eckey_asn1_meth,
#endif
    &hmac_asn1_meth,
#ifndef OPENSSL_NO_CMAC
    &cmac_asn1_meth,
#endif
#ifndef OPENSSL_NO_RSA
    &rsa_pss_asn1_meth,
#endif
#ifndef OPENSSL_NO_DH
    &dhx_asn1_meth,
#endif
#ifndef OPENSSL_NO_EC
    &ecx25519_asn1_meth,
    &ecx448_asn1_meth,
#endif
#ifndef OPENSSL_NO_POLY1305
    &poly1305_asn1_meth,
#endif
#ifndef OPENSSL_NO_SIPHASH
    &siphash_asn1_meth,
#endif
#ifndef OPENSSL_NO_EC
    &ed25519_asn1_meth,
    &ed448_asn1_meth,
#endif
#ifndef OPENSSL_NO_SM2
    &sm2_asn1_meth,
#endif
#if !defined(OQS_NIST_BRANCH)
    /* OQS sig schemes (list in NID order!) */
    /* ADD_MORE_OQS_SIG_HERE */
    &picnicL1FS_asn1_meth,
    &p256_picnicL1FS_asn1_meth,
    &rsa3072_picnicL1FS_asn1_meth,
    &qteslaI_asn1_meth,
    &p256_qteslaI_asn1_meth,
    &rsa3072_qteslaI_asn1_meth,
    &qteslaIIIsize_asn1_meth,
    &p384_qteslaIIIsize_asn1_meth,
    &qteslaIIIspeed_asn1_meth,
    &p384_qteslaIIIspeed_asn1_meth,
    &dilithium2_asn1_meth,
    &dilithium3_asn1_meth,
    &dilithium4_asn1_meth,
#endif
};
