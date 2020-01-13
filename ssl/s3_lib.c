/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <opentls/objects.h>
#include "internal/nelem.h"
#include "tls_local.h"
#include <opentls/md5.h>
#include <opentls/dh.h>
#include <opentls/rand.h>
#include <opentls/trace.h>
#include "internal/cryptlib.h"

#define TLS13_NUM_CIPHERS       Otls_NELEM(tls13_ciphers)
#define tls3_NUM_CIPHERS        Otls_NELEM(tls3_ciphers)
#define tls3_NUM_SCSVS          Otls_NELEM(tls3_scsvs)

/* TLSv1.3 downgrade protection sentinel values */
const unsigned char tls11downgrade[] = {
    0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00
};
const unsigned char tls12downgrade[] = {
    0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01
};

/* The list of available TLSv1.3 ciphers */
static tls_CIPHER tls13_ciphers[] = {
    {
        1,
        TLS1_3_RFC_AES_128_GCM_SHA256,
        TLS1_3_RFC_AES_128_GCM_SHA256,
        TLS1_3_CK_AES_128_GCM_SHA256,
        tls_kANY,
        tls_aANY,
        tls_AES128GCM,
        tls_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        tls_HIGH,
        tls_HANDSHAKE_MAC_SHA256,
        128,
        128,
    }, {
        1,
        TLS1_3_RFC_AES_256_GCM_SHA384,
        TLS1_3_RFC_AES_256_GCM_SHA384,
        TLS1_3_CK_AES_256_GCM_SHA384,
        tls_kANY,
        tls_aANY,
        tls_AES256GCM,
        tls_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        tls_HIGH,
        tls_HANDSHAKE_MAC_SHA384,
        256,
        256,
    },
#if !defined(OPENtls_NO_CHACHA) && !defined(OPENtls_NO_POLY1305)
    {
        1,
        TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        TLS1_3_CK_CHACHA20_POLY1305_SHA256,
        tls_kANY,
        tls_aANY,
        tls_CHACHA20POLY1305,
        tls_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        tls_HIGH,
        tls_HANDSHAKE_MAC_SHA256,
        256,
        256,
    },
#endif
    {
        1,
        TLS1_3_RFC_AES_128_CCM_SHA256,
        TLS1_3_RFC_AES_128_CCM_SHA256,
        TLS1_3_CK_AES_128_CCM_SHA256,
        tls_kANY,
        tls_aANY,
        tls_AES128CCM,
        tls_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        tls_NOT_DEFAULT | tls_HIGH,
        tls_HANDSHAKE_MAC_SHA256,
        128,
        128,
    }, {
        1,
        TLS1_3_RFC_AES_128_CCM_8_SHA256,
        TLS1_3_RFC_AES_128_CCM_8_SHA256,
        TLS1_3_CK_AES_128_CCM_8_SHA256,
        tls_kANY,
        tls_aANY,
        tls_AES128CCM8,
        tls_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        tls_NOT_DEFAULT | tls_HIGH,
        tls_HANDSHAKE_MAC_SHA256,
        128,
        128,
    }
};

/*
 * The list of available ciphers, mostly organized into the following
 * groups:
 *      Always there
 *      EC
 *      PSK
 *      SRP (within that: RSA EC PSK)
 *      Cipher families: Chacha/poly, Camellia, Gost, IDEA, SEED
 *      Weak ciphers
 */
static tls_CIPHER tls3_ciphers[] = {
    {
     1,
     tls3_TXT_RSA_NULL_MD5,
     tls3_RFC_RSA_NULL_MD5,
     tls3_CK_RSA_NULL_MD5,
     tls_kRSA,
     tls_aRSA,
     tls_eNULL,
     tls_MD5,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     tls3_TXT_RSA_NULL_SHA,
     tls3_RFC_RSA_NULL_SHA,
     tls3_CK_RSA_NULL_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_eNULL,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
#ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     tls3_TXT_RSA_DES_192_CBC3_SHA,
     tls3_RFC_RSA_DES_192_CBC3_SHA,
     tls3_CK_RSA_DES_192_CBC3_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     tls3_TXT_DHE_DSS_DES_192_CBC3_SHA,
     tls3_RFC_DHE_DSS_DES_192_CBC3_SHA,
     tls3_CK_DHE_DSS_DES_192_CBC3_SHA,
     tls_kDHE,
     tls_aDSS,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     tls3_TXT_DHE_RSA_DES_192_CBC3_SHA,
     tls3_RFC_DHE_RSA_DES_192_CBC3_SHA,
     tls3_CK_DHE_RSA_DES_192_CBC3_SHA,
     tls_kDHE,
     tls_aRSA,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     tls3_TXT_ADH_DES_192_CBC_SHA,
     tls3_RFC_ADH_DES_192_CBC_SHA,
     tls3_CK_ADH_DES_192_CBC_SHA,
     tls_kDHE,
     tls_aNULL,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
#endif
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA,
     TLS1_RFC_RSA_WITH_AES_128_SHA,
     TLS1_CK_RSA_WITH_AES_128_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
     TLS1_RFC_DHE_DSS_WITH_AES_128_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
     tls_kDHE,
     tls_aDSS,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
     TLS1_RFC_DHE_RSA_WITH_AES_128_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
     tls_kDHE,
     tls_aRSA,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA,
     TLS1_RFC_ADH_WITH_AES_128_SHA,
     TLS1_CK_ADH_WITH_AES_128_SHA,
     tls_kDHE,
     tls_aNULL,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA,
     TLS1_RFC_RSA_WITH_AES_256_SHA,
     TLS1_CK_RSA_WITH_AES_256_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
     TLS1_RFC_DHE_DSS_WITH_AES_256_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
     tls_kDHE,
     tls_aDSS,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
     TLS1_RFC_DHE_RSA_WITH_AES_256_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
     tls_kDHE,
     tls_aRSA,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA,
     TLS1_RFC_ADH_WITH_AES_256_SHA,
     TLS1_CK_ADH_WITH_AES_256_SHA,
     tls_kDHE,
     tls_aNULL,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_NULL_SHA256,
     TLS1_RFC_RSA_WITH_NULL_SHA256,
     TLS1_CK_RSA_WITH_NULL_SHA256,
     tls_kRSA,
     tls_aRSA,
     tls_eNULL,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA256,
     TLS1_RFC_RSA_WITH_AES_128_SHA256,
     TLS1_CK_RSA_WITH_AES_128_SHA256,
     tls_kRSA,
     tls_aRSA,
     tls_AES128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA256,
     TLS1_RFC_RSA_WITH_AES_256_SHA256,
     TLS1_CK_RSA_WITH_AES_256_SHA256,
     tls_kRSA,
     tls_aRSA,
     tls_AES256,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256,
     TLS1_RFC_DHE_DSS_WITH_AES_128_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA256,
     tls_kDHE,
     tls_aDSS,
     tls_AES128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
     TLS1_RFC_DHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA256,
     tls_kDHE,
     tls_aRSA,
     tls_AES128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256,
     TLS1_RFC_DHE_DSS_WITH_AES_256_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA256,
     tls_kDHE,
     tls_aDSS,
     tls_AES256,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
     TLS1_RFC_DHE_RSA_WITH_AES_256_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA256,
     tls_kDHE,
     tls_aRSA,
     tls_AES256,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA256,
     TLS1_RFC_ADH_WITH_AES_128_SHA256,
     TLS1_CK_ADH_WITH_AES_128_SHA256,
     tls_kDHE,
     tls_aNULL,
     tls_AES128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA256,
     TLS1_RFC_ADH_WITH_AES_256_SHA256,
     TLS1_CK_ADH_WITH_AES_256_SHA256,
     tls_kDHE,
     tls_aNULL,
     tls_AES256,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_WITH_AES_128_GCM_SHA256,
     tls_kRSA,
     tls_aRSA,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_WITH_AES_256_GCM_SHA384,
     tls_kRSA,
     tls_aRSA,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_DHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
     tls_kDHE,
     tls_aRSA,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_DHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
     tls_kDHE,
     tls_aRSA,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_DHE_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256,
     tls_kDHE,
     tls_aDSS,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_DHE_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384,
     tls_kDHE,
     tls_aDSS,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_ADH_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ADH_WITH_AES_128_GCM_SHA256,
     tls_kDHE,
     tls_aNULL,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_ADH_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ADH_WITH_AES_256_GCM_SHA384,
     tls_kDHE,
     tls_aNULL,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_CCM,
     TLS1_RFC_RSA_WITH_AES_128_CCM,
     TLS1_CK_RSA_WITH_AES_128_CCM,
     tls_kRSA,
     tls_aRSA,
     tls_AES128CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_CCM,
     TLS1_RFC_RSA_WITH_AES_256_CCM,
     TLS1_CK_RSA_WITH_AES_256_CCM,
     tls_kRSA,
     tls_aRSA,
     tls_AES256CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_CCM,
     TLS1_RFC_DHE_RSA_WITH_AES_128_CCM,
     TLS1_CK_DHE_RSA_WITH_AES_128_CCM,
     tls_kDHE,
     tls_aRSA,
     tls_AES128CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_CCM,
     TLS1_RFC_DHE_RSA_WITH_AES_256_CCM,
     TLS1_CK_DHE_RSA_WITH_AES_256_CCM,
     tls_kDHE,
     tls_aRSA,
     tls_AES256CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_CCM_8,
     TLS1_RFC_RSA_WITH_AES_128_CCM_8,
     TLS1_CK_RSA_WITH_AES_128_CCM_8,
     tls_kRSA,
     tls_aRSA,
     tls_AES128CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_CCM_8,
     TLS1_RFC_RSA_WITH_AES_256_CCM_8,
     TLS1_CK_RSA_WITH_AES_256_CCM_8,
     tls_kRSA,
     tls_aRSA,
     tls_AES256CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8,
     TLS1_RFC_DHE_RSA_WITH_AES_128_CCM_8,
     TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8,
     tls_kDHE,
     tls_aRSA,
     tls_AES128CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8,
     TLS1_RFC_DHE_RSA_WITH_AES_256_CCM_8,
     TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8,
     tls_kDHE,
     tls_aRSA,
     tls_AES256CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CCM,
     TLS1_RFC_PSK_WITH_AES_128_CCM,
     TLS1_CK_PSK_WITH_AES_128_CCM,
     tls_kPSK,
     tls_aPSK,
     tls_AES128CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CCM,
     TLS1_RFC_PSK_WITH_AES_256_CCM,
     TLS1_CK_PSK_WITH_AES_256_CCM,
     tls_kPSK,
     tls_aPSK,
     tls_AES256CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CCM,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CCM,
     TLS1_CK_DHE_PSK_WITH_AES_128_CCM,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES128CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CCM,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CCM,
     TLS1_CK_DHE_PSK_WITH_AES_256_CCM,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES256CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CCM_8,
     TLS1_RFC_PSK_WITH_AES_128_CCM_8,
     TLS1_CK_PSK_WITH_AES_128_CCM_8,
     tls_kPSK,
     tls_aPSK,
     tls_AES128CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CCM_8,
     TLS1_RFC_PSK_WITH_AES_256_CCM_8,
     TLS1_CK_PSK_WITH_AES_256_CCM_8,
     tls_kPSK,
     tls_aPSK,
     tls_AES256CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CCM_8,
     TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES128CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CCM_8,
     TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES256CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES128CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES256CCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES128CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES256CCM8,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
     tls_kECDHE,
     tls_aECDSA,
     tls_eNULL,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     tls_kECDHE,
     tls_aECDSA,
     tls_3DES,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES128,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES256,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
     tls_kECDHE,
     tls_aRSA,
     tls_eNULL,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     tls_kECDHE,
     tls_aRSA,
     tls_3DES,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     tls_kECDHE,
     tls_aRSA,
     tls_AES128,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     tls_kECDHE,
     tls_aRSA,
     tls_AES256,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
     TLS1_RFC_ECDH_anon_WITH_NULL_SHA,
     TLS1_CK_ECDH_anon_WITH_NULL_SHA,
     tls_kECDHE,
     tls_aNULL,
     tls_eNULL,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA,
     TLS1_RFC_ECDH_anon_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA,
     tls_kECDHE,
     tls_aNULL,
     tls_3DES,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
     TLS1_RFC_ECDH_anon_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA,
     tls_kECDHE,
     tls_aNULL,
     tls_AES128,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
     TLS1_RFC_ECDH_anon_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA,
     tls_kECDHE,
     tls_aNULL,
     tls_AES256,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES256,
     tls_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
     TLS1_RFC_ECDHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
     tls_kECDHE,
     tls_aRSA,
     tls_AES128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
     TLS1_RFC_ECDHE_RSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
     tls_kECDHE,
     tls_aRSA,
     tls_AES256,
     tls_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     tls_kECDHE,
     tls_aECDSA,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     tls_kECDHE,
     tls_aRSA,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     tls_kECDHE,
     tls_aRSA,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA,
     TLS1_RFC_PSK_WITH_NULL_SHA,
     TLS1_CK_PSK_WITH_NULL_SHA,
     tls_kPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA,
     TLS1_RFC_DHE_PSK_WITH_NULL_SHA,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA,
     tls_kDHEPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA,
     TLS1_RFC_RSA_PSK_WITH_NULL_SHA,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA,
     tls_kRSAPSK,
     tls_aRSA,
     tls_eNULL,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA,
     tls_kPSK,
     tls_aPSK,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CBC_SHA,
     TLS1_RFC_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_128_CBC_SHA,
     tls_kPSK,
     tls_aPSK,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CBC_SHA,
     TLS1_RFC_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_256_CBC_SHA,
     tls_kPSK,
     tls_aPSK,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
# ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
     tls_kDHEPSK,
     tls_aPSK,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
# ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
     tls_kRSAPSK,
     tls_aRSA,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA,
     TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA,
     tls_kRSAPSK,
     tls_aRSA,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA,
     TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA,
     tls_kRSAPSK,
     tls_aRSA,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_PSK_WITH_AES_128_GCM_SHA256,
     tls_kPSK,
     tls_aPSK,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_PSK_WITH_AES_256_GCM_SHA384,
     tls_kPSK,
     tls_aPSK,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_DHE_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_DHE_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_RSA_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256,
     tls_kRSAPSK,
     tls_aRSA,
     tls_AES128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_RSA_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384,
     tls_kRSAPSK,
     tls_aRSA,
     tls_AES256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_RFC_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_PSK_WITH_AES_128_CBC_SHA256,
     tls_kPSK,
     tls_aPSK,
     tls_AES128,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_RFC_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_PSK_WITH_AES_256_CBC_SHA384,
     tls_kPSK,
     tls_aPSK,
     tls_AES256,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA256,
     TLS1_RFC_PSK_WITH_NULL_SHA256,
     TLS1_CK_PSK_WITH_NULL_SHA256,
     tls_kPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA384,
     TLS1_RFC_PSK_WITH_NULL_SHA384,
     TLS1_CK_PSK_WITH_NULL_SHA384,
     tls_kPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES128,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384,
     tls_kDHEPSK,
     tls_aPSK,
     tls_AES256,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA256,
     TLS1_RFC_DHE_PSK_WITH_NULL_SHA256,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA256,
     tls_kDHEPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA384,
     TLS1_RFC_DHE_PSK_WITH_NULL_SHA384,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA384,
     tls_kDHEPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256,
     tls_kRSAPSK,
     tls_aRSA,
     tls_AES128,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384,
     tls_kRSAPSK,
     tls_aRSA,
     tls_AES256,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA256,
     TLS1_RFC_RSA_PSK_WITH_NULL_SHA256,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA256,
     tls_kRSAPSK,
     tls_aRSA,
     tls_eNULL,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA384,
     TLS1_RFC_RSA_PSK_WITH_NULL_SHA384,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA384,
     tls_kRSAPSK,
     tls_aRSA,
     tls_eNULL,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
#  ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_3DES,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
#  endif
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_AES128,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_AES256,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_AES128,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_AES256,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA256,
     TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA384,
     TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_eNULL,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_STRONG_NONE | tls_FIPS,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },

# ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     tls_kSRP,
     tls_aSRP,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     tls_kSRP,
     tls_aRSA,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     tls_kSRP,
     tls_aDSS,
     tls_3DES,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA,
     TLS1_RFC_SRP_SHA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA,
     tls_kSRP,
     tls_aSRP,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     TLS1_RFC_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     tls_kSRP,
     tls_aRSA,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     TLS1_RFC_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     tls_kSRP,
     tls_aDSS,
     tls_AES128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA,
     TLS1_RFC_SRP_SHA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA,
     tls_kSRP,
     tls_aSRP,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     TLS1_RFC_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     tls_kSRP,
     tls_aRSA,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     TLS1_RFC_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     tls_kSRP,
     tls_aDSS,
     tls_AES256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

#if !defined(OPENtls_NO_CHACHA) && !defined(OPENtls_NO_POLY1305)
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_RFC_DHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305,
     tls_kDHE,
     tls_aRSA,
     tls_CHACHA20POLY1305,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_RFC_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     tls_kECDHE,
     tls_aRSA,
     tls_CHACHA20POLY1305,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     TLS1_RFC_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     tls_kECDHE,
     tls_aECDSA,
     tls_CHACHA20POLY1305,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_CHACHA20_POLY1305,
     TLS1_RFC_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_PSK_WITH_CHACHA20_POLY1305,
     tls_kPSK,
     tls_aPSK,
     tls_CHACHA20POLY1305,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_RFC_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_CHACHA20POLY1305,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_RFC_DHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305,
     tls_kDHEPSK,
     tls_aPSK,
     tls_CHACHA20POLY1305,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305,
     TLS1_RFC_RSA_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305,
     tls_kRSAPSK,
     tls_aRSA,
     tls_CHACHA20POLY1305,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
#endif                          /* !defined(OPENtls_NO_CHACHA) &&
                                 * !defined(OPENtls_NO_POLY1305) */

#ifndef OPENtls_NO_CAMELLIA
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kRSA,
     tls_aRSA,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kEDH,
     tls_aDSS,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kEDH,
     tls_aRSA,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kEDH,
     tls_aNULL,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     tls_kRSA,
     tls_aRSA,
     tls_CAMELLIA256,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
     tls_kEDH,
     tls_aDSS,
     tls_CAMELLIA256,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     tls_kEDH,
     tls_aRSA,
     tls_CAMELLIA256,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256,
     tls_kEDH,
     tls_aNULL,
     tls_CAMELLIA256,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_CAMELLIA256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     tls_kDHE,
     tls_aDSS,
     tls_CAMELLIA256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     tls_kDHE,
     tls_aRSA,
     tls_CAMELLIA256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA,
     tls_kDHE,
     tls_aNULL,
     tls_CAMELLIA256,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_CAMELLIA128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     tls_kDHE,
     tls_aDSS,
     tls_CAMELLIA128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     tls_kDHE,
     tls_aRSA,
     tls_CAMELLIA128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA,
     tls_kDHE,
     tls_aNULL,
     tls_CAMELLIA128,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kECDHE,
     tls_aECDSA,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     tls_kECDHE,
     tls_aECDSA,
     tls_CAMELLIA256,
     tls_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kECDHE,
     tls_aRSA,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     tls_kECDHE,
     tls_aRSA,
     tls_CAMELLIA256,
     tls_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kPSK,
     tls_aPSK,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     tls_kPSK,
     tls_aPSK,
     tls_CAMELLIA256,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kDHEPSK,
     tls_aPSK,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     tls_kDHEPSK,
     tls_aPSK,
     tls_CAMELLIA256,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kRSAPSK,
     tls_aRSA,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     tls_kRSAPSK,
     tls_aRSA,
     tls_CAMELLIA256,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_CAMELLIA128,
     tls_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_CAMELLIA256,
     tls_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
#endif                          /* OPENtls_NO_CAMELLIA */

#ifndef OPENtls_NO_GOST
    {
     1,
     "GOST2001-GOST89-GOST89",
     "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
     0x3000081,
     tls_kGOST,
     tls_aGOST01,
     tls_eGOST2814789CNT,
     tls_GOST89MAC,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_HIGH,
     tls_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
     256,
     256,
     },
    {
     1,
     "GOST2001-NULL-GOST94",
     "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
     0x3000083,
     tls_kGOST,
     tls_aGOST01,
     tls_eNULL,
     tls_GOST94,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_STRONG_NONE,
     tls_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
     0,
     0,
     },
    {
     1,
     "GOST2012-GOST8912-GOST8912",
     NULL,
     0x0300ff85,
     tls_kGOST,
     tls_aGOST12 | tls_aGOST01,
     tls_eGOST2814789CNT12,
     tls_GOST89MAC12,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_HIGH,
     tls_HANDSHAKE_MAC_GOST12_256 | TLS1_PRF_GOST12_256 | TLS1_STREAM_MAC,
     256,
     256,
     },
    {
     1,
     "GOST2012-NULL-GOST12",
     NULL,
     0x0300ff87,
     tls_kGOST,
     tls_aGOST12 | tls_aGOST01,
     tls_eNULL,
     tls_GOST12_256,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_STRONG_NONE,
     tls_HANDSHAKE_MAC_GOST12_256 | TLS1_PRF_GOST12_256 | TLS1_STREAM_MAC,
     0,
     0,
     },
#endif                          /* OPENtls_NO_GOST */

#ifndef OPENtls_NO_IDEA
    {
     1,
     tls3_TXT_RSA_IDEA_128_SHA,
     tls3_RFC_RSA_IDEA_128_SHA,
     tls3_CK_RSA_IDEA_128_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_IDEA,
     tls_SHA1,
     tls3_VERSION, TLS1_1_VERSION,
     DTLS1_BAD_VER, DTLS1_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

#ifndef OPENtls_NO_SEED
    {
     1,
     TLS1_TXT_RSA_WITH_SEED_SHA,
     TLS1_RFC_RSA_WITH_SEED_SHA,
     TLS1_CK_RSA_WITH_SEED_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_SEED,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_SEED_SHA,
     TLS1_RFC_DHE_DSS_WITH_SEED_SHA,
     TLS1_CK_DHE_DSS_WITH_SEED_SHA,
     tls_kDHE,
     tls_aDSS,
     tls_SEED,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_SEED_SHA,
     TLS1_RFC_DHE_RSA_WITH_SEED_SHA,
     TLS1_CK_DHE_RSA_WITH_SEED_SHA,
     tls_kDHE,
     tls_aRSA,
     tls_SEED,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_SEED_SHA,
     TLS1_RFC_ADH_WITH_SEED_SHA,
     TLS1_CK_ADH_WITH_SEED_SHA,
     tls_kDHE,
     tls_aNULL,
     tls_SEED,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif                          /* OPENtls_NO_SEED */

#ifndef OPENtls_NO_WEAK_tls_CIPHERS
    {
     1,
     tls3_TXT_RSA_RC4_128_MD5,
     tls3_RFC_RSA_RC4_128_MD5,
     tls3_CK_RSA_RC4_128_MD5,
     tls_kRSA,
     tls_aRSA,
     tls_RC4,
     tls_MD5,
     tls3_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     tls3_TXT_RSA_RC4_128_SHA,
     tls3_RFC_RSA_RC4_128_SHA,
     tls3_CK_RSA_RC4_128_SHA,
     tls_kRSA,
     tls_aRSA,
     tls_RC4,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     tls3_TXT_ADH_RC4_128_MD5,
     tls3_RFC_ADH_RC4_128_MD5,
     tls3_CK_ADH_RC4_128_MD5,
     tls_kDHE,
     tls_aNULL,
     tls_RC4,
     tls_MD5,
     tls3_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_RC4_128_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA,
     tls_kECDHEPSK,
     tls_aPSK,
     tls_RC4,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA,
     TLS1_RFC_ECDH_anon_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
     tls_kECDHE,
     tls_aNULL,
     tls_RC4,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
     tls_kECDHE,
     tls_aECDSA,
     tls_RC4,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
     tls_kECDHE,
     tls_aRSA,
     tls_RC4,
     tls_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_RC4_128_SHA,
     TLS1_RFC_PSK_WITH_RC4_128_SHA,
     TLS1_CK_PSK_WITH_RC4_128_SHA,
     tls_kPSK,
     tls_aPSK,
     tls_RC4,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_RC4_128_SHA,
     TLS1_RFC_RSA_PSK_WITH_RC4_128_SHA,
     TLS1_CK_RSA_PSK_WITH_RC4_128_SHA,
     tls_kRSAPSK,
     tls_aRSA,
     tls_RC4,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_RC4_128_SHA,
     TLS1_RFC_DHE_PSK_WITH_RC4_128_SHA,
     TLS1_CK_DHE_PSK_WITH_RC4_128_SHA,
     tls_kDHEPSK,
     tls_aPSK,
     tls_RC4,
     tls_SHA1,
     tls3_VERSION, TLS1_2_VERSION,
     0, 0,
     tls_NOT_DEFAULT | tls_MEDIUM,
     tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif                          /* OPENtls_NO_WEAK_tls_CIPHERS */

#ifndef OPENtls_NO_ARIA
    {
     1,
     TLS1_TXT_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_RSA_WITH_ARIA_128_GCM_SHA256,
     tls_kRSA,
     tls_aRSA,
     tls_ARIA128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_RSA_WITH_ARIA_256_GCM_SHA384,
     tls_kRSA,
     tls_aRSA,
     tls_ARIA256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
     tls_kDHE,
     tls_aRSA,
     tls_ARIA128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
     tls_kDHE,
     tls_aRSA,
     tls_ARIA256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
     tls_kDHE,
     tls_aDSS,
     tls_ARIA128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
     tls_kDHE,
     tls_aDSS,
     tls_ARIA256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
     tls_kECDHE,
     tls_aECDSA,
     tls_ARIA128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
     tls_kECDHE,
     tls_aECDSA,
     tls_ARIA256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
     tls_kECDHE,
     tls_aRSA,
     tls_ARIA128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
     tls_kECDHE,
     tls_aRSA,
     tls_ARIA256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_PSK_WITH_ARIA_128_GCM_SHA256,
     tls_kPSK,
     tls_aPSK,
     tls_ARIA128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_PSK_WITH_ARIA_256_GCM_SHA384,
     tls_kPSK,
     tls_aPSK,
     tls_ARIA256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
     tls_kDHEPSK,
     tls_aPSK,
     tls_ARIA128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
     tls_kDHEPSK,
     tls_aPSK,
     tls_ARIA256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
     tls_kRSAPSK,
     tls_aRSA,
     tls_ARIA128GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
     tls_kRSAPSK,
     tls_aRSA,
     tls_ARIA256GCM,
     tls_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     tls_NOT_DEFAULT | tls_HIGH,
     tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
#endif /* OPENtls_NO_ARIA */
};

/*
 * The list of known Signalling Cipher-Suite Value "ciphers", non-valid
 * values stuffed into the ciphers field of the wire protocol for signalling
 * purposes.
 */
static tls_CIPHER tls3_scsvs[] = {
    {
     0,
     "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
     "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
     tls3_CK_SCSV,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    },
    {
     0,
     "TLS_FALLBACK_SCSV",
     "TLS_FALLBACK_SCSV",
     tls3_CK_FALLBACK_SCSV,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    },
};

static int cipher_compare(const void *a, const void *b)
{
    const tls_CIPHER *ap = (const tls_CIPHER *)a;
    const tls_CIPHER *bp = (const tls_CIPHER *)b;

    if (ap->id == bp->id)
        return 0;
    return ap->id < bp->id ? -1 : 1;
}

void tls_sort_cipher_list(void)
{
    qsort(tls13_ciphers, TLS13_NUM_CIPHERS, sizeof(tls13_ciphers[0]),
          cipher_compare);
    qsort(tls3_ciphers, tls3_NUM_CIPHERS, sizeof(tls3_ciphers[0]),
          cipher_compare);
    qsort(tls3_scsvs, tls3_NUM_SCSVS, sizeof(tls3_scsvs[0]), cipher_compare);
}

static int tls_undefined_function_1(tls *tls, unsigned char *r, size_t s,
                                    const char * t, size_t u,
                                    const unsigned char * v, size_t w, int x)
{
    (void)r;
    (void)s;
    (void)t;
    (void)u;
    (void)v;
    (void)w;
    (void)x;
    return tls_undefined_function(tls);
}

const tls3_ENC_METHOD tlsv3_enc_data = {
    tls3_enc,
    n_tls3_mac,
    tls3_setup_key_block,
    tls3_generate_master_secret,
    tls3_change_cipher_state,
    tls3_final_finish_mac,
    tls3_MD_CLIENT_FINISHED_CONST, 4,
    tls3_MD_SERVER_FINISHED_CONST, 4,
    tls3_alert_code,
    tls_undefined_function_1,
    0,
    tls3_set_handshake_header,
    tls_close_construct_packet,
    tls3_handshake_write
};

long tls3_default_timeout(void)
{
    /*
     * 2 hours, the 24 hours mentioned in the tlsv3 spec is way too long for
     * http, the cache would over fill
     */
    return (60 * 60 * 2);
}

int tls3_num_ciphers(void)
{
    return tls3_NUM_CIPHERS;
}

const tls_CIPHER *tls3_get_cipher(unsigned int u)
{
    if (u < tls3_NUM_CIPHERS)
        return &(tls3_ciphers[tls3_NUM_CIPHERS - 1 - u]);
    else
        return NULL;
}

int tls3_set_handshake_header(tls *s, WPACKET *pkt, int htype)
{
    /* No header in the event of a CCS */
    if (htype == tls3_MT_CHANGE_CIPHER_SPEC)
        return 1;

    /* Set the content type and 3 bytes for the message len */
    if (!WPACKET_put_bytes_u8(pkt, htype)
            || !WPACKET_start_sub_packet_u24(pkt))
        return 0;

    return 1;
}

int tls3_handshake_write(tls *s)
{
    return tls3_do_write(s, tls3_RT_HANDSHAKE);
}

int tls3_new(tls *s)
{
#ifndef OPENtls_NO_SRP
    if (!tls_SRP_CTX_init(s))
        return 0;
#endif

    if (!s->method->tls_clear(s))
        return 0;

    return 1;
}

void tls3_free(tls *s)
{
    if (s == NULL)
        return;

    tls3_cleanup_key_block(s);

#if !defined(OPENtls_NO_EC) || !defined(OPENtls_NO_DH)
    EVP_PKEY_free(s->s3.peer_tmp);
    s->s3.peer_tmp = NULL;
    EVP_PKEY_free(s->s3.tmp.pkey);
    s->s3.tmp.pkey = NULL;
#endif

    OPENtls_free(s->s3.tmp.ctype);
    sk_X509_NAME_pop_free(s->s3.tmp.peer_ca_names, X509_NAME_free);
    OPENtls_free(s->s3.tmp.ciphers_raw);
    OPENtls_clear_free(s->s3.tmp.pms, s->s3.tmp.pmslen);
    OPENtls_free(s->s3.tmp.peer_sigalgs);
    OPENtls_free(s->s3.tmp.peer_cert_sigalgs);
    tls3_free_digest_list(s);
    OPENtls_free(s->s3.alpn_selected);
    OPENtls_free(s->s3.alpn_proposed);

#ifndef OPENtls_NO_SRP
    tls_SRP_CTX_free(s);
#endif
    memset(&s->s3, 0, sizeof(s->s3));
}

int tls3_clear(tls *s)
{
    tls3_cleanup_key_block(s);
    OPENtls_free(s->s3.tmp.ctype);
    sk_X509_NAME_pop_free(s->s3.tmp.peer_ca_names, X509_NAME_free);
    OPENtls_free(s->s3.tmp.ciphers_raw);
    OPENtls_clear_free(s->s3.tmp.pms, s->s3.tmp.pmslen);
    OPENtls_free(s->s3.tmp.peer_sigalgs);
    OPENtls_free(s->s3.tmp.peer_cert_sigalgs);

#if !defined(OPENtls_NO_EC) || !defined(OPENtls_NO_DH)
    EVP_PKEY_free(s->s3.tmp.pkey);
    EVP_PKEY_free(s->s3.peer_tmp);
#endif                          /* !OPENtls_NO_EC */

    tls3_free_digest_list(s);

    OPENtls_free(s->s3.alpn_selected);
    OPENtls_free(s->s3.alpn_proposed);

    /* NULL/zero-out everything in the s3 struct */
    memset(&s->s3, 0, sizeof(s->s3));

    if (!tls_free_wbio_buffer(s))
        return 0;

    s->version = tls3_VERSION;

#if !defined(OPENtls_NO_NEXTPROTONEG)
    OPENtls_free(s->ext.npn);
    s->ext.npn = NULL;
    s->ext.npn_len = 0;
#endif

    return 1;
}

#ifndef OPENtls_NO_SRP
static char *srp_password_from_info_cb(tls *s, void *arg)
{
    return OPENtls_strdup(s->srp_ctx.info);
}
#endif

static int tls3_set_req_cert_type(CERT *c, const unsigned char *p, size_t len);

long tls3_ctrl(tls *s, int cmd, long larg, void *parg)
{
    int ret = 0;

    switch (cmd) {
    case tls_CTRL_GET_CLIENT_CERT_REQUEST:
        break;
    case tls_CTRL_GET_NUM_RENEGOTIATIONS:
        ret = s->s3.num_renegotiations;
        break;
    case tls_CTRL_CLEAR_NUM_RENEGOTIATIONS:
        ret = s->s3.num_renegotiations;
        s->s3.num_renegotiations = 0;
        break;
    case tls_CTRL_GET_TOTAL_RENEGOTIATIONS:
        ret = s->s3.total_renegotiations;
        break;
    case tls_CTRL_GET_FLAGS:
        ret = (int)(s->s3.flags);
        break;
#ifndef OPENtls_NO_DH
    case tls_CTRL_SET_TMP_DH:
        {
            DH *dh = (DH *)parg;
            EVP_PKEY *pkdh = NULL;
            if (dh == NULL) {
                tlserr(tls_F_tls3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return 0;
            }
            pkdh = tls_dh_to_pkey(dh);
            if (pkdh == NULL) {
                tlserr(tls_F_tls3_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            if (!tls_security(s, tls_SECOP_TMP_DH,
                              EVP_PKEY_security_bits(pkdh), 0, pkdh)) {
                tlserr(tls_F_tls3_CTRL, tls_R_DH_KEY_TOO_SMALL);
                EVP_PKEY_free(pkdh);
                return 0;
            }
            EVP_PKEY_free(s->cert->dh_tmp);
            s->cert->dh_tmp = pkdh;
            return 1;
        }
        break;
    case tls_CTRL_SET_TMP_DH_CB:
        {
            tlserr(tls_F_tls3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return ret;
        }
    case tls_CTRL_SET_DH_AUTO:
        s->cert->dh_tmp_auto = larg;
        return 1;
#endif
#ifndef OPENtls_NO_EC
    case tls_CTRL_SET_TMP_ECDH:
        {
            const EC_GROUP *group = NULL;
            int nid;

            if (parg == NULL) {
                tlserr(tls_F_tls3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return 0;
            }
            group = EC_KEY_get0_group((const EC_KEY *)parg);
            if (group == NULL) {
                tlserr(tls_F_tls3_CTRL, EC_R_MISSING_PARAMETERS);
                return 0;
            }
            nid = EC_GROUP_get_curve_name(group);
            if (nid == NID_undef)
                return 0;
            return tls1_set_groups(&s->ext.supportedgroups,
                                   &s->ext.supportedgroups_len,
                                   &nid, 1);
        }
        break;
#endif                          /* !OPENtls_NO_EC */
    case tls_CTRL_SET_TLSEXT_HOSTNAME:
        /*
         * TODO(Opentls1.2)
         * This API is only used for a client to set what SNI it will request
         * from the server, but we currently allow it to be used on servers
         * as well, which is a programming error.  Currently we just clear
         * the field in tls_do_handshake() for server tlss, but when we can
         * make ABI-breaking changes, we may want to make use of this API
         * an error on server tlss.
         */
        if (larg == TLSEXT_NAMETYPE_host_name) {
            size_t len;

            OPENtls_free(s->ext.hostname);
            s->ext.hostname = NULL;

            ret = 1;
            if (parg == NULL)
                break;
            len = strlen((char *)parg);
            if (len == 0 || len > TLSEXT_MAXLEN_host_name) {
                tlserr(tls_F_tls3_CTRL, tls_R_tls3_EXT_INVALID_SERVERNAME);
                return 0;
            }
            if ((s->ext.hostname = OPENtls_strdup((char *)parg)) == NULL) {
                tlserr(tls_F_tls3_CTRL, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        } else {
            tlserr(tls_F_tls3_CTRL, tls_R_tls3_EXT_INVALID_SERVERNAME_TYPE);
            return 0;
        }
        break;
    case tls_CTRL_SET_TLSEXT_DEBUG_ARG:
        s->ext.debug_arg = parg;
        ret = 1;
        break;

    case tls_CTRL_GET_TLSEXT_STATUS_REQ_TYPE:
        ret = s->ext.status_type;
        break;

    case tls_CTRL_SET_TLSEXT_STATUS_REQ_TYPE:
        s->ext.status_type = larg;
        ret = 1;
        break;

    case tls_CTRL_GET_TLSEXT_STATUS_REQ_EXTS:
        *(STACK_OF(X509_EXTENSION) **)parg = s->ext.ocsp.exts;
        ret = 1;
        break;

    case tls_CTRL_SET_TLSEXT_STATUS_REQ_EXTS:
        s->ext.ocsp.exts = parg;
        ret = 1;
        break;

    case tls_CTRL_GET_TLSEXT_STATUS_REQ_IDS:
        *(STACK_OF(OCSP_RESPID) **)parg = s->ext.ocsp.ids;
        ret = 1;
        break;

    case tls_CTRL_SET_TLSEXT_STATUS_REQ_IDS:
        s->ext.ocsp.ids = parg;
        ret = 1;
        break;

    case tls_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP:
        *(unsigned char **)parg = s->ext.ocsp.resp;
        if (s->ext.ocsp.resp_len == 0
                || s->ext.ocsp.resp_len > LONG_MAX)
            return -1;
        return (long)s->ext.ocsp.resp_len;

    case tls_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP:
        OPENtls_free(s->ext.ocsp.resp);
        s->ext.ocsp.resp = parg;
        s->ext.ocsp.resp_len = larg;
        ret = 1;
        break;

    case tls_CTRL_CHAIN:
        if (larg)
            return tls_cert_set1_chain(s, NULL, (STACK_OF(X509) *)parg);
        else
            return tls_cert_set0_chain(s, NULL, (STACK_OF(X509) *)parg);

    case tls_CTRL_CHAIN_CERT:
        if (larg)
            return tls_cert_add1_chain_cert(s, NULL, (X509 *)parg);
        else
            return tls_cert_add0_chain_cert(s, NULL, (X509 *)parg);

    case tls_CTRL_GET_CHAIN_CERTS:
        *(STACK_OF(X509) **)parg = s->cert->key->chain;
        ret = 1;
        break;

    case tls_CTRL_SELECT_CURRENT_CERT:
        return tls_cert_select_current(s->cert, (X509 *)parg);

    case tls_CTRL_SET_CURRENT_CERT:
        if (larg == tls_CERT_SET_SERVER) {
            const tls_CIPHER *cipher;
            if (!s->server)
                return 0;
            cipher = s->s3.tmp.new_cipher;
            if (cipher == NULL)
                return 0;
            /*
             * No certificate for unauthenticated ciphersuites or using SRP
             * authentication
             */
            if (cipher->algorithm_auth & (tls_aNULL | tls_aSRP))
                return 2;
            if (s->s3.tmp.cert == NULL)
                return 0;
            s->cert->key = s->s3.tmp.cert;
            return 1;
        }
        return tls_cert_set_current(s->cert, larg);

#if !defined(OPENtls_NO_EC) || !defined(OPENtls_NO_DH)
    case tls_CTRL_GET_GROUPS:
        {
            uint16_t *clist;
            size_t clistlen;

            if (!s->session)
                return 0;
            clist = s->ext.peer_supportedgroups;
            clistlen = s->ext.peer_supportedgroups_len;
            if (parg) {
                size_t i;
                int *cptr = parg;

                for (i = 0; i < clistlen; i++) {
                    const TLS_GROUP_INFO *cinf = tls1_group_id_lookup(clist[i]);

                    if (cinf != NULL)
                        cptr[i] = cinf->nid;
                    else
                        cptr[i] = TLSEXT_nid_unknown | clist[i];
                }
            }
            return (int)clistlen;
        }

    case tls_CTRL_SET_GROUPS:
        return tls1_set_groups(&s->ext.supportedgroups,
                               &s->ext.supportedgroups_len, parg, larg);

    case tls_CTRL_SET_GROUPS_LIST:
        return tls1_set_groups_list(&s->ext.supportedgroups,
                                    &s->ext.supportedgroups_len, parg);

    case tls_CTRL_GET_SHARED_GROUP:
        {
            uint16_t id = tls1_shared_group(s, larg);

            if (larg != -1)
                return tls1_group_id2nid(id);
            return id;
        }
    case tls_CTRL_GET_NEGOTIATED_GROUP:
        ret = tls1_group_id2nid(s->s3.group_id);
        break;
#endif /* !defined(OPENtls_NO_EC) || !defined(OPENtls_NO_DH) */

    case tls_CTRL_SET_SIGALGS:
        return tls1_set_sigalgs(s->cert, parg, larg, 0);

    case tls_CTRL_SET_SIGALGS_LIST:
        return tls1_set_sigalgs_list(s->cert, parg, 0);

    case tls_CTRL_SET_CLIENT_SIGALGS:
        return tls1_set_sigalgs(s->cert, parg, larg, 1);

    case tls_CTRL_SET_CLIENT_SIGALGS_LIST:
        return tls1_set_sigalgs_list(s->cert, parg, 1);

    case tls_CTRL_GET_CLIENT_CERT_TYPES:
        {
            const unsigned char **pctype = parg;
            if (s->server || !s->s3.tmp.cert_req)
                return 0;
            if (pctype)
                *pctype = s->s3.tmp.ctype;
            return s->s3.tmp.ctype_len;
        }

    case tls_CTRL_SET_CLIENT_CERT_TYPES:
        if (!s->server)
            return 0;
        return tls3_set_req_cert_type(s->cert, parg, larg);

    case tls_CTRL_BUILD_CERT_CHAIN:
        return tls_build_cert_chain(s, NULL, larg);

    case tls_CTRL_SET_VERIFY_CERT_STORE:
        return tls_cert_set_cert_store(s->cert, parg, 0, larg);

    case tls_CTRL_SET_CHAIN_CERT_STORE:
        return tls_cert_set_cert_store(s->cert, parg, 1, larg);

    case tls_CTRL_GET_PEER_SIGNATURE_NID:
        if (s->s3.tmp.peer_sigalg == NULL)
            return 0;
        *(int *)parg = s->s3.tmp.peer_sigalg->hash;
        return 1;

    case tls_CTRL_GET_SIGNATURE_NID:
        if (s->s3.tmp.sigalg == NULL)
            return 0;
        *(int *)parg = s->s3.tmp.sigalg->hash;
        return 1;

    case tls_CTRL_GET_PEER_TMP_KEY:
#if !defined(OPENtls_NO_DH) || !defined(OPENtls_NO_EC)
        if (s->session == NULL || s->s3.peer_tmp == NULL) {
            return 0;
        } else {
            EVP_PKEY_up_ref(s->s3.peer_tmp);
            *(EVP_PKEY **)parg = s->s3.peer_tmp;
            return 1;
        }
#else
        return 0;
#endif

    case tls_CTRL_GET_TMP_KEY:
#if !defined(OPENtls_NO_DH) || !defined(OPENtls_NO_EC)
        if (s->session == NULL || s->s3.tmp.pkey == NULL) {
            return 0;
        } else {
            EVP_PKEY_up_ref(s->s3.tmp.pkey);
            *(EVP_PKEY **)parg = s->s3.tmp.pkey;
            return 1;
        }
#else
        return 0;
#endif

#ifndef OPENtls_NO_EC
    case tls_CTRL_GET_EC_POINT_FORMATS:
        {
            const unsigned char **pformat = parg;

            if (s->ext.peer_ecpointformats == NULL)
                return 0;
            *pformat = s->ext.peer_ecpointformats;
            return (int)s->ext.peer_ecpointformats_len;
        }
#endif

    default:
        break;
    }
    return ret;
}

long tls3_callback_ctrl(tls *s, int cmd, void (*fp) (void))
{
    int ret = 0;

    switch (cmd) {
#ifndef OPENtls_NO_DH
    case tls_CTRL_SET_TMP_DH_CB:
        {
            s->cert->dh_tmp_cb = (DH *(*)(tls *, int, int))fp;
        }
        break;
#endif
    case tls_CTRL_SET_TLSEXT_DEBUG_CB:
        s->ext.debug_cb = (void (*)(tls *, int, int,
                                    const unsigned char *, int, void *))fp;
        break;

    case tls_CTRL_SET_NOT_RESUMABLE_SESS_CB:
        {
            s->not_resumable_session_cb = (int (*)(tls *, int))fp;
        }
        break;
    default:
        break;
    }
    return ret;
}

long tls3_ctx_ctrl(tls_CTX *ctx, int cmd, long larg, void *parg)
{
    switch (cmd) {
#ifndef OPENtls_NO_DH
    case tls_CTRL_SET_TMP_DH:
        {
            DH *dh = (DH *)parg;
            EVP_PKEY *pkdh = NULL;
            if (dh == NULL) {
                tlserr(tls_F_tls3_CTX_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return 0;
            }
            pkdh = tls_dh_to_pkey(dh);
            if (pkdh == NULL) {
                tlserr(tls_F_tls3_CTX_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            if (!tls_ctx_security(ctx, tls_SECOP_TMP_DH,
                                  EVP_PKEY_security_bits(pkdh), 0, pkdh)) {
                tlserr(tls_F_tls3_CTX_CTRL, tls_R_DH_KEY_TOO_SMALL);
                EVP_PKEY_free(pkdh);
                return 0;
            }
            EVP_PKEY_free(ctx->cert->dh_tmp);
            ctx->cert->dh_tmp = pkdh;
            return 1;
        }
    case tls_CTRL_SET_TMP_DH_CB:
        {
            tlserr(tls_F_tls3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return 0;
        }
    case tls_CTRL_SET_DH_AUTO:
        ctx->cert->dh_tmp_auto = larg;
        return 1;
#endif
#ifndef OPENtls_NO_EC
    case tls_CTRL_SET_TMP_ECDH:
        {
            const EC_GROUP *group = NULL;
            int nid;

            if (parg == NULL) {
                tlserr(tls_F_tls3_CTX_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return 0;
            }
            group = EC_KEY_get0_group((const EC_KEY *)parg);
            if (group == NULL) {
                tlserr(tls_F_tls3_CTX_CTRL, EC_R_MISSING_PARAMETERS);
                return 0;
            }
            nid = EC_GROUP_get_curve_name(group);
            if (nid == NID_undef)
                return 0;
            return tls1_set_groups(&ctx->ext.supportedgroups,
                                   &ctx->ext.supportedgroups_len,
                                   &nid, 1);
        }
#endif                          /* !OPENtls_NO_EC */
    case tls_CTRL_SET_TLSEXT_SERVERNAME_ARG:
        ctx->ext.servername_arg = parg;
        break;
    case tls_CTRL_SET_TLSEXT_TICKET_KEYS:
    case tls_CTRL_GET_TLSEXT_TICKET_KEYS:
        {
            unsigned char *keys = parg;
            long tick_keylen = (sizeof(ctx->ext.tick_key_name) +
                                sizeof(ctx->ext.secure->tick_hmac_key) +
                                sizeof(ctx->ext.secure->tick_aes_key));
            if (keys == NULL)
                return tick_keylen;
            if (larg != tick_keylen) {
                tlserr(tls_F_tls3_CTX_CTRL, tls_R_INVALID_TICKET_KEYS_LENGTH);
                return 0;
            }
            if (cmd == tls_CTRL_SET_TLSEXT_TICKET_KEYS) {
                memcpy(ctx->ext.tick_key_name, keys,
                       sizeof(ctx->ext.tick_key_name));
                memcpy(ctx->ext.secure->tick_hmac_key,
                       keys + sizeof(ctx->ext.tick_key_name),
                       sizeof(ctx->ext.secure->tick_hmac_key));
                memcpy(ctx->ext.secure->tick_aes_key,
                       keys + sizeof(ctx->ext.tick_key_name) +
                       sizeof(ctx->ext.secure->tick_hmac_key),
                       sizeof(ctx->ext.secure->tick_aes_key));
            } else {
                memcpy(keys, ctx->ext.tick_key_name,
                       sizeof(ctx->ext.tick_key_name));
                memcpy(keys + sizeof(ctx->ext.tick_key_name),
                       ctx->ext.secure->tick_hmac_key,
                       sizeof(ctx->ext.secure->tick_hmac_key));
                memcpy(keys + sizeof(ctx->ext.tick_key_name) +
                       sizeof(ctx->ext.secure->tick_hmac_key),
                       ctx->ext.secure->tick_aes_key,
                       sizeof(ctx->ext.secure->tick_aes_key));
            }
            return 1;
        }

    case tls_CTRL_GET_TLSEXT_STATUS_REQ_TYPE:
        return ctx->ext.status_type;

    case tls_CTRL_SET_TLSEXT_STATUS_REQ_TYPE:
        ctx->ext.status_type = larg;
        break;

    case tls_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG:
        ctx->ext.status_arg = parg;
        return 1;

    case tls_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG:
        *(void**)parg = ctx->ext.status_arg;
        break;

    case tls_CTRL_GET_TLSEXT_STATUS_REQ_CB:
        *(int (**)(tls*, void*))parg = ctx->ext.status_cb;
        break;

#ifndef OPENtls_NO_SRP
    case tls_CTRL_SET_TLS_EXT_SRP_USERNAME:
        ctx->srp_ctx.srp_Mask |= tls_kSRP;
        OPENtls_free(ctx->srp_ctx.login);
        ctx->srp_ctx.login = NULL;
        if (parg == NULL)
            break;
        if (strlen((const char *)parg) > 255 || strlen((const char *)parg) < 1) {
            tlserr(tls_F_tls3_CTX_CTRL, tls_R_INVALID_SRP_USERNAME);
            return 0;
        }
        if ((ctx->srp_ctx.login = OPENtls_strdup((char *)parg)) == NULL) {
            tlserr(tls_F_tls3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        break;
    case tls_CTRL_SET_TLS_EXT_SRP_PASSWORD:
        ctx->srp_ctx.SRP_give_srp_client_pwd_callback =
            srp_password_from_info_cb;
        if (ctx->srp_ctx.info != NULL)
            OPENtls_free(ctx->srp_ctx.info);
        if ((ctx->srp_ctx.info = OPENtls_strdup((char *)parg)) == NULL) {
            tlserr(tls_F_tls3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        break;
    case tls_CTRL_SET_SRP_ARG:
        ctx->srp_ctx.srp_Mask |= tls_kSRP;
        ctx->srp_ctx.SRP_cb_arg = parg;
        break;

    case tls_CTRL_SET_TLS_EXT_SRP_STRENGTH:
        ctx->srp_ctx.strength = larg;
        break;
#endif

#if !defined(OPENtls_NO_EC) || !defined(OPENtls_NO_DH)
    case tls_CTRL_SET_GROUPS:
        return tls1_set_groups(&ctx->ext.supportedgroups,
                               &ctx->ext.supportedgroups_len,
                               parg, larg);

    case tls_CTRL_SET_GROUPS_LIST:
        return tls1_set_groups_list(&ctx->ext.supportedgroups,
                                    &ctx->ext.supportedgroups_len,
                                    parg);
#endif /* !defined(OPENtls_NO_EC) || !defined(OPENtls_NO_DH) */

    case tls_CTRL_SET_SIGALGS:
        return tls1_set_sigalgs(ctx->cert, parg, larg, 0);

    case tls_CTRL_SET_SIGALGS_LIST:
        return tls1_set_sigalgs_list(ctx->cert, parg, 0);

    case tls_CTRL_SET_CLIENT_SIGALGS:
        return tls1_set_sigalgs(ctx->cert, parg, larg, 1);

    case tls_CTRL_SET_CLIENT_SIGALGS_LIST:
        return tls1_set_sigalgs_list(ctx->cert, parg, 1);

    case tls_CTRL_SET_CLIENT_CERT_TYPES:
        return tls3_set_req_cert_type(ctx->cert, parg, larg);

    case tls_CTRL_BUILD_CERT_CHAIN:
        return tls_build_cert_chain(NULL, ctx, larg);

    case tls_CTRL_SET_VERIFY_CERT_STORE:
        return tls_cert_set_cert_store(ctx->cert, parg, 0, larg);

    case tls_CTRL_SET_CHAIN_CERT_STORE:
        return tls_cert_set_cert_store(ctx->cert, parg, 1, larg);

        /* A Thawte special :-) */
    case tls_CTRL_EXTRA_CHAIN_CERT:
        if (ctx->extra_certs == NULL) {
            if ((ctx->extra_certs = sk_X509_new_null()) == NULL) {
                tlserr(tls_F_tls3_CTX_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        if (!sk_X509_push(ctx->extra_certs, (X509 *)parg)) {
            tlserr(tls_F_tls3_CTX_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        break;

    case tls_CTRL_GET_EXTRA_CHAIN_CERTS:
        if (ctx->extra_certs == NULL && larg == 0)
            *(STACK_OF(X509) **)parg = ctx->cert->key->chain;
        else
            *(STACK_OF(X509) **)parg = ctx->extra_certs;
        break;

    case tls_CTRL_CLEAR_EXTRA_CHAIN_CERTS:
        sk_X509_pop_free(ctx->extra_certs, X509_free);
        ctx->extra_certs = NULL;
        break;

    case tls_CTRL_CHAIN:
        if (larg)
            return tls_cert_set1_chain(NULL, ctx, (STACK_OF(X509) *)parg);
        else
            return tls_cert_set0_chain(NULL, ctx, (STACK_OF(X509) *)parg);

    case tls_CTRL_CHAIN_CERT:
        if (larg)
            return tls_cert_add1_chain_cert(NULL, ctx, (X509 *)parg);
        else
            return tls_cert_add0_chain_cert(NULL, ctx, (X509 *)parg);

    case tls_CTRL_GET_CHAIN_CERTS:
        *(STACK_OF(X509) **)parg = ctx->cert->key->chain;
        break;

    case tls_CTRL_SELECT_CURRENT_CERT:
        return tls_cert_select_current(ctx->cert, (X509 *)parg);

    case tls_CTRL_SET_CURRENT_CERT:
        return tls_cert_set_current(ctx->cert, larg);

    default:
        return 0;
    }
    return 1;
}

long tls3_ctx_callback_ctrl(tls_CTX *ctx, int cmd, void (*fp) (void))
{
    switch (cmd) {
#ifndef OPENtls_NO_DH
    case tls_CTRL_SET_TMP_DH_CB:
        {
            ctx->cert->dh_tmp_cb = (DH *(*)(tls *, int, int))fp;
        }
        break;
#endif
    case tls_CTRL_SET_TLSEXT_SERVERNAME_CB:
        ctx->ext.servername_cb = (int (*)(tls *, int *, void *))fp;
        break;

    case tls_CTRL_SET_TLSEXT_STATUS_REQ_CB:
        ctx->ext.status_cb = (int (*)(tls *, void *))fp;
        break;

    case tls_CTRL_SET_TLSEXT_TICKET_KEY_CB:
        ctx->ext.ticket_key_cb = (int (*)(tls *, unsigned char *,
                                             unsigned char *,
                                             EVP_CIPHER_CTX *,
                                             HMAC_CTX *, int))fp;
        break;

#ifndef OPENtls_NO_SRP
    case tls_CTRL_SET_SRP_VERIFY_PARAM_CB:
        ctx->srp_ctx.srp_Mask |= tls_kSRP;
        ctx->srp_ctx.SRP_verify_param_callback = (int (*)(tls *, void *))fp;
        break;
    case tls_CTRL_SET_TLS_EXT_SRP_USERNAME_CB:
        ctx->srp_ctx.srp_Mask |= tls_kSRP;
        ctx->srp_ctx.TLS_ext_srp_username_callback =
            (int (*)(tls *, int *, void *))fp;
        break;
    case tls_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB:
        ctx->srp_ctx.srp_Mask |= tls_kSRP;
        ctx->srp_ctx.SRP_give_srp_client_pwd_callback =
            (char *(*)(tls *, void *))fp;
        break;
#endif
    case tls_CTRL_SET_NOT_RESUMABLE_SESS_CB:
        {
            ctx->not_resumable_session_cb = (int (*)(tls *, int))fp;
        }
        break;
    default:
        return 0;
    }
    return 1;
}

const tls_CIPHER *tls3_get_cipher_by_id(uint32_t id)
{
    tls_CIPHER c;
    const tls_CIPHER *cp;

    c.id = id;
    cp = OBJ_bsearch_tls_cipher_id(&c, tls13_ciphers, TLS13_NUM_CIPHERS);
    if (cp != NULL)
        return cp;
    cp = OBJ_bsearch_tls_cipher_id(&c, tls3_ciphers, tls3_NUM_CIPHERS);
    if (cp != NULL)
        return cp;
    return OBJ_bsearch_tls_cipher_id(&c, tls3_scsvs, tls3_NUM_SCSVS);
}

const tls_CIPHER *tls3_get_cipher_by_std_name(const char *stdname)
{
    tls_CIPHER *c = NULL, *tbl;
    tls_CIPHER *alltabs[] = {tls13_ciphers, tls3_ciphers};
    size_t i, j, tblsize[] = {TLS13_NUM_CIPHERS, tls3_NUM_CIPHERS};

    /* this is not efficient, necessary to optimize this? */
    for (j = 0; j < Otls_NELEM(alltabs); j++) {
        for (i = 0, tbl = alltabs[j]; i < tblsize[j]; i++, tbl++) {
            if (tbl->stdname == NULL)
                continue;
            if (strcmp(stdname, tbl->stdname) == 0) {
                c = tbl;
                break;
            }
        }
    }
    if (c == NULL) {
        tbl = tls3_scsvs;
        for (i = 0; i < tls3_NUM_SCSVS; i++, tbl++) {
            if (strcmp(stdname, tbl->stdname) == 0) {
                c = tbl;
                break;
            }
        }
    }
    return c;
}

/*
 * This function needs to check if the ciphers required are actually
 * available
 */
const tls_CIPHER *tls3_get_cipher_by_char(const unsigned char *p)
{
    return tls3_get_cipher_by_id(tls3_CK_CIPHERSUITE_FLAG
                                 | ((uint32_t)p[0] << 8L)
                                 | (uint32_t)p[1]);
}

int tls3_put_cipher_by_char(const tls_CIPHER *c, WPACKET *pkt, size_t *len)
{
    if ((c->id & 0xff000000) != tls3_CK_CIPHERSUITE_FLAG) {
        *len = 0;
        return 1;
    }

    if (!WPACKET_put_bytes_u16(pkt, c->id & 0xffff))
        return 0;

    *len = 2;
    return 1;
}

/*
 * tls3_choose_cipher - choose a cipher from those offered by the client
 * @s: tls connection
 * @clnt: ciphers offered by the client
 * @srvr: ciphers enabled on the server?
 *
 * Returns the selected cipher or NULL when no common ciphers.
 */
const tls_CIPHER *tls3_choose_cipher(tls *s, STACK_OF(tls_CIPHER) *clnt,
                                     STACK_OF(tls_CIPHER) *srvr)
{
    const tls_CIPHER *c, *ret = NULL;
    STACK_OF(tls_CIPHER) *prio, *allow;
    int i, ii, ok, prefer_sha256 = 0;
    unsigned long alg_k = 0, alg_a = 0, mask_k = 0, mask_a = 0;
    const EVP_MD *mdsha256 = EVP_sha256();
#ifndef OPENtls_NO_CHACHA
    STACK_OF(tls_CIPHER) *prio_chacha = NULL;
#endif

    /* Let's see which ciphers we can support */

    /*
     * Do not set the compare functions, because this may lead to a
     * reordering by "id". We want to keep the original ordering. We may pay
     * a price in performance during sk_tls_CIPHER_find(), but would have to
     * pay with the price of sk_tls_CIPHER_dup().
     */

    Otls_TRACE_BEGIN(TLS_CIPHER) {
        BIO_printf(trc_out, "Server has %d from %p:\n",
                   sk_tls_CIPHER_num(srvr), (void *)srvr);
        for (i = 0; i < sk_tls_CIPHER_num(srvr); ++i) {
            c = sk_tls_CIPHER_value(srvr, i);
            BIO_printf(trc_out, "%p:%s\n", (void *)c, c->name);
        }
        BIO_printf(trc_out, "Client sent %d from %p:\n",
                   sk_tls_CIPHER_num(clnt), (void *)clnt);
        for (i = 0; i < sk_tls_CIPHER_num(clnt); ++i) {
            c = sk_tls_CIPHER_value(clnt, i);
            BIO_printf(trc_out, "%p:%s\n", (void *)c, c->name);
        }
    } Otls_TRACE_END(TLS_CIPHER);

    /* SUITE-B takes precedence over server preference and ChaCha priortiy */
    if (tls1_suiteb(s)) {
        prio = srvr;
        allow = clnt;
    } else if (s->options & tls_OP_CIPHER_SERVER_PREFERENCE) {
        prio = srvr;
        allow = clnt;
#ifndef OPENtls_NO_CHACHA
        /* If ChaCha20 is at the top of the client preference list,
           and there are ChaCha20 ciphers in the server list, then
           temporarily prioritize all ChaCha20 ciphers in the servers list. */
        if (s->options & tls_OP_PRIORITIZE_CHACHA && sk_tls_CIPHER_num(clnt) > 0) {
            c = sk_tls_CIPHER_value(clnt, 0);
            if (c->algorithm_enc == tls_CHACHA20POLY1305) {
                /* ChaCha20 is client preferred, check server... */
                int num = sk_tls_CIPHER_num(srvr);
                int found = 0;
                for (i = 0; i < num; i++) {
                    c = sk_tls_CIPHER_value(srvr, i);
                    if (c->algorithm_enc == tls_CHACHA20POLY1305) {
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    prio_chacha = sk_tls_CIPHER_new_reserve(NULL, num);
                    /* if reserve fails, then there's likely a memory issue */
                    if (prio_chacha != NULL) {
                        /* Put all ChaCha20 at the top, starting with the one we just found */
                        sk_tls_CIPHER_push(prio_chacha, c);
                        for (i++; i < num; i++) {
                            c = sk_tls_CIPHER_value(srvr, i);
                            if (c->algorithm_enc == tls_CHACHA20POLY1305)
                                sk_tls_CIPHER_push(prio_chacha, c);
                        }
                        /* Pull in the rest */
                        for (i = 0; i < num; i++) {
                            c = sk_tls_CIPHER_value(srvr, i);
                            if (c->algorithm_enc != tls_CHACHA20POLY1305)
                                sk_tls_CIPHER_push(prio_chacha, c);
                        }
                        prio = prio_chacha;
                    }
                }
            }
        }
# endif
    } else {
        prio = clnt;
        allow = srvr;
    }

    if (tls_IS_TLS13(s)) {
#ifndef OPENtls_NO_PSK
        int j;

        /*
         * If we allow "old" style PSK callbacks, and we have no certificate (so
         * we're not going to succeed without a PSK anyway), and we're in
         * TLSv1.3 then the default hash for a PSK is SHA-256 (as per the
         * TLSv1.3 spec). Therefore we should prioritise ciphersuites using
         * that.
         */
        if (s->psk_server_callback != NULL) {
            for (j = 0; j < tls_PKEY_NUM && !tls_has_cert(s, j); j++);
            if (j == tls_PKEY_NUM) {
                /* There are no certificates */
                prefer_sha256 = 1;
            }
        }
#endif
    } else {
        tls1_set_cert_validity(s);
        tls_set_masks(s);
    }

    for (i = 0; i < sk_tls_CIPHER_num(prio); i++) {
        c = sk_tls_CIPHER_value(prio, i);

        /* Skip ciphers not supported by the protocol version */
        if (!tls_IS_DTLS(s) &&
            ((s->version < c->min_tls) || (s->version > c->max_tls)))
            continue;
        if (tls_IS_DTLS(s) &&
            (DTLS_VERSION_LT(s->version, c->min_dtls) ||
             DTLS_VERSION_GT(s->version, c->max_dtls)))
            continue;

        /*
         * Since TLS 1.3 ciphersuites can be used with any auth or
         * key exchange scheme skip tests.
         */
        if (!tls_IS_TLS13(s)) {
            mask_k = s->s3.tmp.mask_k;
            mask_a = s->s3.tmp.mask_a;
#ifndef OPENtls_NO_SRP
            if (s->srp_ctx.srp_Mask & tls_kSRP) {
                mask_k |= tls_kSRP;
                mask_a |= tls_aSRP;
            }
#endif

            alg_k = c->algorithm_mkey;
            alg_a = c->algorithm_auth;

#ifndef OPENtls_NO_PSK
            /* with PSK there must be server callback set */
            if ((alg_k & tls_PSK) && s->psk_server_callback == NULL)
                continue;
#endif                          /* OPENtls_NO_PSK */

            ok = (alg_k & mask_k) && (alg_a & mask_a);
            Otls_TRACE7(TLS_CIPHER,
                        "%d:[%08lX:%08lX:%08lX:%08lX]%p:%s\n",
                        ok, alg_k, alg_a, mask_k, mask_a, (void *)c, c->name);

#ifndef OPENtls_NO_EC
            /*
             * if we are considering an ECC cipher suite that uses an ephemeral
             * EC key check it
             */
            if (alg_k & tls_kECDHE)
                ok = ok && tls1_check_ec_tmp_key(s, c->id);
#endif                          /* OPENtls_NO_EC */

            if (!ok)
                continue;
        }
        ii = sk_tls_CIPHER_find(allow, c);
        if (ii >= 0) {
            /* Check security callback permits this cipher */
            if (!tls_security(s, tls_SECOP_CIPHER_SHARED,
                              c->strength_bits, 0, (void *)c))
                continue;
#if !defined(OPENtls_NO_EC)
            if ((alg_k & tls_kECDHE) && (alg_a & tls_aECDSA)
                && s->s3.is_probably_safari) {
                if (!ret)
                    ret = sk_tls_CIPHER_value(allow, ii);
                continue;
            }
#endif
            if (prefer_sha256) {
                const tls_CIPHER *tmp = sk_tls_CIPHER_value(allow, ii);

                if (tls_md(tmp->algorithm2) == mdsha256) {
                    ret = tmp;
                    break;
                }
                if (ret == NULL)
                    ret = tmp;
                continue;
            }
            ret = sk_tls_CIPHER_value(allow, ii);
            break;
        }
    }
#ifndef OPENtls_NO_CHACHA
    sk_tls_CIPHER_free(prio_chacha);
#endif
    return ret;
}

int tls3_get_req_cert_type(tls *s, WPACKET *pkt)
{
    uint32_t alg_k, alg_a = 0;

    /* If we have custom certificate types set, use them */
    if (s->cert->ctype)
        return WPACKET_memcpy(pkt, s->cert->ctype, s->cert->ctype_len);
    /* Get mask of algorithms disabled by signature list */
    tls_set_sig_mask(&alg_a, s, tls_SECOP_SIGALG_MASK);

    alg_k = s->s3.tmp.new_cipher->algorithm_mkey;

#ifndef OPENtls_NO_GOST
    if (s->version >= TLS1_VERSION && (alg_k & tls_kGOST))
            return WPACKET_put_bytes_u8(pkt, TLS_CT_GOST01_SIGN)
                    && WPACKET_put_bytes_u8(pkt, TLS_CT_GOST12_SIGN)
                    && WPACKET_put_bytes_u8(pkt, TLS_CT_GOST12_512_SIGN);
#endif

    if ((s->version == tls3_VERSION) && (alg_k & tls_kDHE)) {
#ifndef OPENtls_NO_DH
# ifndef OPENtls_NO_RSA
        if (!WPACKET_put_bytes_u8(pkt, tls3_CT_RSA_EPHEMERAL_DH))
            return 0;
# endif
# ifndef OPENtls_NO_DSA
        if (!WPACKET_put_bytes_u8(pkt, tls3_CT_DSS_EPHEMERAL_DH))
            return 0;
# endif
#endif                          /* !OPENtls_NO_DH */
    }
#ifndef OPENtls_NO_RSA
    if (!(alg_a & tls_aRSA) && !WPACKET_put_bytes_u8(pkt, tls3_CT_RSA_SIGN))
        return 0;
#endif
#ifndef OPENtls_NO_DSA
    if (!(alg_a & tls_aDSS) && !WPACKET_put_bytes_u8(pkt, tls3_CT_DSS_SIGN))
        return 0;
#endif
#ifndef OPENtls_NO_EC
    /*
     * ECDSA certs can be used with RSA cipher suites too so we don't
     * need to check for tls_kECDH or tls_kECDHE
     */
    if (s->version >= TLS1_VERSION
            && !(alg_a & tls_aECDSA)
            && !WPACKET_put_bytes_u8(pkt, TLS_CT_ECDSA_SIGN))
        return 0;
#endif
    return 1;
}

static int tls3_set_req_cert_type(CERT *c, const unsigned char *p, size_t len)
{
    OPENtls_free(c->ctype);
    c->ctype = NULL;
    c->ctype_len = 0;
    if (p == NULL || len == 0)
        return 1;
    if (len > 0xff)
        return 0;
    c->ctype = OPENtls_memdup(p, len);
    if (c->ctype == NULL)
        return 0;
    c->ctype_len = len;
    return 1;
}

int tls3_shutdown(tls *s)
{
    int ret;

    /*
     * Don't do anything much if we have not done the handshake or we don't
     * want to send messages :-)
     */
    if (s->quiet_shutdown || tls_in_before(s)) {
        s->shutdown = (tls_SENT_SHUTDOWN | tls_RECEIVED_SHUTDOWN);
        return 1;
    }

    if (!(s->shutdown & tls_SENT_SHUTDOWN)) {
        s->shutdown |= tls_SENT_SHUTDOWN;
        tls3_send_alert(s, tls3_AL_WARNING, tls_AD_CLOSE_NOTIFY);
        /*
         * our shutdown alert has been sent now, and if it still needs to be
         * written, s->s3.alert_dispatch will be true
         */
        if (s->s3.alert_dispatch)
            return -1;        /* return WANT_WRITE */
    } else if (s->s3.alert_dispatch) {
        /* resend it if not sent */
        ret = s->method->tls_dispatch_alert(s);
        if (ret == -1) {
            /*
             * we only get to return -1 here the 2nd/Nth invocation, we must
             * have already signalled return 0 upon a previous invocation,
             * return WANT_WRITE
             */
            return ret;
        }
    } else if (!(s->shutdown & tls_RECEIVED_SHUTDOWN)) {
        size_t readbytes;
        /*
         * If we are waiting for a close from our peer, we are closed
         */
        s->method->tls_read_bytes(s, 0, NULL, NULL, 0, 0, &readbytes);
        if (!(s->shutdown & tls_RECEIVED_SHUTDOWN)) {
            return -1;        /* return WANT_READ */
        }
    }

    if ((s->shutdown == (tls_SENT_SHUTDOWN | tls_RECEIVED_SHUTDOWN)) &&
        !s->s3.alert_dispatch)
        return 1;
    else
        return 0;
}

int tls3_write(tls *s, const void *buf, size_t len, size_t *written)
{
    clear_sys_error();
    if (s->s3.renegotiate)
        tls3_renegotiate_check(s, 0);

    return s->method->tls_write_bytes(s, tls3_RT_APPLICATION_DATA, buf, len,
                                      written);
}

static int tls3_read_internal(tls *s, void *buf, size_t len, int peek,
                              size_t *readbytes)
{
    int ret;

    clear_sys_error();
    if (s->s3.renegotiate)
        tls3_renegotiate_check(s, 0);
    s->s3.in_read_app_data = 1;
    ret =
        s->method->tls_read_bytes(s, tls3_RT_APPLICATION_DATA, NULL, buf, len,
                                  peek, readbytes);
    if ((ret == -1) && (s->s3.in_read_app_data == 2)) {
        /*
         * tls3_read_bytes decided to call s->handshake_func, which called
         * tls3_read_bytes to read handshake data. However, tls3_read_bytes
         * actually found application data and thinks that application data
         * makes sense here; so disable handshake processing and try to read
         * application data again.
         */
        otls_statem_set_in_handshake(s, 1);
        ret =
            s->method->tls_read_bytes(s, tls3_RT_APPLICATION_DATA, NULL, buf,
                                      len, peek, readbytes);
        otls_statem_set_in_handshake(s, 0);
    } else
        s->s3.in_read_app_data = 0;

    return ret;
}

int tls3_read(tls *s, void *buf, size_t len, size_t *readbytes)
{
    return tls3_read_internal(s, buf, len, 0, readbytes);
}

int tls3_peek(tls *s, void *buf, size_t len, size_t *readbytes)
{
    return tls3_read_internal(s, buf, len, 1, readbytes);
}

int tls3_renegotiate(tls *s)
{
    if (s->handshake_func == NULL)
        return 1;

    s->s3.renegotiate = 1;
    return 1;
}

/*
 * Check if we are waiting to do a renegotiation and if so whether now is a
 * good time to do it. If |initok| is true then we are being called from inside
 * the state machine so ignore the result of tls_in_init(s). Otherwise we
 * should not do a renegotiation if tls_in_init(s) is true. Returns 1 if we
 * should do a renegotiation now and sets up the state machine for it. Otherwise
 * returns 0.
 */
int tls3_renegotiate_check(tls *s, int initok)
{
    int ret = 0;

    if (s->s3.renegotiate) {
        if (!RECORD_LAYER_read_pending(&s->rlayer)
            && !RECORD_LAYER_write_pending(&s->rlayer)
            && (initok || !tls_in_init(s))) {
            /*
             * if we are the server, and we have sent a 'RENEGOTIATE'
             * message, we need to set the state machine into the renegotiate
             * state.
             */
            otls_statem_set_renegotiate(s);
            s->s3.renegotiate = 0;
            s->s3.num_renegotiations++;
            s->s3.total_renegotiations++;
            ret = 1;
        }
    }
    return ret;
}

/*
 * If we are using default SHA1+MD5 algorithms switch to new SHA256 PRF and
 * handshake macs if required.
 *
 * If PSK and using SHA384 for TLS < 1.2 switch to default.
 */
long tls_get_algorithm2(tls *s)
{
    long alg2;
    if (s->s3.tmp.new_cipher == NULL)
        return -1;
    alg2 = s->s3.tmp.new_cipher->algorithm2;
    if (s->method->tls3_enc->enc_flags & tls_ENC_FLAG_SHA256_PRF) {
        if (alg2 == (tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF))
            return tls_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256;
    } else if (s->s3.tmp.new_cipher->algorithm_mkey & tls_PSK) {
        if (alg2 == (tls_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384))
            return tls_HANDSHAKE_MAC_DEFAULT | TLS1_PRF;
    }
    return alg2;
}

/*
 * Fill a ClientRandom or ServerRandom field of length len. Returns <= 0 on
 * failure, 1 on success.
 */
int tls_fill_hello_random(tls *s, int server, unsigned char *result, size_t len,
                          DOWNGRADE dgrd)
{
    int send_time = 0, ret;

    if (len < 4)
        return 0;
    if (server)
        send_time = (s->mode & tls_MODE_SEND_SERVERHELLO_TIME) != 0;
    else
        send_time = (s->mode & tls_MODE_SEND_CLIENTHELLO_TIME) != 0;
    if (send_time) {
        unsigned long Time = (unsigned long)time(NULL);
        unsigned char *p = result;

        l2n(Time, p);
        ret = RAND_bytes(p, len - 4);
    } else {
        ret = RAND_bytes(result, len);
    }

    if (ret > 0) {
        if (!otls_assert(sizeof(tls11downgrade) < len)
                || !otls_assert(sizeof(tls12downgrade) < len))
             return 0;
        if (dgrd == DOWNGRADE_TO_1_2)
            memcpy(result + len - sizeof(tls12downgrade), tls12downgrade,
                   sizeof(tls12downgrade));
        else if (dgrd == DOWNGRADE_TO_1_1)
            memcpy(result + len - sizeof(tls11downgrade), tls11downgrade,
                   sizeof(tls11downgrade));
    }

    return ret;
}

int tls_generate_master_secret(tls *s, unsigned char *pms, size_t pmslen,
                               int free_pms)
{
    unsigned long alg_k = s->s3.tmp.new_cipher->algorithm_mkey;
    int ret = 0;

    if (alg_k & tls_PSK) {
#ifndef OPENtls_NO_PSK
        unsigned char *pskpms, *t;
        size_t psklen = s->s3.tmp.psklen;
        size_t pskpmslen;

        /* create PSK premaster_secret */

        /* For plain PSK "other_secret" is psklen zeroes */
        if (alg_k & tls_kPSK)
            pmslen = psklen;

        pskpmslen = 4 + pmslen + psklen;
        pskpms = OPENtls_malloc(pskpmslen);
        if (pskpms == NULL)
            goto err;
        t = pskpms;
        s2n(pmslen, t);
        if (alg_k & tls_kPSK)
            memset(t, 0, pmslen);
        else
            memcpy(t, pms, pmslen);
        t += pmslen;
        s2n(psklen, t);
        memcpy(t, s->s3.tmp.psk, psklen);

        OPENtls_clear_free(s->s3.tmp.psk, psklen);
        s->s3.tmp.psk = NULL;
        if (!s->method->tls3_enc->generate_master_secret(s,
                    s->session->master_key,pskpms, pskpmslen,
                    &s->session->master_key_length)) {
            OPENtls_clear_free(pskpms, pskpmslen);
            /* tlsfatal() already called */
            goto err;
        }
        OPENtls_clear_free(pskpms, pskpmslen);
#else
        /* Should never happen */
        goto err;
#endif
    } else {
        if (!s->method->tls3_enc->generate_master_secret(s,
                s->session->master_key, pms, pmslen,
                &s->session->master_key_length)) {
            /* tlsfatal() already called */
            goto err;
        }
    }

    ret = 1;
 err:
    if (pms) {
        if (free_pms)
            OPENtls_clear_free(pms, pmslen);
        else
            OPENtls_cleanse(pms, pmslen);
    }
    if (s->server == 0)
        s->s3.tmp.pms = NULL;
    return ret;
}

/* Generate a private key from parameters */
EVP_PKEY *tls_generate_pkey(EVP_PKEY *pm)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (pm == NULL)
        return NULL;
    pctx = EVP_PKEY_CTX_new(pm, NULL);
    if (pctx == NULL)
        goto err;
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    err:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/* Generate a private key from a group ID */
#if !defined(OPENtls_NO_DH) || !defined(OPENtls_NO_EC)
EVP_PKEY *tls_generate_pkey_group(tls *s, uint16_t id)
{
    const TLS_GROUP_INFO *ginf = tls1_group_id_lookup(id);
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    uint16_t gtype;
# ifndef OPENtls_NO_DH
    DH *dh = NULL;
# endif

    if (ginf == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_PKEY_GROUP,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }
    gtype = ginf->flags & TLS_GROUP_TYPE;
# ifndef OPENtls_NO_DH
    if (gtype == TLS_GROUP_FFDHE)
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
#  ifndef OPENtls_NO_EC
    else
#  endif
# endif
# ifndef OPENtls_NO_EC
    {
        if (gtype == TLS_GROUP_CURVE_CUSTOM)
            pctx = EVP_PKEY_CTX_new_id(ginf->nid, NULL);
        else
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    }
# endif
    if (pctx == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_PKEY_GROUP,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_PKEY_GROUP,
                 ERR_R_EVP_LIB);
        goto err;
    }
# ifndef OPENtls_NO_DH
    if (gtype == TLS_GROUP_FFDHE) {
        if ((pkey = EVP_PKEY_new()) == NULL
                || (dh = DH_new_by_nid(ginf->nid)) == NULL
                || !EVP_PKEY_assign(pkey, EVP_PKEY_DH, dh)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_PKEY_GROUP,
                    ERR_R_EVP_LIB);
            DH_free(dh);
            EVP_PKEY_free(pkey);
            pkey = NULL;
            goto err;
        }
        if (EVP_PKEY_CTX_set_dh_nid(pctx, ginf->nid) <= 0) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_PKEY_GROUP,
                    ERR_R_EVP_LIB);
            EVP_PKEY_free(pkey);
            pkey = NULL;
            goto err;
        }
    }
#  ifndef OPENtls_NO_EC
    else
#  endif
# endif
# ifndef OPENtls_NO_EC
    {
        if (gtype != TLS_GROUP_CURVE_CUSTOM
                && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, ginf->nid) <= 0) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_PKEY_GROUP,
                     ERR_R_EVP_LIB);
            goto err;
        }
    }
# endif
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_GENERATE_PKEY_GROUP,
                 ERR_R_EVP_LIB);
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

 err:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
#endif

/*
 * Generate parameters from a group ID
 */
EVP_PKEY *tls_generate_param_group(uint16_t id)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    const TLS_GROUP_INFO *ginf = tls1_group_id_lookup(id);
    int pkey_ctx_id;

    if (ginf == NULL)
        goto err;

    if ((ginf->flags & TLS_GROUP_TYPE) == TLS_GROUP_CURVE_CUSTOM) {
        pkey = EVP_PKEY_new();
        if (pkey != NULL && EVP_PKEY_set_type(pkey, ginf->nid))
            return pkey;
        EVP_PKEY_free(pkey);
        return NULL;
    }

    pkey_ctx_id = (ginf->flags & TLS_GROUP_FFDHE)
                        ? EVP_PKEY_DH : EVP_PKEY_EC;
    pctx = EVP_PKEY_CTX_new_id(pkey_ctx_id, NULL);
    if (pctx == NULL)
        goto err;
    if (EVP_PKEY_paramgen_init(pctx) <= 0)
        goto err;
# ifndef OPENtls_NO_DH
    if (ginf->flags & TLS_GROUP_FFDHE) {
        if (EVP_PKEY_CTX_set_dh_nid(pctx, ginf->nid) <= 0)
            goto err;
    }
#  ifndef OPENtls_NO_EC
    else
#  endif
# endif
# ifndef OPENtls_NO_EC
    {
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, ginf->nid) <= 0)
            goto err;
    }
# endif
    if (EVP_PKEY_paramgen(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

 err:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/* Derive secrets for ECDH/DH */
int tls_derive(tls *s, EVP_PKEY *privkey, EVP_PKEY *pubkey, int gensecret)
{
    int rv = 0;
    unsigned char *pms = NULL;
    size_t pmslen = 0;
    EVP_PKEY_CTX *pctx;

    if (privkey == NULL || pubkey == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_DERIVE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pctx = EVP_PKEY_CTX_new(privkey, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_derive_set_peer(pctx, pubkey) <= 0
        || EVP_PKEY_derive(pctx, NULL, &pmslen) <= 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_DERIVE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

#ifndef OPENtls_NO_DH
    if (tls_IS_TLS13(s) &&  EVP_PKEY_id(privkey) == EVP_PKEY_DH)
        EVP_PKEY_CTX_set_dh_pad(pctx, 1);
#endif

    pms = OPENtls_malloc(pmslen);
    if (pms == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_DERIVE,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_derive(pctx, pms, &pmslen) <= 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls_DERIVE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (gensecret) {
        /* tlsfatal() called as appropriate in the below functions */
        if (tls_IS_TLS13(s)) {
            /*
             * If we are resuming then we already generated the early secret
             * when we created the ClientHello, so don't recreate it.
             */
            if (!s->hit)
                rv = tls13_generate_secret(s, tls_handshake_md(s), NULL, NULL,
                                           0,
                                           (unsigned char *)&s->early_secret);
            else
                rv = 1;

            rv = rv && tls13_generate_handshake_secret(s, pms, pmslen);
        } else {
            rv = tls_generate_master_secret(s, pms, pmslen, 0);
        }
    } else {
        /* Save premaster secret */
        s->s3.tmp.pms = pms;
        s->s3.tmp.pmslen = pmslen;
        pms = NULL;
        rv = 1;
    }

 err:
    OPENtls_clear_free(pms, pmslen);
    EVP_PKEY_CTX_free(pctx);
    return rv;
}

#ifndef OPENtls_NO_DH
EVP_PKEY *tls_dh_to_pkey(DH *dh)
{
    EVP_PKEY *ret;
    if (dh == NULL)
        return NULL;
    ret = EVP_PKEY_new();
    if (EVP_PKEY_set1_DH(ret, dh) <= 0) {
        EVP_PKEY_free(ret);
        return NULL;
    }
    return ret;
}
#endif
