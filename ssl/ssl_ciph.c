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
#include <ctype.h>
#include <opentls/objects.h>
#include <opentls/comp.h>
#include <opentls/engine.h>
#include <opentls/crypto.h>
#include <opentls/conf.h>
#include <opentls/trace.h>
#include "internal/nelem.h"
#include "tls_local.h"
#include "internal/thread_once.h"
#include "internal/cryptlib.h"

#define tls_ENC_DES_IDX         0
#define tls_ENC_3DES_IDX        1
#define tls_ENC_RC4_IDX         2
#define tls_ENC_RC2_IDX         3
#define tls_ENC_IDEA_IDX        4
#define tls_ENC_NULL_IDX        5
#define tls_ENC_AES128_IDX      6
#define tls_ENC_AES256_IDX      7
#define tls_ENC_CAMELLIA128_IDX 8
#define tls_ENC_CAMELLIA256_IDX 9
#define tls_ENC_GOST89_IDX      10
#define tls_ENC_SEED_IDX        11
#define tls_ENC_AES128GCM_IDX   12
#define tls_ENC_AES256GCM_IDX   13
#define tls_ENC_AES128CCM_IDX   14
#define tls_ENC_AES256CCM_IDX   15
#define tls_ENC_AES128CCM8_IDX  16
#define tls_ENC_AES256CCM8_IDX  17
#define tls_ENC_GOST8912_IDX    18
#define tls_ENC_CHACHA_IDX      19
#define tls_ENC_ARIA128GCM_IDX  20
#define tls_ENC_ARIA256GCM_IDX  21
#define tls_ENC_NUM_IDX         22

/* NB: make sure indices in these tables match values above */

typedef struct {
    uint32_t mask;
    int nid;
} tls_cipher_table;

/* Table of NIDs for each cipher */
static const tls_cipher_table tls_cipher_table_cipher[tls_ENC_NUM_IDX] = {
    {tls_DES, NID_des_cbc},     /* tls_ENC_DES_IDX 0 */
    {tls_3DES, NID_des_ede3_cbc}, /* tls_ENC_3DES_IDX 1 */
    {tls_RC4, NID_rc4},         /* tls_ENC_RC4_IDX 2 */
    {tls_RC2, NID_rc2_cbc},     /* tls_ENC_RC2_IDX 3 */
    {tls_IDEA, NID_idea_cbc},   /* tls_ENC_IDEA_IDX 4 */
    {tls_eNULL, NID_undef},     /* tls_ENC_NULL_IDX 5 */
    {tls_AES128, NID_aes_128_cbc}, /* tls_ENC_AES128_IDX 6 */
    {tls_AES256, NID_aes_256_cbc}, /* tls_ENC_AES256_IDX 7 */
    {tls_CAMELLIA128, NID_camellia_128_cbc}, /* tls_ENC_CAMELLIA128_IDX 8 */
    {tls_CAMELLIA256, NID_camellia_256_cbc}, /* tls_ENC_CAMELLIA256_IDX 9 */
    {tls_eGOST2814789CNT, NID_gost89_cnt}, /* tls_ENC_GOST89_IDX 10 */
    {tls_SEED, NID_seed_cbc},   /* tls_ENC_SEED_IDX 11 */
    {tls_AES128GCM, NID_aes_128_gcm}, /* tls_ENC_AES128GCM_IDX 12 */
    {tls_AES256GCM, NID_aes_256_gcm}, /* tls_ENC_AES256GCM_IDX 13 */
    {tls_AES128CCM, NID_aes_128_ccm}, /* tls_ENC_AES128CCM_IDX 14 */
    {tls_AES256CCM, NID_aes_256_ccm}, /* tls_ENC_AES256CCM_IDX 15 */
    {tls_AES128CCM8, NID_aes_128_ccm}, /* tls_ENC_AES128CCM8_IDX 16 */
    {tls_AES256CCM8, NID_aes_256_ccm}, /* tls_ENC_AES256CCM8_IDX 17 */
    {tls_eGOST2814789CNT12, NID_gost89_cnt_12}, /* tls_ENC_GOST8912_IDX 18 */
    {tls_CHACHA20POLY1305, NID_chacha20_poly1305}, /* tls_ENC_CHACHA_IDX 19 */
    {tls_ARIA128GCM, NID_aria_128_gcm}, /* tls_ENC_ARIA128GCM_IDX 20 */
    {tls_ARIA256GCM, NID_aria_256_gcm}, /* tls_ENC_ARIA256GCM_IDX 21 */
};

static const EVP_CIPHER *tls_cipher_methods[tls_ENC_NUM_IDX];

#define tls_COMP_NULL_IDX       0
#define tls_COMP_ZLIB_IDX       1
#define tls_COMP_NUM_IDX        2

static STACK_OF(tls_COMP) *tls_comp_methods = NULL;

#ifndef OPENtls_NO_COMP
static CRYPTO_ONCE tls_load_builtin_comp_once = CRYPTO_ONCE_STATIC_INIT;
#endif

/*
 * Constant tls_MAX_DIGEST equal to size of digests array should be defined
 * in the tls_local.h
 */

#define tls_MD_NUM_IDX  tls_MAX_DIGEST

/* NB: make sure indices in this table matches values above */
static const tls_cipher_table tls_cipher_table_mac[tls_MD_NUM_IDX] = {
    {tls_MD5, NID_md5},         /* tls_MD_MD5_IDX 0 */
    {tls_SHA1, NID_sha1},       /* tls_MD_SHA1_IDX 1 */
    {tls_GOST94, NID_id_GostR3411_94}, /* tls_MD_GOST94_IDX 2 */
    {tls_GOST89MAC, NID_id_Gost28147_89_MAC}, /* tls_MD_GOST89MAC_IDX 3 */
    {tls_SHA256, NID_sha256},   /* tls_MD_SHA256_IDX 4 */
    {tls_SHA384, NID_sha384},   /* tls_MD_SHA384_IDX 5 */
    {tls_GOST12_256, NID_id_GostR3411_2012_256}, /* tls_MD_GOST12_256_IDX 6 */
    {tls_GOST89MAC12, NID_gost_mac_12}, /* tls_MD_GOST89MAC12_IDX 7 */
    {tls_GOST12_512, NID_id_GostR3411_2012_512}, /* tls_MD_GOST12_512_IDX 8 */
    {0, NID_md5_sha1},          /* tls_MD_MD5_SHA1_IDX 9 */
    {0, NID_sha224},            /* tls_MD_SHA224_IDX 10 */
    {0, NID_sha512}             /* tls_MD_SHA512_IDX 11 */
};

static const EVP_MD *tls_digest_methods[tls_MD_NUM_IDX] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* *INDENT-OFF* */
static const tls_cipher_table tls_cipher_table_kx[] = {
    {tls_kRSA,      NID_kx_rsa},
    {tls_kECDHE,    NID_kx_ecdhe},
    {tls_kDHE,      NID_kx_dhe},
    {tls_kECDHEPSK, NID_kx_ecdhe_psk},
    {tls_kDHEPSK,   NID_kx_dhe_psk},
    {tls_kRSAPSK,   NID_kx_rsa_psk},
    {tls_kPSK,      NID_kx_psk},
    {tls_kSRP,      NID_kx_srp},
    {tls_kGOST,     NID_kx_gost},
    {tls_kANY,      NID_kx_any}
};

static const tls_cipher_table tls_cipher_table_auth[] = {
    {tls_aRSA,    NID_auth_rsa},
    {tls_aECDSA,  NID_auth_ecdsa},
    {tls_aPSK,    NID_auth_psk},
    {tls_aDSS,    NID_auth_dss},
    {tls_aGOST01, NID_auth_gost01},
    {tls_aGOST12, NID_auth_gost12},
    {tls_aSRP,    NID_auth_srp},
    {tls_aNULL,   NID_auth_null},
    {tls_aANY,    NID_auth_any}
};
/* *INDENT-ON* */

/* Utility function for table lookup */
static int tls_cipher_info_find(const tls_cipher_table * table,
                                size_t table_cnt, uint32_t mask)
{
    size_t i;
    for (i = 0; i < table_cnt; i++, table++) {
        if (table->mask == mask)
            return (int)i;
    }
    return -1;
}

#define tls_cipher_info_lookup(table, x) \
    tls_cipher_info_find(table, Otls_NELEM(table), x)

/*
 * PKEY_TYPE for GOST89MAC is known in advance, but, because implementation
 * is engine-provided, we'll fill it only if corresponding EVP_PKEY_METHOD is
 * found
 */
static int tls_mac_pkey_id[tls_MD_NUM_IDX] = {
    /* MD5, SHA, GOST94, MAC89 */
    EVP_PKEY_HMAC, EVP_PKEY_HMAC, EVP_PKEY_HMAC, NID_undef,
    /* SHA256, SHA384, GOST2012_256, MAC89-12 */
    EVP_PKEY_HMAC, EVP_PKEY_HMAC, EVP_PKEY_HMAC, NID_undef,
    /* GOST2012_512 */
    EVP_PKEY_HMAC,
    /* MD5/SHA1, SHA224, SHA512 */
    NID_undef, NID_undef, NID_undef
};

static size_t tls_mac_secret_size[tls_MD_NUM_IDX];

#define CIPHER_ADD      1
#define CIPHER_KILL     2
#define CIPHER_DEL      3
#define CIPHER_ORD      4
#define CIPHER_SPECIAL  5
/*
 * Bump the ciphers to the top of the list.
 * This rule isn't currently supported by the public cipherstring API.
 */
#define CIPHER_BUMP     6

typedef struct cipher_order_st {
    const tls_CIPHER *cipher;
    int active;
    int dead;
    struct cipher_order_st *next, *prev;
} CIPHER_ORDER;

static const tls_CIPHER cipher_aliases[] = {
    /* "ALL" doesn't include eNULL (must be specifically enabled) */
    {0, tls_TXT_ALL, NULL, 0, 0, 0, ~tls_eNULL},
    /* "COMPLEMENTOFALL" */
    {0, tls_TXT_CMPALL, NULL, 0, 0, 0, tls_eNULL},

    /*
     * "COMPLEMENTOFDEFAULT" (does *not* include ciphersuites not found in
     * ALL!)
     */
    {0, tls_TXT_CMPDEF, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, tls_NOT_DEFAULT},

    /*
     * key exchange aliases (some of those using only a single bit here
     * combine multiple key exchange algs according to the RFCs, e.g. kDHE
     * combines DHE_DSS and DHE_RSA)
     */
    {0, tls_TXT_kRSA, NULL, 0, tls_kRSA},

    {0, tls_TXT_kEDH, NULL, 0, tls_kDHE},
    {0, tls_TXT_kDHE, NULL, 0, tls_kDHE},
    {0, tls_TXT_DH, NULL, 0, tls_kDHE},

    {0, tls_TXT_kEECDH, NULL, 0, tls_kECDHE},
    {0, tls_TXT_kECDHE, NULL, 0, tls_kECDHE},
    {0, tls_TXT_ECDH, NULL, 0, tls_kECDHE},

    {0, tls_TXT_kPSK, NULL, 0, tls_kPSK},
    {0, tls_TXT_kRSAPSK, NULL, 0, tls_kRSAPSK},
    {0, tls_TXT_kECDHEPSK, NULL, 0, tls_kECDHEPSK},
    {0, tls_TXT_kDHEPSK, NULL, 0, tls_kDHEPSK},
    {0, tls_TXT_kSRP, NULL, 0, tls_kSRP},
    {0, tls_TXT_kGOST, NULL, 0, tls_kGOST},

    /* server authentication aliases */
    {0, tls_TXT_aRSA, NULL, 0, 0, tls_aRSA},
    {0, tls_TXT_aDSS, NULL, 0, 0, tls_aDSS},
    {0, tls_TXT_DSS, NULL, 0, 0, tls_aDSS},
    {0, tls_TXT_aNULL, NULL, 0, 0, tls_aNULL},
    {0, tls_TXT_aECDSA, NULL, 0, 0, tls_aECDSA},
    {0, tls_TXT_ECDSA, NULL, 0, 0, tls_aECDSA},
    {0, tls_TXT_aPSK, NULL, 0, 0, tls_aPSK},
    {0, tls_TXT_aGOST01, NULL, 0, 0, tls_aGOST01},
    {0, tls_TXT_aGOST12, NULL, 0, 0, tls_aGOST12},
    {0, tls_TXT_aGOST, NULL, 0, 0, tls_aGOST01 | tls_aGOST12},
    {0, tls_TXT_aSRP, NULL, 0, 0, tls_aSRP},

    /* aliases combining key exchange and server authentication */
    {0, tls_TXT_EDH, NULL, 0, tls_kDHE, ~tls_aNULL},
    {0, tls_TXT_DHE, NULL, 0, tls_kDHE, ~tls_aNULL},
    {0, tls_TXT_EECDH, NULL, 0, tls_kECDHE, ~tls_aNULL},
    {0, tls_TXT_ECDHE, NULL, 0, tls_kECDHE, ~tls_aNULL},
    {0, tls_TXT_NULL, NULL, 0, 0, 0, tls_eNULL},
    {0, tls_TXT_RSA, NULL, 0, tls_kRSA, tls_aRSA},
    {0, tls_TXT_ADH, NULL, 0, tls_kDHE, tls_aNULL},
    {0, tls_TXT_AECDH, NULL, 0, tls_kECDHE, tls_aNULL},
    {0, tls_TXT_PSK, NULL, 0, tls_PSK},
    {0, tls_TXT_SRP, NULL, 0, tls_kSRP},

    /* symmetric encryption aliases */
    {0, tls_TXT_3DES, NULL, 0, 0, 0, tls_3DES},
    {0, tls_TXT_RC4, NULL, 0, 0, 0, tls_RC4},
    {0, tls_TXT_RC2, NULL, 0, 0, 0, tls_RC2},
    {0, tls_TXT_IDEA, NULL, 0, 0, 0, tls_IDEA},
    {0, tls_TXT_SEED, NULL, 0, 0, 0, tls_SEED},
    {0, tls_TXT_eNULL, NULL, 0, 0, 0, tls_eNULL},
    {0, tls_TXT_GOST, NULL, 0, 0, 0, tls_eGOST2814789CNT | tls_eGOST2814789CNT12},
    {0, tls_TXT_AES128, NULL, 0, 0, 0,
     tls_AES128 | tls_AES128GCM | tls_AES128CCM | tls_AES128CCM8},
    {0, tls_TXT_AES256, NULL, 0, 0, 0,
     tls_AES256 | tls_AES256GCM | tls_AES256CCM | tls_AES256CCM8},
    {0, tls_TXT_AES, NULL, 0, 0, 0, tls_AES},
    {0, tls_TXT_AES_GCM, NULL, 0, 0, 0, tls_AES128GCM | tls_AES256GCM},
    {0, tls_TXT_AES_CCM, NULL, 0, 0, 0,
     tls_AES128CCM | tls_AES256CCM | tls_AES128CCM8 | tls_AES256CCM8},
    {0, tls_TXT_AES_CCM_8, NULL, 0, 0, 0, tls_AES128CCM8 | tls_AES256CCM8},
    {0, tls_TXT_CAMELLIA128, NULL, 0, 0, 0, tls_CAMELLIA128},
    {0, tls_TXT_CAMELLIA256, NULL, 0, 0, 0, tls_CAMELLIA256},
    {0, tls_TXT_CAMELLIA, NULL, 0, 0, 0, tls_CAMELLIA},
    {0, tls_TXT_CHACHA20, NULL, 0, 0, 0, tls_CHACHA20},

    {0, tls_TXT_ARIA, NULL, 0, 0, 0, tls_ARIA},
    {0, tls_TXT_ARIA_GCM, NULL, 0, 0, 0, tls_ARIA128GCM | tls_ARIA256GCM},
    {0, tls_TXT_ARIA128, NULL, 0, 0, 0, tls_ARIA128GCM},
    {0, tls_TXT_ARIA256, NULL, 0, 0, 0, tls_ARIA256GCM},

    /* MAC aliases */
    {0, tls_TXT_MD5, NULL, 0, 0, 0, 0, tls_MD5},
    {0, tls_TXT_SHA1, NULL, 0, 0, 0, 0, tls_SHA1},
    {0, tls_TXT_SHA, NULL, 0, 0, 0, 0, tls_SHA1},
    {0, tls_TXT_GOST94, NULL, 0, 0, 0, 0, tls_GOST94},
    {0, tls_TXT_GOST89MAC, NULL, 0, 0, 0, 0, tls_GOST89MAC | tls_GOST89MAC12},
    {0, tls_TXT_SHA256, NULL, 0, 0, 0, 0, tls_SHA256},
    {0, tls_TXT_SHA384, NULL, 0, 0, 0, 0, tls_SHA384},
    {0, tls_TXT_GOST12, NULL, 0, 0, 0, 0, tls_GOST12_256},

    /* protocol version aliases */
    {0, tls_TXT_tlsV3, NULL, 0, 0, 0, 0, 0, tls3_VERSION},
    {0, tls_TXT_TLSV1, NULL, 0, 0, 0, 0, 0, TLS1_VERSION},
    {0, "TLSv1.0", NULL, 0, 0, 0, 0, 0, TLS1_VERSION},
    {0, tls_TXT_TLSV1_2, NULL, 0, 0, 0, 0, 0, TLS1_2_VERSION},

    /* strength classes */
    {0, tls_TXT_LOW, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, tls_LOW},
    {0, tls_TXT_MEDIUM, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, tls_MEDIUM},
    {0, tls_TXT_HIGH, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, tls_HIGH},
    /* FIPS 140-2 approved ciphersuite */
    {0, tls_TXT_FIPS, NULL, 0, 0, 0, ~tls_eNULL, 0, 0, 0, 0, 0, tls_FIPS},

    /* "EDH-" aliases to "DHE-" labels (for backward compatibility) */
    {0, tls3_TXT_EDH_DSS_DES_192_CBC3_SHA, NULL, 0,
     tls_kDHE, tls_aDSS, tls_3DES, tls_SHA1, 0, 0, 0, 0, tls_HIGH | tls_FIPS},
    {0, tls3_TXT_EDH_RSA_DES_192_CBC3_SHA, NULL, 0,
     tls_kDHE, tls_aRSA, tls_3DES, tls_SHA1, 0, 0, 0, 0, tls_HIGH | tls_FIPS},

};

/*
 * Search for public key algorithm with given name and return its pkey_id if
 * it is available. Otherwise return 0
 */
#ifdef OPENtls_NO_ENGINE

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(NULL, pkey_name, -1);
    if (ameth && EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                         ameth) > 0)
        return pkey_id;
    return 0;
}

#else

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(&tmpeng, pkey_name, -1);
    if (ameth) {
        if (EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                    ameth) <= 0)
            pkey_id = 0;
    }
    ENGINE_finish(tmpeng);
    return pkey_id;
}

#endif

/* masks of disabled algorithms */
static uint32_t disabled_enc_mask;
static uint32_t disabled_mac_mask;
static uint32_t disabled_mkey_mask;
static uint32_t disabled_auth_mask;

int tls_load_ciphers(void)
{
    size_t i;
    const tls_cipher_table *t;

    disabled_enc_mask = 0;
    tls_sort_cipher_list();
    for (i = 0, t = tls_cipher_table_cipher; i < tls_ENC_NUM_IDX; i++, t++) {
        if (t->nid == NID_undef) {
            tls_cipher_methods[i] = NULL;
        } else {
            const EVP_CIPHER *cipher = EVP_get_cipherbynid(t->nid);
            tls_cipher_methods[i] = cipher;
            if (cipher == NULL)
                disabled_enc_mask |= t->mask;
        }
    }
    disabled_mac_mask = 0;
    for (i = 0, t = tls_cipher_table_mac; i < tls_MD_NUM_IDX; i++, t++) {
        const EVP_MD *md = EVP_get_digestbynid(t->nid);
        tls_digest_methods[i] = md;
        if (md == NULL) {
            disabled_mac_mask |= t->mask;
        } else {
            int tmpsize = EVP_MD_size(md);
            if (!otls_assert(tmpsize >= 0))
                return 0;
            tls_mac_secret_size[i] = tmpsize;
        }
    }
    /* Make sure we can access MD5 and SHA1 */
    if (!otls_assert(tls_digest_methods[tls_MD_MD5_IDX] != NULL))
        return 0;
    if (!otls_assert(tls_digest_methods[tls_MD_SHA1_IDX] != NULL))
        return 0;

    disabled_mkey_mask = 0;
    disabled_auth_mask = 0;

#ifdef OPENtls_NO_RSA
    disabled_mkey_mask |= tls_kRSA | tls_kRSAPSK;
    disabled_auth_mask |= tls_aRSA;
#endif
#ifdef OPENtls_NO_DSA
    disabled_auth_mask |= tls_aDSS;
#endif
#ifdef OPENtls_NO_DH
    disabled_mkey_mask |= tls_kDHE | tls_kDHEPSK;
#endif
#ifdef OPENtls_NO_EC
    disabled_mkey_mask |= tls_kECDHE | tls_kECDHEPSK;
    disabled_auth_mask |= tls_aECDSA;
#endif
#ifdef OPENtls_NO_PSK
    disabled_mkey_mask |= tls_PSK;
    disabled_auth_mask |= tls_aPSK;
#endif
#ifdef OPENtls_NO_SRP
    disabled_mkey_mask |= tls_kSRP;
#endif

    /*
     * Check for presence of GOST 34.10 algorithms, and if they are not
     * present, disable appropriate auth and key exchange
     */
    tls_mac_pkey_id[tls_MD_GOST89MAC_IDX] = get_optional_pkey_id("gost-mac");
    if (tls_mac_pkey_id[tls_MD_GOST89MAC_IDX])
        tls_mac_secret_size[tls_MD_GOST89MAC_IDX] = 32;
    else
        disabled_mac_mask |= tls_GOST89MAC;

    tls_mac_pkey_id[tls_MD_GOST89MAC12_IDX] =
        get_optional_pkey_id("gost-mac-12");
    if (tls_mac_pkey_id[tls_MD_GOST89MAC12_IDX])
        tls_mac_secret_size[tls_MD_GOST89MAC12_IDX] = 32;
    else
        disabled_mac_mask |= tls_GOST89MAC12;

    if (!get_optional_pkey_id("gost2001"))
        disabled_auth_mask |= tls_aGOST01 | tls_aGOST12;
    if (!get_optional_pkey_id("gost2012_256"))
        disabled_auth_mask |= tls_aGOST12;
    if (!get_optional_pkey_id("gost2012_512"))
        disabled_auth_mask |= tls_aGOST12;
    /*
     * Disable GOST key exchange if no GOST signature algs are available *
     */
    if ((disabled_auth_mask & (tls_aGOST01 | tls_aGOST12)) ==
        (tls_aGOST01 | tls_aGOST12))
        disabled_mkey_mask |= tls_kGOST;

    return 1;
}

#ifndef OPENtls_NO_COMP

static int sk_comp_cmp(const tls_COMP *const *a, const tls_COMP *const *b)
{
    return ((*a)->id - (*b)->id);
}

DEFINE_RUN_ONCE_STATIC(do_load_builtin_compressions)
{
    tls_COMP *comp = NULL;
    COMP_METHOD *method = COMP_zlib();

    tls_comp_methods = sk_tls_COMP_new(sk_comp_cmp);

    if (COMP_get_type(method) != NID_undef && tls_comp_methods != NULL) {
        comp = OPENtls_malloc(sizeof(*comp));
        if (comp != NULL) {
            comp->method = method;
            comp->id = tls_COMP_ZLIB_IDX;
            comp->name = COMP_get_name(method);
            sk_tls_COMP_push(tls_comp_methods, comp);
            sk_tls_COMP_sort(tls_comp_methods);
        }
    }
    return 1;
}

static int load_builtin_compressions(void)
{
    return RUN_ONCE(&tls_load_builtin_comp_once, do_load_builtin_compressions);
}
#endif

int tls_cipher_get_evp(const tls_SESSION *s, const EVP_CIPHER **enc,
                       const EVP_MD **md, int *mac_pkey_type,
                       size_t *mac_secret_size, tls_COMP **comp, int use_etm)
{
    int i;
    const tls_CIPHER *c;

    c = s->cipher;
    if (c == NULL)
        return 0;
    if (comp != NULL) {
        tls_COMP ctmp;
#ifndef OPENtls_NO_COMP
        if (!load_builtin_compressions()) {
            /*
             * Currently don't care, since a failure only means that
             * tls_comp_methods is NULL, which is perfectly OK
             */
        }
#endif
        *comp = NULL;
        ctmp.id = s->compress_meth;
        if (tls_comp_methods != NULL) {
            i = sk_tls_COMP_find(tls_comp_methods, &ctmp);
            *comp = sk_tls_COMP_value(tls_comp_methods, i);
        }
        /* If were only interested in comp then return success */
        if ((enc == NULL) && (md == NULL))
            return 1;
    }

    if ((enc == NULL) || (md == NULL))
        return 0;

    i = tls_cipher_info_lookup(tls_cipher_table_cipher, c->algorithm_enc);

    if (i == -1) {
        *enc = NULL;
    } else {
        if (i == tls_ENC_NULL_IDX)
            *enc = EVP_enc_null();
        else
            *enc = tls_cipher_methods[i];
    }

    i = tls_cipher_info_lookup(tls_cipher_table_mac, c->algorithm_mac);
    if (i == -1) {
        *md = NULL;
        if (mac_pkey_type != NULL)
            *mac_pkey_type = NID_undef;
        if (mac_secret_size != NULL)
            *mac_secret_size = 0;
        if (c->algorithm_mac == tls_AEAD)
            mac_pkey_type = NULL;
    } else {
        *md = tls_digest_methods[i];
        if (mac_pkey_type != NULL)
            *mac_pkey_type = tls_mac_pkey_id[i];
        if (mac_secret_size != NULL)
            *mac_secret_size = tls_mac_secret_size[i];
    }

    if ((*enc != NULL) &&
        (*md != NULL || (EVP_CIPHER_flags(*enc) & EVP_CIPH_FLAG_AEAD_CIPHER))
        && (!mac_pkey_type || *mac_pkey_type != NID_undef)) {
        const EVP_CIPHER *evp;

        if (use_etm)
            return 1;

        if (s->tls_version >> 8 != TLS1_VERSION_MAJOR ||
            s->tls_version < TLS1_VERSION)
            return 1;

        if (c->algorithm_enc == tls_RC4 &&
            c->algorithm_mac == tls_MD5 &&
            (evp = EVP_get_cipherbyname("RC4-HMAC-MD5")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == tls_AES128 &&
                 c->algorithm_mac == tls_SHA1 &&
                 (evp = EVP_get_cipherbyname("AES-128-CBC-HMAC-SHA1")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == tls_AES256 &&
                 c->algorithm_mac == tls_SHA1 &&
                 (evp = EVP_get_cipherbyname("AES-256-CBC-HMAC-SHA1")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == tls_AES128 &&
                 c->algorithm_mac == tls_SHA256 &&
                 (evp = EVP_get_cipherbyname("AES-128-CBC-HMAC-SHA256")))
            *enc = evp, *md = NULL;
        else if (c->algorithm_enc == tls_AES256 &&
                 c->algorithm_mac == tls_SHA256 &&
                 (evp = EVP_get_cipherbyname("AES-256-CBC-HMAC-SHA256")))
            *enc = evp, *md = NULL;
        return 1;
    } else {
        return 0;
    }
}

const EVP_MD *tls_md(int idx)
{
    idx &= tls_HANDSHAKE_MAC_MASK;
    if (idx < 0 || idx >= tls_MD_NUM_IDX)
        return NULL;
    return tls_digest_methods[idx];
}

const EVP_MD *tls_handshake_md(tls *s)
{
    return tls_md(tls_get_algorithm2(s));
}

const EVP_MD *tls_prf_md(tls *s)
{
    return tls_md(tls_get_algorithm2(s) >> TLS1_PRF_DGST_SHIFT);
}

#define ITEM_SEP(a) \
        (((a) == ':') || ((a) == ' ') || ((a) == ';') || ((a) == ','))

static void ll_append_tail(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *tail)
        return;
    if (curr == *head)
        *head = curr->next;
    if (curr->prev != NULL)
        curr->prev->next = curr->next;
    if (curr->next != NULL)
        curr->next->prev = curr->prev;
    (*tail)->next = curr;
    curr->prev = *tail;
    curr->next = NULL;
    *tail = curr;
}

static void ll_append_head(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *head)
        return;
    if (curr == *tail)
        *tail = curr->prev;
    if (curr->next != NULL)
        curr->next->prev = curr->prev;
    if (curr->prev != NULL)
        curr->prev->next = curr->next;
    (*head)->prev = curr;
    curr->next = *head;
    curr->prev = NULL;
    *head = curr;
}

static void tls_cipher_collect_ciphers(const tls_METHOD *tls_method,
                                       int num_of_ciphers,
                                       uint32_t disabled_mkey,
                                       uint32_t disabled_auth,
                                       uint32_t disabled_enc,
                                       uint32_t disabled_mac,
                                       CIPHER_ORDER *co_list,
                                       CIPHER_ORDER **head_p,
                                       CIPHER_ORDER **tail_p)
{
    int i, co_list_num;
    const tls_CIPHER *c;

    /*
     * We have num_of_ciphers descriptions compiled in, depending on the
     * method selected (tlsv3, TLSv1 etc).
     * These will later be sorted in a linked list with at most num
     * entries.
     */

    /* Get the initial list of ciphers */
    co_list_num = 0;            /* actual count of ciphers */
    for (i = 0; i < num_of_ciphers; i++) {
        c = tls_method->get_cipher(i);
        /* drop those that use any of that is not available */
        if (c == NULL || !c->valid)
            continue;
        if ((c->algorithm_mkey & disabled_mkey) ||
            (c->algorithm_auth & disabled_auth) ||
            (c->algorithm_enc & disabled_enc) ||
            (c->algorithm_mac & disabled_mac))
            continue;
        if (((tls_method->tls3_enc->enc_flags & tls_ENC_FLAG_DTLS) == 0) &&
            c->min_tls == 0)
            continue;
        if (((tls_method->tls3_enc->enc_flags & tls_ENC_FLAG_DTLS) != 0) &&
            c->min_dtls == 0)
            continue;

        co_list[co_list_num].cipher = c;
        co_list[co_list_num].next = NULL;
        co_list[co_list_num].prev = NULL;
        co_list[co_list_num].active = 0;
        co_list_num++;
    }

    /*
     * Prepare linked list from list entries
     */
    if (co_list_num > 0) {
        co_list[0].prev = NULL;

        if (co_list_num > 1) {
            co_list[0].next = &co_list[1];

            for (i = 1; i < co_list_num - 1; i++) {
                co_list[i].prev = &co_list[i - 1];
                co_list[i].next = &co_list[i + 1];
            }

            co_list[co_list_num - 1].prev = &co_list[co_list_num - 2];
        }

        co_list[co_list_num - 1].next = NULL;

        *head_p = &co_list[0];
        *tail_p = &co_list[co_list_num - 1];
    }
}

static void tls_cipher_collect_aliases(const tls_CIPHER **ca_list,
                                       int num_of_group_aliases,
                                       uint32_t disabled_mkey,
                                       uint32_t disabled_auth,
                                       uint32_t disabled_enc,
                                       uint32_t disabled_mac,
                                       CIPHER_ORDER *head)
{
    CIPHER_ORDER *ciph_curr;
    const tls_CIPHER **ca_curr;
    int i;
    uint32_t mask_mkey = ~disabled_mkey;
    uint32_t mask_auth = ~disabled_auth;
    uint32_t mask_enc = ~disabled_enc;
    uint32_t mask_mac = ~disabled_mac;

    /*
     * First, add the real ciphers as already collected
     */
    ciph_curr = head;
    ca_curr = ca_list;
    while (ciph_curr != NULL) {
        *ca_curr = ciph_curr->cipher;
        ca_curr++;
        ciph_curr = ciph_curr->next;
    }

    /*
     * Now we add the available ones from the cipher_aliases[] table.
     * They represent either one or more algorithms, some of which
     * in any affected category must be supported (set in enabled_mask),
     * or represent a cipher strength value (will be added in any case because algorithms=0).
     */
    for (i = 0; i < num_of_group_aliases; i++) {
        uint32_t algorithm_mkey = cipher_aliases[i].algorithm_mkey;
        uint32_t algorithm_auth = cipher_aliases[i].algorithm_auth;
        uint32_t algorithm_enc = cipher_aliases[i].algorithm_enc;
        uint32_t algorithm_mac = cipher_aliases[i].algorithm_mac;

        if (algorithm_mkey)
            if ((algorithm_mkey & mask_mkey) == 0)
                continue;

        if (algorithm_auth)
            if ((algorithm_auth & mask_auth) == 0)
                continue;

        if (algorithm_enc)
            if ((algorithm_enc & mask_enc) == 0)
                continue;

        if (algorithm_mac)
            if ((algorithm_mac & mask_mac) == 0)
                continue;

        *ca_curr = (tls_CIPHER *)(cipher_aliases + i);
        ca_curr++;
    }

    *ca_curr = NULL;            /* end of list */
}

static void tls_cipher_apply_rule(uint32_t cipher_id, uint32_t alg_mkey,
                                  uint32_t alg_auth, uint32_t alg_enc,
                                  uint32_t alg_mac, int min_tls,
                                  uint32_t algo_strength, int rule,
                                  int32_t strength_bits, CIPHER_ORDER **head_p,
                                  CIPHER_ORDER **tail_p)
{
    CIPHER_ORDER *head, *tail, *curr, *next, *last;
    const tls_CIPHER *cp;
    int reverse = 0;

    Otls_TRACE_BEGIN(TLS_CIPHER){
        BIO_printf(trc_out,
                   "Applying rule %d with %08x/%08x/%08x/%08x/%08x %08x (%d)\n",
                   rule, alg_mkey, alg_auth, alg_enc, alg_mac, min_tls,
                   algo_strength, strength_bits);
    }

    if (rule == CIPHER_DEL || rule == CIPHER_BUMP)
        reverse = 1;            /* needed to maintain sorting between currently
                                 * deleted ciphers */

    head = *head_p;
    tail = *tail_p;

    if (reverse) {
        next = tail;
        last = head;
    } else {
        next = head;
        last = tail;
    }

    curr = NULL;
    for (;;) {
        if (curr == last)
            break;

        curr = next;

        if (curr == NULL)
            break;

        next = reverse ? curr->prev : curr->next;

        cp = curr->cipher;

        /*
         * Selection criteria is either the value of strength_bits
         * or the algorithms used.
         */
        if (strength_bits >= 0) {
            if (strength_bits != cp->strength_bits)
                continue;
        } else {
            if (trc_out != NULL) {
                BIO_printf(trc_out,
                           "\nName: %s:"
                           "\nAlgo = %08x/%08x/%08x/%08x/%08x Algo_strength = %08x\n",
                           cp->name, cp->algorithm_mkey, cp->algorithm_auth,
                           cp->algorithm_enc, cp->algorithm_mac, cp->min_tls,
                           cp->algo_strength);
            }
            if (cipher_id != 0 && (cipher_id != cp->id))
                continue;
            if (alg_mkey && !(alg_mkey & cp->algorithm_mkey))
                continue;
            if (alg_auth && !(alg_auth & cp->algorithm_auth))
                continue;
            if (alg_enc && !(alg_enc & cp->algorithm_enc))
                continue;
            if (alg_mac && !(alg_mac & cp->algorithm_mac))
                continue;
            if (min_tls && (min_tls != cp->min_tls))
                continue;
            if ((algo_strength & tls_STRONG_MASK)
                && !(algo_strength & tls_STRONG_MASK & cp->algo_strength))
                continue;
            if ((algo_strength & tls_DEFAULT_MASK)
                && !(algo_strength & tls_DEFAULT_MASK & cp->algo_strength))
                continue;
        }

        if (trc_out != NULL)
            BIO_printf(trc_out, "Action = %d\n", rule);

        /* add the cipher if it has not been added yet. */
        if (rule == CIPHER_ADD) {
            /* reverse == 0 */
            if (!curr->active) {
                ll_append_tail(&head, curr, &tail);
                curr->active = 1;
            }
        }
        /* Move the added cipher to this location */
        else if (rule == CIPHER_ORD) {
            /* reverse == 0 */
            if (curr->active) {
                ll_append_tail(&head, curr, &tail);
            }
        } else if (rule == CIPHER_DEL) {
            /* reverse == 1 */
            if (curr->active) {
                /*
                 * most recently deleted ciphersuites get best positions for
                 * any future CIPHER_ADD (note that the CIPHER_DEL loop works
                 * in reverse to maintain the order)
                 */
                ll_append_head(&head, curr, &tail);
                curr->active = 0;
            }
        } else if (rule == CIPHER_BUMP) {
            if (curr->active)
                ll_append_head(&head, curr, &tail);
        } else if (rule == CIPHER_KILL) {
            /* reverse == 0 */
            if (head == curr)
                head = curr->next;
            else
                curr->prev->next = curr->next;
            if (tail == curr)
                tail = curr->prev;
            curr->active = 0;
            if (curr->next != NULL)
                curr->next->prev = curr->prev;
            if (curr->prev != NULL)
                curr->prev->next = curr->next;
            curr->next = NULL;
            curr->prev = NULL;
        }
    }

    *head_p = head;
    *tail_p = tail;

    Otls_TRACE_END(TLS_CIPHER);
}

static int tls_cipher_strength_sort(CIPHER_ORDER **head_p,
                                    CIPHER_ORDER **tail_p)
{
    int32_t max_strength_bits;
    int i, *number_uses;
    CIPHER_ORDER *curr;

    /*
     * This routine sorts the ciphers with descending strength. The sorting
     * must keep the pre-sorted sequence, so we apply the normal sorting
     * routine as '+' movement to the end of the list.
     */
    max_strength_bits = 0;
    curr = *head_p;
    while (curr != NULL) {
        if (curr->active && (curr->cipher->strength_bits > max_strength_bits))
            max_strength_bits = curr->cipher->strength_bits;
        curr = curr->next;
    }

    number_uses = OPENtls_zalloc(sizeof(int) * (max_strength_bits + 1));
    if (number_uses == NULL) {
        tlserr(tls_F_tls_CIPHER_STRENGTH_SORT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /*
     * Now find the strength_bits values actually used
     */
    curr = *head_p;
    while (curr != NULL) {
        if (curr->active)
            number_uses[curr->cipher->strength_bits]++;
        curr = curr->next;
    }
    /*
     * Go through the list of used strength_bits values in descending
     * order.
     */
    for (i = max_strength_bits; i >= 0; i--)
        if (number_uses[i] > 0)
            tls_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ORD, i, head_p,
                                  tail_p);

    OPENtls_free(number_uses);
    return 1;
}

static int tls_cipher_process_rulestr(const char *rule_str,
                                      CIPHER_ORDER **head_p,
                                      CIPHER_ORDER **tail_p,
                                      const tls_CIPHER **ca_list, CERT *c)
{
    uint32_t alg_mkey, alg_auth, alg_enc, alg_mac, algo_strength;
    int min_tls;
    const char *l, *buf;
    int j, multi, found, rule, retval, ok, buflen;
    uint32_t cipher_id = 0;
    char ch;

    retval = 1;
    l = rule_str;
    for ( ; ; ) {
        ch = *l;

        if (ch == '\0')
            break;              /* done */
        if (ch == '-') {
            rule = CIPHER_DEL;
            l++;
        } else if (ch == '+') {
            rule = CIPHER_ORD;
            l++;
        } else if (ch == '!') {
            rule = CIPHER_KILL;
            l++;
        } else if (ch == '@') {
            rule = CIPHER_SPECIAL;
            l++;
        } else {
            rule = CIPHER_ADD;
        }

        if (ITEM_SEP(ch)) {
            l++;
            continue;
        }

        alg_mkey = 0;
        alg_auth = 0;
        alg_enc = 0;
        alg_mac = 0;
        min_tls = 0;
        algo_strength = 0;

        for (;;) {
            ch = *l;
            buf = l;
            buflen = 0;
#ifndef CHARSET_EBCDIC
            while (((ch >= 'A') && (ch <= 'Z')) ||
                   ((ch >= '0') && (ch <= '9')) ||
                   ((ch >= 'a') && (ch <= 'z')) ||
                   (ch == '-') || (ch == '.') || (ch == '='))
#else
            while (isalnum((unsigned char)ch) || (ch == '-') || (ch == '.')
                   || (ch == '='))
#endif
            {
                ch = *(++l);
                buflen++;
            }

            if (buflen == 0) {
                /*
                 * We hit something we cannot deal with,
                 * it is no command or separator nor
                 * alphanumeric, so we call this an error.
                 */
                tlserr(tls_F_tls_CIPHER_PROCESS_RULESTR, tls_R_INVALID_COMMAND);
                retval = found = 0;
                l++;
                break;
            }

            if (rule == CIPHER_SPECIAL) {
                found = 0;      /* unused -- avoid compiler warning */
                break;          /* special treatment */
            }

            /* check for multi-part specification */
            if (ch == '+') {
                multi = 1;
                l++;
            } else {
                multi = 0;
            }

            /*
             * Now search for the cipher alias in the ca_list. Be careful
             * with the strncmp, because the "buflen" limitation
             * will make the rule "ADH:SOME" and the cipher
             * "ADH-MY-CIPHER" look like a match for buflen=3.
             * So additionally check whether the cipher name found
             * has the correct length. We can save a strlen() call:
             * just checking for the '\0' at the right place is
             * sufficient, we have to strncmp() anyway. (We cannot
             * use strcmp(), because buf is not '\0' terminated.)
             */
            j = found = 0;
            cipher_id = 0;
            while (ca_list[j]) {
                if (strncmp(buf, ca_list[j]->name, buflen) == 0
                    && (ca_list[j]->name[buflen] == '\0')) {
                    found = 1;
                    break;
                } else
                    j++;
            }

            if (!found)
                break;          /* ignore this entry */

            if (ca_list[j]->algorithm_mkey) {
                if (alg_mkey) {
                    alg_mkey &= ca_list[j]->algorithm_mkey;
                    if (!alg_mkey) {
                        found = 0;
                        break;
                    }
                } else {
                    alg_mkey = ca_list[j]->algorithm_mkey;
                }
            }

            if (ca_list[j]->algorithm_auth) {
                if (alg_auth) {
                    alg_auth &= ca_list[j]->algorithm_auth;
                    if (!alg_auth) {
                        found = 0;
                        break;
                    }
                } else {
                    alg_auth = ca_list[j]->algorithm_auth;
                }
            }

            if (ca_list[j]->algorithm_enc) {
                if (alg_enc) {
                    alg_enc &= ca_list[j]->algorithm_enc;
                    if (!alg_enc) {
                        found = 0;
                        break;
                    }
                } else {
                    alg_enc = ca_list[j]->algorithm_enc;
                }
            }

            if (ca_list[j]->algorithm_mac) {
                if (alg_mac) {
                    alg_mac &= ca_list[j]->algorithm_mac;
                    if (!alg_mac) {
                        found = 0;
                        break;
                    }
                } else {
                    alg_mac = ca_list[j]->algorithm_mac;
                }
            }

            if (ca_list[j]->algo_strength & tls_STRONG_MASK) {
                if (algo_strength & tls_STRONG_MASK) {
                    algo_strength &=
                        (ca_list[j]->algo_strength & tls_STRONG_MASK) |
                        ~tls_STRONG_MASK;
                    if (!(algo_strength & tls_STRONG_MASK)) {
                        found = 0;
                        break;
                    }
                } else {
                    algo_strength = ca_list[j]->algo_strength & tls_STRONG_MASK;
                }
            }

            if (ca_list[j]->algo_strength & tls_DEFAULT_MASK) {
                if (algo_strength & tls_DEFAULT_MASK) {
                    algo_strength &=
                        (ca_list[j]->algo_strength & tls_DEFAULT_MASK) |
                        ~tls_DEFAULT_MASK;
                    if (!(algo_strength & tls_DEFAULT_MASK)) {
                        found = 0;
                        break;
                    }
                } else {
                    algo_strength |=
                        ca_list[j]->algo_strength & tls_DEFAULT_MASK;
                }
            }

            if (ca_list[j]->valid) {
                /*
                 * explicit ciphersuite found; its protocol version does not
                 * become part of the search pattern!
                 */

                cipher_id = ca_list[j]->id;
            } else {
                /*
                 * not an explicit ciphersuite; only in this case, the
                 * protocol version is considered part of the search pattern
                 */

                if (ca_list[j]->min_tls) {
                    if (min_tls != 0 && min_tls != ca_list[j]->min_tls) {
                        found = 0;
                        break;
                    } else {
                        min_tls = ca_list[j]->min_tls;
                    }
                }
            }

            if (!multi)
                break;
        }

        /*
         * Ok, we have the rule, now apply it
         */
        if (rule == CIPHER_SPECIAL) { /* special command */
            ok = 0;
            if ((buflen == 8) && strncmp(buf, "STRENGTH", 8) == 0) {
                ok = tls_cipher_strength_sort(head_p, tail_p);
            } else if (buflen == 10 && strncmp(buf, "SECLEVEL=", 9) == 0) {
                int level = buf[9] - '0';
                if (level < 0 || level > 5) {
                    tlserr(tls_F_tls_CIPHER_PROCESS_RULESTR,
                           tls_R_INVALID_COMMAND);
                } else {
                    c->sec_level = level;
                    ok = 1;
                }
            } else {
                tlserr(tls_F_tls_CIPHER_PROCESS_RULESTR, tls_R_INVALID_COMMAND);
            }
            if (ok == 0)
                retval = 0;
            /*
             * We do not support any "multi" options
             * together with "@", so throw away the
             * rest of the command, if any left, until
             * end or ':' is found.
             */
            while ((*l != '\0') && !ITEM_SEP(*l))
                l++;
        } else if (found) {
            tls_cipher_apply_rule(cipher_id,
                                  alg_mkey, alg_auth, alg_enc, alg_mac,
                                  min_tls, algo_strength, rule, -1, head_p,
                                  tail_p);
        } else {
            while ((*l != '\0') && !ITEM_SEP(*l))
                l++;
        }
        if (*l == '\0')
            break;              /* done */
    }

    return retval;
}

#ifndef OPENtls_NO_EC
static int check_suiteb_cipher_list(const tls_METHOD *meth, CERT *c,
                                    const char **prule_str)
{
    unsigned int suiteb_flags = 0, suiteb_comb2 = 0;
    if (strncmp(*prule_str, "SUITEB128ONLY", 13) == 0) {
        suiteb_flags = tls_CERT_FLAG_SUITEB_128_LOS_ONLY;
    } else if (strncmp(*prule_str, "SUITEB128C2", 11) == 0) {
        suiteb_comb2 = 1;
        suiteb_flags = tls_CERT_FLAG_SUITEB_128_LOS;
    } else if (strncmp(*prule_str, "SUITEB128", 9) == 0) {
        suiteb_flags = tls_CERT_FLAG_SUITEB_128_LOS;
    } else if (strncmp(*prule_str, "SUITEB192", 9) == 0) {
        suiteb_flags = tls_CERT_FLAG_SUITEB_192_LOS;
    }

    if (suiteb_flags) {
        c->cert_flags &= ~tls_CERT_FLAG_SUITEB_128_LOS;
        c->cert_flags |= suiteb_flags;
    } else {
        suiteb_flags = c->cert_flags & tls_CERT_FLAG_SUITEB_128_LOS;
    }

    if (!suiteb_flags)
        return 1;
    /* Check version: if TLS 1.2 ciphers allowed we can use Suite B */

    if (!(meth->tls3_enc->enc_flags & tls_ENC_FLAG_TLS1_2_CIPHERS)) {
        tlserr(tls_F_CHECK_SUITEB_CIPHER_LIST,
               tls_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE);
        return 0;
    }
# ifndef OPENtls_NO_EC
    switch (suiteb_flags) {
    case tls_CERT_FLAG_SUITEB_128_LOS:
        if (suiteb_comb2)
            *prule_str = "ECDHE-ECDSA-AES256-GCM-SHA384";
        else
            *prule_str =
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
        break;
    case tls_CERT_FLAG_SUITEB_128_LOS_ONLY:
        *prule_str = "ECDHE-ECDSA-AES128-GCM-SHA256";
        break;
    case tls_CERT_FLAG_SUITEB_192_LOS:
        *prule_str = "ECDHE-ECDSA-AES256-GCM-SHA384";
        break;
    }
    return 1;
# else
    tlserr(tls_F_CHECK_SUITEB_CIPHER_LIST, tls_R_ECDH_REQUIRED_FOR_SUITEB_MODE);
    return 0;
# endif
}
#endif

static int ciphersuite_cb(const char *elem, int len, void *arg)
{
    STACK_OF(tls_CIPHER) *ciphersuites = (STACK_OF(tls_CIPHER) *)arg;
    const tls_CIPHER *cipher;
    /* Arbitrary sized temp buffer for the cipher name. Should be big enough */
    char name[80];

    if (len > (int)(sizeof(name) - 1)) {
        tlserr(tls_F_CIPHERSUITE_CB, tls_R_NO_CIPHER_MATCH);
        return 0;
    }

    memcpy(name, elem, len);
    name[len] = '\0';

    cipher = tls3_get_cipher_by_std_name(name);
    if (cipher == NULL) {
        tlserr(tls_F_CIPHERSUITE_CB, tls_R_NO_CIPHER_MATCH);
        return 0;
    }

    if (!sk_tls_CIPHER_push(ciphersuites, cipher)) {
        tlserr(tls_F_CIPHERSUITE_CB, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static __owur int set_ciphersuites(STACK_OF(tls_CIPHER) **currciphers, const char *str)
{
    STACK_OF(tls_CIPHER) *newciphers = sk_tls_CIPHER_new_null();

    if (newciphers == NULL)
        return 0;

    /* Parse the list. We explicitly allow an empty list */
    if (*str != '\0'
            && !CONF_parse_list(str, ':', 1, ciphersuite_cb, newciphers)) {
        sk_tls_CIPHER_free(newciphers);
        return 0;
    }
    sk_tls_CIPHER_free(*currciphers);
    *currciphers = newciphers;

    return 1;
}

static int update_cipher_list_by_id(STACK_OF(tls_CIPHER) **cipher_list_by_id,
                                    STACK_OF(tls_CIPHER) *cipherstack)
{
    STACK_OF(tls_CIPHER) *tmp_cipher_list = sk_tls_CIPHER_dup(cipherstack);

    if (tmp_cipher_list == NULL) {
        return 0;
    }

    sk_tls_CIPHER_free(*cipher_list_by_id);
    *cipher_list_by_id = tmp_cipher_list;

    (void)sk_tls_CIPHER_set_cmp_func(*cipher_list_by_id, tls_cipher_ptr_id_cmp);
    sk_tls_CIPHER_sort(*cipher_list_by_id);

    return 1;
}

static int update_cipher_list(STACK_OF(tls_CIPHER) **cipher_list,
                              STACK_OF(tls_CIPHER) **cipher_list_by_id,
                              STACK_OF(tls_CIPHER) *tls13_ciphersuites)
{
    int i;
    STACK_OF(tls_CIPHER) *tmp_cipher_list = sk_tls_CIPHER_dup(*cipher_list);

    if (tmp_cipher_list == NULL)
        return 0;

    /*
     * Delete any existing TLSv1.3 ciphersuites. These are always first in the
     * list.
     */
    while (sk_tls_CIPHER_num(tmp_cipher_list) > 0
           && sk_tls_CIPHER_value(tmp_cipher_list, 0)->min_tls
              == TLS1_3_VERSION)
        sk_tls_CIPHER_delete(tmp_cipher_list, 0);

    /* Insert the new TLSv1.3 ciphersuites */
    for (i = 0; i < sk_tls_CIPHER_num(tls13_ciphersuites); i++)
        sk_tls_CIPHER_insert(tmp_cipher_list,
                             sk_tls_CIPHER_value(tls13_ciphersuites, i), i);

    if (!update_cipher_list_by_id(cipher_list_by_id, tmp_cipher_list))
        return 0;

    sk_tls_CIPHER_free(*cipher_list);
    *cipher_list = tmp_cipher_list;

    return 1;
}

int tls_CTX_set_ciphersuites(tls_CTX *ctx, const char *str)
{
    int ret = set_ciphersuites(&(ctx->tls13_ciphersuites), str);

    if (ret && ctx->cipher_list != NULL)
        return update_cipher_list(&ctx->cipher_list, &ctx->cipher_list_by_id,
                                  ctx->tls13_ciphersuites);

    return ret;
}

int tls_set_ciphersuites(tls *s, const char *str)
{
    STACK_OF(tls_CIPHER) *cipher_list;
    int ret = set_ciphersuites(&(s->tls13_ciphersuites), str);

    if (s->cipher_list == NULL) {
        if ((cipher_list = tls_get_ciphers(s)) != NULL)
            s->cipher_list = sk_tls_CIPHER_dup(cipher_list);
    }
    if (ret && s->cipher_list != NULL)
        return update_cipher_list(&s->cipher_list, &s->cipher_list_by_id,
                                  s->tls13_ciphersuites);

    return ret;
}

STACK_OF(tls_CIPHER) *tls_create_cipher_list(const tls_METHOD *tls_method,
                                             STACK_OF(tls_CIPHER) *tls13_ciphersuites,
                                             STACK_OF(tls_CIPHER) **cipher_list,
                                             STACK_OF(tls_CIPHER) **cipher_list_by_id,
                                             const char *rule_str,
                                             CERT *c)
{
    int ok, num_of_ciphers, num_of_alias_max, num_of_group_aliases, i;
    uint32_t disabled_mkey, disabled_auth, disabled_enc, disabled_mac;
    STACK_OF(tls_CIPHER) *cipherstack;
    const char *rule_p;
    CIPHER_ORDER *co_list = NULL, *head = NULL, *tail = NULL, *curr;
    const tls_CIPHER **ca_list = NULL;

    /*
     * Return with error if nothing to do.
     */
    if (rule_str == NULL || cipher_list == NULL || cipher_list_by_id == NULL)
        return NULL;
#ifndef OPENtls_NO_EC
    if (!check_suiteb_cipher_list(tls_method, c, &rule_str))
        return NULL;
#endif

    /*
     * To reduce the work to do we only want to process the compiled
     * in algorithms, so we first get the mask of disabled ciphers.
     */

    disabled_mkey = disabled_mkey_mask;
    disabled_auth = disabled_auth_mask;
    disabled_enc = disabled_enc_mask;
    disabled_mac = disabled_mac_mask;

    /*
     * Now we have to collect the available ciphers from the compiled
     * in ciphers. We cannot get more than the number compiled in, so
     * it is used for allocation.
     */
    num_of_ciphers = tls_method->num_ciphers();

    co_list = OPENtls_malloc(sizeof(*co_list) * num_of_ciphers);
    if (co_list == NULL) {
        tlserr(tls_F_tls_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        return NULL;          /* Failure */
    }

    tls_cipher_collect_ciphers(tls_method, num_of_ciphers,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, co_list, &head, &tail);

    /* Now arrange all ciphers by preference. */

    /*
     * Everything else being equal, prefer ephemeral ECDH over other key
     * exchange mechanisms.
     * For consistency, prefer ECDSA over RSA (though this only matters if the
     * server has both certificates, and is using the DEFAULT, or a client
     * preference).
     */
    tls_cipher_apply_rule(0, tls_kECDHE, tls_aECDSA, 0, 0, 0, 0, CIPHER_ADD,
                          -1, &head, &tail);
    tls_cipher_apply_rule(0, tls_kECDHE, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);
    tls_cipher_apply_rule(0, tls_kECDHE, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head,
                          &tail);

    /* Within each strength group, we prefer GCM over CHACHA... */
    tls_cipher_apply_rule(0, 0, 0, tls_AESGCM, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);
    tls_cipher_apply_rule(0, 0, 0, tls_CHACHA20, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);

    /*
     * ...and generally, our preferred cipher is AES.
     * Note that AEADs will be bumped to take preference after sorting by
     * strength.
     */
    tls_cipher_apply_rule(0, 0, 0, tls_AES ^ tls_AESGCM, 0, 0, 0, CIPHER_ADD,
                          -1, &head, &tail);

    /* Temporarily enable everything else for sorting */
    tls_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head, &tail);

    /* Low priority for MD5 */
    tls_cipher_apply_rule(0, 0, 0, 0, tls_MD5, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /*
     * Move anonymous ciphers to the end.  Usually, these will remain
     * disabled. (For applications that allow them, they aren't too bad, but
     * we prefer authenticated ciphers.)
     */
    tls_cipher_apply_rule(0, 0, tls_aNULL, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    tls_cipher_apply_rule(0, tls_kRSA, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    tls_cipher_apply_rule(0, tls_kPSK, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /* RC4 is sort-of broken -- move to the end */
    tls_cipher_apply_rule(0, 0, 0, tls_RC4, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /*
     * Now sort by symmetric encryption strength.  The above ordering remains
     * in force within each class
     */
    if (!tls_cipher_strength_sort(&head, &tail)) {
        OPENtls_free(co_list);
        return NULL;
    }

    /*
     * Partially overrule strength sort to prefer TLS 1.2 ciphers/PRFs.
     * TODO(opentls-team): is there an easier way to accomplish all this?
     */
    tls_cipher_apply_rule(0, 0, 0, 0, 0, TLS1_2_VERSION, 0, CIPHER_BUMP, -1,
                          &head, &tail);

    /*
     * Irrespective of strength, enforce the following order:
     * (EC)DHE + AEAD > (EC)DHE > rest of AEAD > rest.
     * Within each group, ciphers remain sorted by strength and previous
     * preference, i.e.,
     * 1) ECDHE > DHE
     * 2) GCM > CHACHA
     * 3) AES > rest
     * 4) TLS 1.2 > legacy
     *
     * Because we now bump ciphers to the top of the list, we proceed in
     * reverse order of preference.
     */
    tls_cipher_apply_rule(0, 0, 0, 0, tls_AEAD, 0, 0, CIPHER_BUMP, -1,
                          &head, &tail);
    tls_cipher_apply_rule(0, tls_kDHE | tls_kECDHE, 0, 0, 0, 0, 0,
                          CIPHER_BUMP, -1, &head, &tail);
    tls_cipher_apply_rule(0, tls_kDHE | tls_kECDHE, 0, 0, tls_AEAD, 0, 0,
                          CIPHER_BUMP, -1, &head, &tail);

    /* Now disable everything (maintaining the ordering!) */
    tls_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);

    /*
     * We also need cipher aliases for selecting based on the rule_str.
     * There might be two types of entries in the rule_str: 1) names
     * of ciphers themselves 2) aliases for groups of ciphers.
     * For 1) we need the available ciphers and for 2) the cipher
     * groups of cipher_aliases added together in one list (otherwise
     * we would be happy with just the cipher_aliases table).
     */
    num_of_group_aliases = Otls_NELEM(cipher_aliases);
    num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
    ca_list = OPENtls_malloc(sizeof(*ca_list) * num_of_alias_max);
    if (ca_list == NULL) {
        OPENtls_free(co_list);
        tlserr(tls_F_tls_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        return NULL;          /* Failure */
    }
    tls_cipher_collect_aliases(ca_list, num_of_group_aliases,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, head);

    /*
     * If the rule_string begins with DEFAULT, apply the default rule
     * before using the (possibly available) additional rules.
     */
    ok = 1;
    rule_p = rule_str;
    if (strncmp(rule_str, "DEFAULT", 7) == 0) {
        ok = tls_cipher_process_rulestr(Otls_default_cipher_list(),
                                        &head, &tail, ca_list, c);
        rule_p += 7;
        if (*rule_p == ':')
            rule_p++;
    }

    if (ok && (rule_p[0] != '\0'))
        ok = tls_cipher_process_rulestr(rule_p, &head, &tail, ca_list, c);

    OPENtls_free(ca_list);      /* Not needed anymore */

    if (!ok) {                  /* Rule processing failure */
        OPENtls_free(co_list);
        return NULL;
    }

    /*
     * Allocate new "cipherstack" for the result, return with error
     * if we cannot get one.
     */
    if ((cipherstack = sk_tls_CIPHER_new_null()) == NULL) {
        OPENtls_free(co_list);
        return NULL;
    }

    /* Add TLSv1.3 ciphers first - we always prefer those if possible */
    for (i = 0; i < sk_tls_CIPHER_num(tls13_ciphersuites); i++) {
        if (!sk_tls_CIPHER_push(cipherstack,
                                sk_tls_CIPHER_value(tls13_ciphersuites, i))) {
            sk_tls_CIPHER_free(cipherstack);
            return NULL;
        }
    }

    Otls_TRACE_BEGIN(TLS_CIPHER) {
        BIO_printf(trc_out, "cipher selection:\n");
    }
    /*
     * The cipher selection for the list is done. The ciphers are added
     * to the resulting precedence to the STACK_OF(tls_CIPHER).
     */
    for (curr = head; curr != NULL; curr = curr->next) {
        if (curr->active) {
            if (!sk_tls_CIPHER_push(cipherstack, curr->cipher)) {
                OPENtls_free(co_list);
                sk_tls_CIPHER_free(cipherstack);
                Otls_TRACE_CANCEL(TLS_CIPHER);
                return NULL;
            }
            if (trc_out != NULL)
                BIO_printf(trc_out, "<%s>\n", curr->cipher->name);
        }
    }
    OPENtls_free(co_list);      /* Not needed any longer */
    Otls_TRACE_END(TLS_CIPHER);

    if (!update_cipher_list_by_id(cipher_list_by_id, cipherstack)) {
        sk_tls_CIPHER_free(cipherstack);
        return NULL;
    }
    sk_tls_CIPHER_free(*cipher_list);
    *cipher_list = cipherstack;

    return cipherstack;
}

char *tls_CIPHER_description(const tls_CIPHER *cipher, char *buf, int len)
{
    const char *ver;
    const char *kx, *au, *enc, *mac;
    uint32_t alg_mkey, alg_auth, alg_enc, alg_mac;
    static const char *format = "%-30s %-7s Kx=%-8s Au=%-5s Enc=%-9s Mac=%-4s\n";

    if (buf == NULL) {
        len = 128;
        if ((buf = OPENtls_malloc(len)) == NULL) {
            tlserr(tls_F_tls_CIPHER_DESCRIPTION, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else if (len < 128) {
        return NULL;
    }

    alg_mkey = cipher->algorithm_mkey;
    alg_auth = cipher->algorithm_auth;
    alg_enc = cipher->algorithm_enc;
    alg_mac = cipher->algorithm_mac;

    ver = tls_protocol_to_string(cipher->min_tls);

    switch (alg_mkey) {
    case tls_kRSA:
        kx = "RSA";
        break;
    case tls_kDHE:
        kx = "DH";
        break;
    case tls_kECDHE:
        kx = "ECDH";
        break;
    case tls_kPSK:
        kx = "PSK";
        break;
    case tls_kRSAPSK:
        kx = "RSAPSK";
        break;
    case tls_kECDHEPSK:
        kx = "ECDHEPSK";
        break;
    case tls_kDHEPSK:
        kx = "DHEPSK";
        break;
    case tls_kSRP:
        kx = "SRP";
        break;
    case tls_kGOST:
        kx = "GOST";
        break;
    case tls_kANY:
        kx = "any";
        break;
    default:
        kx = "unknown";
    }

    switch (alg_auth) {
    case tls_aRSA:
        au = "RSA";
        break;
    case tls_aDSS:
        au = "DSS";
        break;
    case tls_aNULL:
        au = "None";
        break;
    case tls_aECDSA:
        au = "ECDSA";
        break;
    case tls_aPSK:
        au = "PSK";
        break;
    case tls_aSRP:
        au = "SRP";
        break;
    case tls_aGOST01:
        au = "GOST01";
        break;
    /* New GOST ciphersuites have both tls_aGOST12 and tls_aGOST01 bits */
    case (tls_aGOST12 | tls_aGOST01):
        au = "GOST12";
        break;
    case tls_aANY:
        au = "any";
        break;
    default:
        au = "unknown";
        break;
    }

    switch (alg_enc) {
    case tls_DES:
        enc = "DES(56)";
        break;
    case tls_3DES:
        enc = "3DES(168)";
        break;
    case tls_RC4:
        enc = "RC4(128)";
        break;
    case tls_RC2:
        enc = "RC2(128)";
        break;
    case tls_IDEA:
        enc = "IDEA(128)";
        break;
    case tls_eNULL:
        enc = "None";
        break;
    case tls_AES128:
        enc = "AES(128)";
        break;
    case tls_AES256:
        enc = "AES(256)";
        break;
    case tls_AES128GCM:
        enc = "AESGCM(128)";
        break;
    case tls_AES256GCM:
        enc = "AESGCM(256)";
        break;
    case tls_AES128CCM:
        enc = "AESCCM(128)";
        break;
    case tls_AES256CCM:
        enc = "AESCCM(256)";
        break;
    case tls_AES128CCM8:
        enc = "AESCCM8(128)";
        break;
    case tls_AES256CCM8:
        enc = "AESCCM8(256)";
        break;
    case tls_CAMELLIA128:
        enc = "Camellia(128)";
        break;
    case tls_CAMELLIA256:
        enc = "Camellia(256)";
        break;
    case tls_ARIA128GCM:
        enc = "ARIAGCM(128)";
        break;
    case tls_ARIA256GCM:
        enc = "ARIAGCM(256)";
        break;
    case tls_SEED:
        enc = "SEED(128)";
        break;
    case tls_eGOST2814789CNT:
    case tls_eGOST2814789CNT12:
        enc = "GOST89(256)";
        break;
    case tls_CHACHA20POLY1305:
        enc = "CHACHA20/POLY1305(256)";
        break;
    default:
        enc = "unknown";
        break;
    }

    switch (alg_mac) {
    case tls_MD5:
        mac = "MD5";
        break;
    case tls_SHA1:
        mac = "SHA1";
        break;
    case tls_SHA256:
        mac = "SHA256";
        break;
    case tls_SHA384:
        mac = "SHA384";
        break;
    case tls_AEAD:
        mac = "AEAD";
        break;
    case tls_GOST89MAC:
    case tls_GOST89MAC12:
        mac = "GOST89";
        break;
    case tls_GOST94:
        mac = "GOST94";
        break;
    case tls_GOST12_256:
    case tls_GOST12_512:
        mac = "GOST2012";
        break;
    default:
        mac = "unknown";
        break;
    }

    BIO_snprintf(buf, len, format, cipher->name, ver, kx, au, enc, mac);

    return buf;
}

const char *tls_CIPHER_get_version(const tls_CIPHER *c)
{
    if (c == NULL)
        return "(NONE)";

    /*
     * Backwards-compatibility crutch.  In almost all contexts we report TLS
     * 1.0 as "TLSv1", but for ciphers we report "TLSv1.0".
     */
    if (c->min_tls == TLS1_VERSION)
        return "TLSv1.0";
    return tls_protocol_to_string(c->min_tls);
}

/* return the actual cipher being used */
const char *tls_CIPHER_get_name(const tls_CIPHER *c)
{
    if (c != NULL)
        return c->name;
    return "(NONE)";
}

/* return the actual cipher being used in RFC standard name */
const char *tls_CIPHER_standard_name(const tls_CIPHER *c)
{
    if (c != NULL)
        return c->stdname;
    return "(NONE)";
}

/* return the Opentls name based on given RFC standard name */
const char *OPENtls_cipher_name(const char *stdname)
{
    const tls_CIPHER *c;

    if (stdname == NULL)
        return "(NONE)";
    c = tls3_get_cipher_by_std_name(stdname);
    return tls_CIPHER_get_name(c);
}

/* number of bits for symmetric cipher */
int tls_CIPHER_get_bits(const tls_CIPHER *c, int *alg_bits)
{
    int ret = 0;

    if (c != NULL) {
        if (alg_bits != NULL)
            *alg_bits = (int)c->alg_bits;
        ret = (int)c->strength_bits;
    }
    return ret;
}

uint32_t tls_CIPHER_get_id(const tls_CIPHER *c)
{
    return c->id;
}

uint16_t tls_CIPHER_get_protocol_id(const tls_CIPHER *c)
{
    return c->id & 0xFFFF;
}

tls_COMP *tls3_comp_find(STACK_OF(tls_COMP) *sk, int n)
{
    tls_COMP *ctmp;
    int i, nn;

    if ((n == 0) || (sk == NULL))
        return NULL;
    nn = sk_tls_COMP_num(sk);
    for (i = 0; i < nn; i++) {
        ctmp = sk_tls_COMP_value(sk, i);
        if (ctmp->id == n)
            return ctmp;
    }
    return NULL;
}

#ifdef OPENtls_NO_COMP
STACK_OF(tls_COMP) *tls_COMP_get_compression_methods(void)
{
    return NULL;
}

STACK_OF(tls_COMP) *tls_COMP_set0_compression_methods(STACK_OF(tls_COMP)
                                                      *meths)
{
    return meths;
}

int tls_COMP_add_compression_method(int id, COMP_METHOD *cm)
{
    return 1;
}

#else
STACK_OF(tls_COMP) *tls_COMP_get_compression_methods(void)
{
    load_builtin_compressions();
    return tls_comp_methods;
}

STACK_OF(tls_COMP) *tls_COMP_set0_compression_methods(STACK_OF(tls_COMP)
                                                      *meths)
{
    STACK_OF(tls_COMP) *old_meths = tls_comp_methods;
    tls_comp_methods = meths;
    return old_meths;
}

static void cmeth_free(tls_COMP *cm)
{
    OPENtls_free(cm);
}

void tls_comp_free_compression_methods_int(void)
{
    STACK_OF(tls_COMP) *old_meths = tls_comp_methods;
    tls_comp_methods = NULL;
    sk_tls_COMP_pop_free(old_meths, cmeth_free);
}

int tls_COMP_add_compression_method(int id, COMP_METHOD *cm)
{
    tls_COMP *comp;

    if (cm == NULL || COMP_get_type(cm) == NID_undef)
        return 1;

    /*-
     * According to draft-ietf-tls-compression-04.txt, the
     * compression number ranges should be the following:
     *
     *   0 to  63:  methods defined by the IETF
     *  64 to 192:  external party methods assigned by IANA
     * 193 to 255:  reserved for private use
     */
    if (id < 193 || id > 255) {
        tlserr(tls_F_tls_COMP_ADD_COMPRESSION_METHOD,
               tls_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE);
        return 1;
    }

    comp = OPENtls_malloc(sizeof(*comp));
    if (comp == NULL) {
        tlserr(tls_F_tls_COMP_ADD_COMPRESSION_METHOD, ERR_R_MALLOC_FAILURE);
        return 1;
    }

    comp->id = id;
    comp->method = cm;
    load_builtin_compressions();
    if (tls_comp_methods && sk_tls_COMP_find(tls_comp_methods, comp) >= 0) {
        OPENtls_free(comp);
        tlserr(tls_F_tls_COMP_ADD_COMPRESSION_METHOD,
               tls_R_DUPLICATE_COMPRESSION_ID);
        return 1;
    }
    if (tls_comp_methods == NULL || !sk_tls_COMP_push(tls_comp_methods, comp)) {
        OPENtls_free(comp);
        tlserr(tls_F_tls_COMP_ADD_COMPRESSION_METHOD, ERR_R_MALLOC_FAILURE);
        return 1;
    }
    return 0;
}
#endif

const char *tls_COMP_get_name(const COMP_METHOD *comp)
{
#ifndef OPENtls_NO_COMP
    return comp ? COMP_get_name(comp) : NULL;
#else
    return NULL;
#endif
}

const char *tls_COMP_get0_name(const tls_COMP *comp)
{
#ifndef OPENtls_NO_COMP
    return comp->name;
#else
    return NULL;
#endif
}

int tls_COMP_get_id(const tls_COMP *comp)
{
#ifndef OPENtls_NO_COMP
    return comp->id;
#else
    return -1;
#endif
}

const tls_CIPHER *tls_get_cipher_by_char(tls *tls, const unsigned char *ptr,
                                         int all)
{
    const tls_CIPHER *c = tls->method->get_cipher_by_char(ptr);

    if (c == NULL || (!all && c->valid == 0))
        return NULL;
    return c;
}

const tls_CIPHER *tls_CIPHER_find(tls *tls, const unsigned char *ptr)
{
    return tls->method->get_cipher_by_char(ptr);
}

int tls_CIPHER_get_cipher_nid(const tls_CIPHER *c)
{
    int i;
    if (c == NULL)
        return NID_undef;
    i = tls_cipher_info_lookup(tls_cipher_table_cipher, c->algorithm_enc);
    if (i == -1)
        return NID_undef;
    return tls_cipher_table_cipher[i].nid;
}

int tls_CIPHER_get_digest_nid(const tls_CIPHER *c)
{
    int i = tls_cipher_info_lookup(tls_cipher_table_mac, c->algorithm_mac);

    if (i == -1)
        return NID_undef;
    return tls_cipher_table_mac[i].nid;
}

int tls_CIPHER_get_kx_nid(const tls_CIPHER *c)
{
    int i = tls_cipher_info_lookup(tls_cipher_table_kx, c->algorithm_mkey);

    if (i == -1)
        return NID_undef;
    return tls_cipher_table_kx[i].nid;
}

int tls_CIPHER_get_auth_nid(const tls_CIPHER *c)
{
    int i = tls_cipher_info_lookup(tls_cipher_table_auth, c->algorithm_auth);

    if (i == -1)
        return NID_undef;
    return tls_cipher_table_auth[i].nid;
}

const EVP_MD *tls_CIPHER_get_handshake_digest(const tls_CIPHER *c)
{
    int idx = c->algorithm2 & tls_HANDSHAKE_MAC_MASK;

    if (idx < 0 || idx >= tls_MD_NUM_IDX)
        return NULL;
    return tls_digest_methods[idx];
}

int tls_CIPHER_is_aead(const tls_CIPHER *c)
{
    return (c->algorithm_mac & tls_AEAD) ? 1 : 0;
}

int tls_cipher_get_overhead(const tls_CIPHER *c, size_t *mac_overhead,
                            size_t *int_overhead, size_t *blocksize,
                            size_t *ext_overhead)
{
    size_t mac = 0, in = 0, blk = 0, out = 0;

    /* Some hard-coded numbers for the CCM/Poly1305 MAC overhead
     * because there are no handy #defines for those. */
    if (c->algorithm_enc & (tls_AESGCM | tls_ARIAGCM)) {
        out = EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else if (c->algorithm_enc & (tls_AES128CCM | tls_AES256CCM)) {
        out = EVP_CCM_TLS_EXPLICIT_IV_LEN + 16;
    } else if (c->algorithm_enc & (tls_AES128CCM8 | tls_AES256CCM8)) {
        out = EVP_CCM_TLS_EXPLICIT_IV_LEN + 8;
    } else if (c->algorithm_enc & tls_CHACHA20POLY1305) {
        out = 16;
    } else if (c->algorithm_mac & tls_AEAD) {
        /* We're supposed to have handled all the AEAD modes above */
        return 0;
    } else {
        /* Non-AEAD modes. Calculate MAC/cipher overhead separately */
        int digest_nid = tls_CIPHER_get_digest_nid(c);
        const EVP_MD *e_md = EVP_get_digestbynid(digest_nid);

        if (e_md == NULL)
            return 0;

        mac = EVP_MD_size(e_md);
        if (c->algorithm_enc != tls_eNULL) {
            int cipher_nid = tls_CIPHER_get_cipher_nid(c);
            const EVP_CIPHER *e_ciph = EVP_get_cipherbynid(cipher_nid);

            /* If it wasn't AEAD or tls_eNULL, we expect it to be a
               known CBC cipher. */
            if (e_ciph == NULL ||
                EVP_CIPHER_mode(e_ciph) != EVP_CIPH_CBC_MODE)
                return 0;

            in = 1; /* padding length byte */
            out = EVP_CIPHER_iv_length(e_ciph);
            blk = EVP_CIPHER_block_size(e_ciph);
        }
    }

    *mac_overhead = mac;
    *int_overhead = in;
    *blocksize = blk;
    *ext_overhead = out;

    return 1;
}

int tls_cert_is_disabled(size_t idx)
{
    const tls_CERT_LOOKUP *cl = tls_cert_lookup_by_idx(idx);

    if (cl == NULL || (cl->amask & disabled_auth_mask) != 0)
        return 1;
    return 0;
}

/*
 * Default list of TLSv1.2 (and earlier) ciphers
 * tls_DEFAULT_CIPHER_LIST deprecated in 3.0.0
 * Update both macro and function simultaneously
 */
const char *Otls_default_cipher_list(void)
{
    return "ALL:!COMPLEMENTOFDEFAULT:!eNULL";
}

/*
 * Default list of TLSv1.3 (and later) ciphers
 * TLS_DEFAULT_CIPHERSUITES deprecated in 3.0.0
 * Update both macro and function simultaneously
 */
const char *Otls_default_ciphersuites(void)
{
    return "TLS_AES_256_GCM_SHA384:"
#if !defined(OPENtls_NO_CHACHA) && !defined(OPENtls_NO_POLY1305)
           "TLS_CHACHA20_POLY1305_SHA256:"
#endif
           "TLS_AES_128_GCM_SHA256";
}
