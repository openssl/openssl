/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/implementations.h"
#include "prov/provider_ctx.h"

static OSSL_OP_capabilities_supported_fn tls_group_supported;

typedef struct tls_group_info_st {
    int id;                /* Group ID */
    const char *name;           /* Group Name */
    const char *algorithmm;     /* Name of algorithm */
    int secbits;                /* Bits of security (from SP800-57) */
} TLS_GROUP_INFO;

static const TLS_GROUP_INFO group_list[] = {
    { 0x0001, "sect163k1", "EC", 80 },
    { 0x0002, "sect163r1", "EC", 80 },
    { 0x0003, "sect163r2", "EC", 80 },
    { 0x0004, "sect193r1", "EC", 80 },
    { 0x0005, "sect193r2", "EC", 80 },
    { 0x0006, "sect233k1", "EC", 112 },
    { 0x0007, "sect233r1", "EC", 112 },
    { 0x0008, "sect239k1", "EC", 112 },
    { 0x0009, "sect283k1", "EC", 128 },
    { 0x000A, "sect283r1", "EC", 128 },
    { 0x000B, "sect409k1", "EC", 192 },
    { 0x000C, "sect409r1", "EC", 192 },
    { 0x000D, "sect571k1", "EC", 256 },
    { 0x000E, "sect571r1", "EC", 256 },
    { 0x000F, "secp160k1", "EC", 80 },
    { 0x0010, "secp160r1", "EC", 80 },
    { 0x0011, "secp160r2", "EC", 80 },
    { 0x0012, "secp192k1", "EC", 80 },
    { 0x0013, "secp192r1", "EC", 80 },
    { 0x0014, "secp224k1", "EC", 112 },
    { 0x0015, "secp224r1", "EC", 112 },
    { 0x0016, "secp256k1", "EC", 128 },
    { 0x0017, "secp256r1", "EC", 128 },
    { 0x0018, "secp384r1", "EC", 192 },
    { 0x0019, "secp521r1", "EC", 256 },
    { 0x001A, "brainpoolP256r1", "EC", 128 },
    { 0x001B, "brainpoolP384r1", "EC", 192 },
    { 0x001C, "brainpoolP512r1", "EC", 256 },
    { 0x001D, "x25519", "X25519", 128 },
    { 0x001E, "x448", "X448", 224 },
    /* Security bit values for FFDHE groups are as per RFC 7919 */
    { 0x0100, "ffdhe2048", "DH", 103, },
    { 0x0101, "ffdhe3072", "DH", 125 },
    { 0x0102, "ffdhe4096", "DH", 150 },
    { 0x0103, "ffdhe6144", "DH", 175 },
    { 0x0104, "ffdhe8192", "DH", 192 },
};

static const OSSL_PARAM tls_group_caps[] = {
# ifndef OPENSSL_NO_EC
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[0].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[1].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[2].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[3].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[4].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[5].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[6].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[7].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[8].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[9].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[10].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[11].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[12].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[13].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[14].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[15].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[16].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[17].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[18].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[19].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[20].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[21].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[22].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[23].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[24].id),
#  ifndef FIPS_MODULE
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[25].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[26].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[27].id),
#  endif
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[28].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[29].id),
# endif /* OPENSSL_NO_EC */
# ifndef OPENSSL_NO_DH
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[30].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[31].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[32].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[33].id),
    OSSL_PARAM_int(OSSL_CAPABILITIES_TLS_GROUP, (int *)&group_list[34].id),
# endif /* OPENSSL_NO_DH */
    OSSL_PARAM_END
};

static const OSSL_PARAM *tls_group_supported(void)
{
    return tls_group_caps;
}

const OSSL_DISPATCH tls_group_capability_functions[] = {
    { OSSL_FUNC_CAPABILITES_SUPPORTED, (void (*)(void))tls_group_supported },
    { 0, NULL }
};
