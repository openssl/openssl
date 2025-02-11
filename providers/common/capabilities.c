/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
/* For TLS1_VERSION etc */
#include <openssl/prov_ssl.h>
#include <openssl/params.h>
#include "internal/nelem.h"
#include "internal/tlsgroups.h"
#include "prov/providercommon.h"
#include "internal/e_os.h"

/* If neither ec or dh is available then we have no TLS-GROUP capabilities */
#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
typedef struct tls_group_constants_st {
    unsigned int group_id;   /* Group ID */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
    int mindtls;             /* Minimum DTLS version, -1 unsupported */
    int maxdtls;             /* Maximum DTLS version (or 0 for undefined) */
} TLS_GROUP_CONSTANTS;

static const TLS_GROUP_CONSTANTS group_list[] = {
    { OSSL_TLS_GROUP_ID_sect163k1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect163r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect163r2, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect193r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect193r2, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect233k1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect233r1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect239k1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect283k1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect283r1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect409k1, 192, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect409r1, 192, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect571k1, 256, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_sect571r1, 256, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp160k1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp160r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp160r2, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp192k1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp192r1, 80, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp224k1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp224r1, 112, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp256k1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_secp384r1, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_secp521r1, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_brainpoolP256r1, 128, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_brainpoolP384r1, 192, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_brainpoolP512r1, 256, TLS1_VERSION, TLS1_2_VERSION,
      DTLS1_VERSION, DTLS1_2_VERSION },
    { OSSL_TLS_GROUP_ID_x25519, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_x448, 224, TLS1_VERSION, 0, DTLS1_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_brainpoolP256r1_tls13, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_brainpoolP384r1_tls13, 192, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_brainpoolP512r1_tls13, 256, TLS1_3_VERSION, 0, -1, -1 },
    /* Security bit values as given by BN_security_bits() */
    { OSSL_TLS_GROUP_ID_ffdhe2048, 112, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_ffdhe3072, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_ffdhe4096, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_ffdhe6144, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_ffdhe8192, 192, TLS1_3_VERSION, 0, -1, -1 },
};

#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               tlsname, \
                               sizeof(tlsname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               realname, \
                               sizeof(realname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               algorithm, \
                               sizeof(algorithm)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&group_list[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                        (unsigned int *)&group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                        (unsigned int *)&group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                        (unsigned int *)&group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                        (unsigned int *)&group_list[idx].maxdtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_group_list[][10] = {
# ifndef OPENSSL_NO_EC
#  ifndef OPENSSL_NO_EC2M
    TLS_GROUP_ENTRY("sect163k1", "sect163k1", "EC", 0),
    TLS_GROUP_ENTRY("K-163", "sect163k1", "EC", 0), /* Alias of above */
#  endif
#  ifndef FIPS_MODULE
    TLS_GROUP_ENTRY("sect163r1", "sect163r1", "EC", 1),
#  endif
#  ifndef OPENSSL_NO_EC2M
    TLS_GROUP_ENTRY("sect163r2", "sect163r2", "EC", 2),
    TLS_GROUP_ENTRY("B-163", "sect163r2", "EC", 2), /* Alias of above */
#  endif
#  ifndef FIPS_MODULE
    TLS_GROUP_ENTRY("sect193r1", "sect193r1", "EC", 3),
    TLS_GROUP_ENTRY("sect193r2", "sect193r2", "EC", 4),
#  endif
#  ifndef OPENSSL_NO_EC2M
    TLS_GROUP_ENTRY("sect233k1", "sect233k1", "EC", 5),
    TLS_GROUP_ENTRY("K-233", "sect233k1", "EC", 5), /* Alias of above */
    TLS_GROUP_ENTRY("sect233r1", "sect233r1", "EC", 6),
    TLS_GROUP_ENTRY("B-233", "sect233r1", "EC", 6), /* Alias of above */
#  endif
#  ifndef FIPS_MODULE
    TLS_GROUP_ENTRY("sect239k1", "sect239k1", "EC", 7),
#  endif
#  ifndef OPENSSL_NO_EC2M
    TLS_GROUP_ENTRY("sect283k1", "sect283k1", "EC", 8),
    TLS_GROUP_ENTRY("K-283", "sect283k1", "EC", 8), /* Alias of above */
    TLS_GROUP_ENTRY("sect283r1", "sect283r1", "EC", 9),
    TLS_GROUP_ENTRY("B-283", "sect283r1", "EC", 9), /* Alias of above */
    TLS_GROUP_ENTRY("sect409k1", "sect409k1", "EC", 10),
    TLS_GROUP_ENTRY("K-409", "sect409k1", "EC", 10), /* Alias of above */
    TLS_GROUP_ENTRY("sect409r1", "sect409r1", "EC", 11),
    TLS_GROUP_ENTRY("B-409", "sect409r1", "EC", 11), /* Alias of above */
    TLS_GROUP_ENTRY("sect571k1", "sect571k1", "EC", 12),
    TLS_GROUP_ENTRY("K-571", "sect571k1", "EC", 12), /* Alias of above */
    TLS_GROUP_ENTRY("sect571r1", "sect571r1", "EC", 13),
    TLS_GROUP_ENTRY("B-571", "sect571r1", "EC", 13), /* Alias of above */
#  endif
#  ifndef FIPS_MODULE
    TLS_GROUP_ENTRY("secp160k1", "secp160k1", "EC", 14),
    TLS_GROUP_ENTRY("secp160r1", "secp160r1", "EC", 15),
    TLS_GROUP_ENTRY("secp160r2", "secp160r2", "EC", 16),
    TLS_GROUP_ENTRY("secp192k1", "secp192k1", "EC", 17),
#  endif
    TLS_GROUP_ENTRY("secp192r1", "prime192v1", "EC", 18),
    TLS_GROUP_ENTRY("P-192", "prime192v1", "EC", 18), /* Alias of above */
#  ifndef FIPS_MODULE
    TLS_GROUP_ENTRY("secp224k1", "secp224k1", "EC", 19),
#  endif
    TLS_GROUP_ENTRY("secp224r1", "secp224r1", "EC", 20),
    TLS_GROUP_ENTRY("P-224", "secp224r1", "EC", 20), /* Alias of above */
#  ifndef FIPS_MODULE
    TLS_GROUP_ENTRY("secp256k1", "secp256k1", "EC", 21),
#  endif
    TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 22),
    TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 22), /* Alias of above */
    TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 23),
    TLS_GROUP_ENTRY("P-384", "secp384r1", "EC", 23), /* Alias of above */
    TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 24),
    TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 24), /* Alias of above */
#  ifndef FIPS_MODULE
    TLS_GROUP_ENTRY("brainpoolP256r1", "brainpoolP256r1", "EC", 25),
    TLS_GROUP_ENTRY("brainpoolP384r1", "brainpoolP384r1", "EC", 26),
    TLS_GROUP_ENTRY("brainpoolP512r1", "brainpoolP512r1", "EC", 27),
    TLS_GROUP_ENTRY("x25519", "X25519", "X25519", 28),
    TLS_GROUP_ENTRY("x448", "X448", "X448", 29),
    TLS_GROUP_ENTRY("brainpoolP256r1tls13", "brainpoolP256r1", "EC", 30),
    TLS_GROUP_ENTRY("brainpoolP384r1tls13", "brainpoolP384r1", "EC", 31),
    TLS_GROUP_ENTRY("brainpoolP512r1tls13", "brainpoolP512r1", "EC", 32),
#  endif
# endif /* OPENSSL_NO_EC */
# ifndef OPENSSL_NO_DH
    /* Security bit values for FFDHE groups are as per RFC 7919 */
    TLS_GROUP_ENTRY("ffdhe2048", "ffdhe2048", "DH", 33),
    TLS_GROUP_ENTRY("ffdhe3072", "ffdhe3072", "DH", 34),
    TLS_GROUP_ENTRY("ffdhe4096", "ffdhe4096", "DH", 35),
    TLS_GROUP_ENTRY("ffdhe6144", "ffdhe6144", "DH", 36),
    TLS_GROUP_ENTRY("ffdhe8192", "ffdhe8192", "DH", 37),
# endif
};
#endif /* !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH) */

static int tls_group_capability(OSSL_CALLBACK *cb, void *arg)
{
#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
    size_t i;

    for (i = 0; i < OSSL_NELEM(param_group_list); i++)
        if (!cb(param_group_list[i], arg))
            return 0;
#endif

    return 1;
}

/* --------------------------------------------------------------- */

#if !defined(OPENSSL_NO_ML_DSA)

typedef struct tls_sigalg_constants_st {
    unsigned int code_point;
    unsigned int sec_bits;    /* Bits of security */
    int min_tls;              /* Minimum TLS version, -1 unsupported */
    int max_tls;              /* Maximum TLS version (or 0 for undefined) */
} TLS_SIGALG_CONSTANTS;

static const TLS_SIGALG_CONSTANTS sigalg_constants_list[3] = {
    { 0x0904, 128, TLS1_3_VERSION, 0 },
    { 0x0905, 192, TLS1_3_VERSION, 0 },
    { 0x0906, 256, TLS1_3_VERSION, 0 },
};

# define TLS_SIGALG_ENTRY(tlsname, algorithm, oid, idx)                         \
    {                                                                           \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,            \
                               tlsname, sizeof(tlsname)),                       \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME,                 \
                               algorithm, sizeof(algorithm)),                   \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID,                  \
                               oid, sizeof(oid)),                               \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,                  \
                        (unsigned int *)&sigalg_constants_list[idx].code_point),\
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,               \
                        (unsigned int *)&sigalg_constants_list[idx].sec_bits),  \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,                      \
                       (unsigned int *)&sigalg_constants_list[idx].min_tls),    \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,                      \
                       (unsigned int *)&sigalg_constants_list[idx].max_tls),    \
        OSSL_PARAM_END                                                          \
    }

static const OSSL_PARAM param_sigalg_list[][8] = {
    TLS_SIGALG_ENTRY("mldsa44", "ML-DSA-44", "2.16.840.1.101.3.4.3.17", 0),
    TLS_SIGALG_ENTRY("mldsa65", "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 1),
    TLS_SIGALG_ENTRY("mldsa87", "ML-DSA-87", "2.16.840.1.101.3.4.3.19", 2),
};
#endif /* OPENSSL_NO_ML_DSA */

static int tls_sigalg_capability(OSSL_CALLBACK *cb, void *arg)
{
#if !defined(OPENSSL_NO_ML_DSA)
    size_t i;

    for (i = 0; i < OSSL_NELEM(param_sigalg_list); i++)
        if (!cb(param_sigalg_list[i], arg))
            return 0;
#endif
    return 1;
}

int ossl_prov_get_capabilities(void *provctx, const char *capability,
                               OSSL_CALLBACK *cb, void *arg)
{
    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0)
        return tls_group_capability(cb, arg);
    if (OPENSSL_strcasecmp(capability, "TLS-SIGALG") == 0)
        return tls_sigalg_capability(cb, arg);

    /* We don't support this capability */
    return 0;
}
