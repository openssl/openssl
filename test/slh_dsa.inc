/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define SLH_DSA_SIG_TEST_ITEM(name, alg) {                                     \
    alg,                                                                       \
    name##_pub, sizeof(name##_pub),                                            \
    name##_priv, sizeof(name##_priv),                                          \
    name##_msg, sizeof(name##_msg),                                            \
    name##_sig_digest, sizeof(name##_sig_digest)                               \
}

#define SLH_DSA_KEYGEN_TEST_ITEM(name, alg) {                                  \
    alg,                                                                       \
    name##_keygen_priv, sizeof(name##_keygen_priv),                            \
    name##_keygen_pub_seed, sizeof(name##_keygen_pub_seed),                    \
    name##_keygen_pub_expected, sizeof(name##_keygen_pub_expected)             \
}

typedef struct slh_dsa_sig_test_data_st {
    const char *alg;
    const unsigned char *pub;
    size_t pub_len;
    const unsigned char *priv;
    size_t priv_len;
    const unsigned char *msg;
    size_t msg_len;
    /* This is the sha256 digest of the signature, to reduce its size */
    const unsigned char *sig_digest;
    size_t sig_digest_len;
} SLH_DSA_SIG_TEST_DATA;

typedef struct slh_dsa_keygen_test_data_st {
    const char *name;
    const uint8_t *priv;
    size_t priv_len;
    const uint8_t *pub_seed;
    size_t pub_seed_len;
    const uint8_t *pub_expected;
    size_t pub_expected_len;
} SLH_DSA_KEYGEN_TEST_DATA;

/*
 * Test vectors from
 * usnistgov/ACVP-Server/refs/heads/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json
 *
 * Note that the test vectors store the private & public components in one field
 * (e.g sk)
 * The following data separates these fields.
 */
static const uint8_t slh_dsa_sha2_128s_0_priv[] = {
    0x62, 0xb1, 0x97, 0x3a, 0x4d, 0xe0, 0x96, 0x3d, 0x74, 0xc1, 0xcb, 0x30, 0xfc, 0x8f, 0x56, 0x75,
    0xcf, 0xc8, 0x48, 0x80, 0xe4, 0xf0, 0xe1, 0xb4, 0x46, 0xb4, 0xf5, 0xd1, 0x3b, 0x2d, 0x31, 0xcc,
};
static const uint8_t slh_dsa_sha2_128s_0_pub[] = {
    0xcb, 0x23, 0xeb, 0x45, 0x52, 0x9e, 0x00, 0xd5, 0xf5, 0xe9, 0x51, 0x50, 0x7a, 0x9b, 0x90, 0xe9,
    0x8b, 0x6e, 0x7a, 0x28, 0x4b, 0xa3, 0xf6, 0x3a, 0x69, 0xe6, 0x9a, 0x78, 0x90, 0x83, 0xbe, 0xf6,
};
static const uint8_t slh_dsa_sha2_128s_0_msg[] = {
    0x9D, 0xDF
};
static const uint8_t slh_dsa_sha2_128s_0_sig_digest[] = {
    0xc7, 0xdf, 0xf0, 0xed, 0x25, 0x38, 0x49, 0xef, 0x51, 0x1e, 0x90, 0xbe, 0x0e, 0x2e, 0xb7, 0x71,
    0x65, 0x98, 0x91, 0x23, 0x17, 0x52, 0x9a, 0x61, 0xda, 0xe4, 0x32, 0x9b, 0xf1, 0x49, 0xef, 0x8b
};

static SLH_DSA_SIG_TEST_DATA slh_dsa_sig_testdata[] = {
    SLH_DSA_SIG_TEST_ITEM(slh_dsa_sha2_128s_0, "SLH-DSA-SHA2-128s"),
};

/* skSeed || skPrf */
static const uint8_t slh_dsa_sha2_128s_0_keygen_priv[] = {
    0x2F, 0x89, 0x6D, 0x61, 0xD9, 0xCD, 0x90, 0x38,
    0xCA, 0x30, 0x33, 0x94, 0xFA, 0xDA, 0xA2, 0x2A,
    0x24, 0xAC, 0x5E, 0xC1, 0xD8, 0x6A, 0x98, 0x9C,
    0xA2, 0x19, 0x6C, 0x3C, 0x86, 0x32, 0x41, 0x9C,
};
/* pkSeed */
static const uint8_t slh_dsa_sha2_128s_0_keygen_pub_seed[] = {
    0x1A, 0x05, 0xA4, 0x2F, 0xE3, 0x00, 0xE8, 0x7B,
    0x16, 0xAE, 0xE1, 0x16, 0xCB, 0x2E, 0x23, 0x63,
};
/* pkSeed || pkRoot */
static const uint8_t slh_dsa_sha2_128s_0_keygen_pub_expected[] = {
    0x1A, 0x05, 0xA4, 0x2F, 0xE3, 0x00, 0xE8, 0x7B,
    0x16, 0xAE, 0xE1, 0x16, 0xCB, 0x2E, 0x23, 0x63,
    0x58, 0xE2, 0xC3, 0xE6, 0x26, 0x32, 0xC9, 0xDE,
    0x03, 0xD0, 0x8A, 0x53, 0x5A, 0x0E, 0xB7, 0xE7,
};

static const SLH_DSA_KEYGEN_TEST_DATA slh_dsa_keygen_testdata[] = {
    SLH_DSA_KEYGEN_TEST_ITEM(slh_dsa_sha2_128s_0, "SLH-DSA-SHA2-128s"),
};
