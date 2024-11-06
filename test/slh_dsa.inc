/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

typedef struct SLH_DSA_ACVP_TEST_DATA_st {
    const char *alg;
    const unsigned char *pub;
    size_t pub_len;
    const unsigned char *priv;
    size_t priv_len;
    const unsigned char *msg;
    size_t msg_len;
    /* sha256 digest of the signature - this reduces the footprint this file */
    const unsigned char *sig_digest;
    size_t sig_digest_len;
} SLH_DSA_ACVP_TEST_DATA;

#define SLH_DSA_ACVP_ITEM(name, alg) {                                         \
    alg,                                                                       \
    name##_pub, sizeof(name##_pub),                                            \
    name##_priv, sizeof(name##_priv),                                          \
    name##_msg, sizeof(name##_msg),                                            \
    name##_sig_digest, sizeof(name##_sig_digest) }

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
    0x65, 0x98, 0x91, 0x23, 0x17, 0x52, 0x9a, 0x61, 0xda, 0xe4, 0x32, 0x9b, 0xf1, 0x49, 0xef, 0x8b,
};

/* We can only use the hss tests that have a single level here */
static SLH_DSA_ACVP_TEST_DATA slh_dsa_testdata[] = {
    SLH_DSA_ACVP_ITEM(slh_dsa_sha2_128s_0, "SLH-DSA-SHA2-128s"),
};
