/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may
 * not use this file except in compliance with the License. You can
 * obtain a copy in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ml-dsa-composite-signature test vector types.
 *
 * There are no deterministic signature generation vectors: all supported
 * algorithms use RSA-PSS (random salt) or ECDSA (random k), so their output
 * cannot be reproduced bit for bit. Known-answer signature verification
 * vectors live in evppkey_ml_dsa_composite_sigver.txt.
 */

typedef struct ml_dsa_composite_sig_ver_test_data_st {
    const char          *alg;
    const unsigned char *pub;
    size_t               pub_len;
    const unsigned char *msg;
    size_t               msg_len;
    const unsigned char *sig;
    size_t               sig_len;
    int                  expected;
} ML_DSA_COMPOSITE_SIG_VER_TEST_DATA;

#define ML_DSA_COMPOSITE_SIGVER_TESTDATA_COUNT 0
