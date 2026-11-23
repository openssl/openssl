/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/provider.h>

/*
 * Fake BLAKE2B-512 provider: two implementations that do not support the
 * OSSL_DIGEST_PARAM_SIZE context parameter, selected with the properties below.
 *   fixed:   ignores it and always produces 64 bytes (as BLAKE2B-512 did
 *            before OpenSSL 3.2)
 *   failing: rejects any size other than 64
 */
/**
 * @brief Register and load the fake BLAKE2B-512 provider.
 *
 * @param libctx library context to load the provider into.
 * @return the loaded provider, or NULL on failure.
 */
OSSL_PROVIDER *fake_blake2b_start(OSSL_LIB_CTX *libctx);

/**
 * @brief Unload a provider returned by fake_blake2b_start().
 *
 * @param p the provider, may be NULL.
 */
void fake_blake2b_finish(OSSL_PROVIDER *p);

#define FAKE_BLAKE2B_PROV_NAME "fake-blake2b"
#define FAKE_BLAKE2B_FIXED_PROPS "?fake.blake2b=fixed"
#define FAKE_BLAKE2B_FAILING_PROPS "?fake.blake2b=failing"
