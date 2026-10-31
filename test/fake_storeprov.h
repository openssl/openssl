/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/provider.h>

/* Fake store provider implementation */
OSSL_PROVIDER *fake_store_start(OSSL_LIB_CTX *libctx);
void fake_store_finish(OSSL_PROVIDER *p);

#define FAKE_STORE_PROV_NAME "fake-store"
#define FAKE_STORE_FETCH_PROPS "provider=fake-store"

/* Scheme with a plain open() entry point and delete support */
#define FAKE_STORE_SCHEME "fake"
/* Scheme with an open_ex() entry point and no delete support */
#define FAKE_STORE_SCHEME_OPEN_EX "fake-ex"

/* URI commands recognised after the scheme, e.g. "fake:two-names" */
#define FAKE_STORE_CMD_ONE_NAME "one-name"
#define FAKE_STORE_CMD_TWO_NAMES "two-names"
#define FAKE_STORE_CMD_OPEN_FAIL "open-fail"
#define FAKE_STORE_CMD_PARAMS_FAIL "params-fail"

/* Bitmask of ctx params the fake loader has observed */
#define FAKE_STORE_SEEN_EXPECT (1u << 0)
#define FAKE_STORE_SEEN_SUBJECT (1u << 1)
#define FAKE_STORE_SEEN_ISSUER (1u << 2)
#define FAKE_STORE_SEEN_SERIAL (1u << 3)
#define FAKE_STORE_SEEN_DIGEST (1u << 4)
#define FAKE_STORE_SEEN_FINGERPRINT (1u << 5)
#define FAKE_STORE_SEEN_ALIAS (1u << 6)
#define FAKE_STORE_SEEN_PROPERTIES (1u << 7)

unsigned int fake_store_get_seen_params(void);
void fake_store_clear_state(void);
const char *fake_store_get0_last_deleted(void);
