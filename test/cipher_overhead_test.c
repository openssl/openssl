/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "internal/nelem.h"
#include "testutil.h"
#include "../ssl/ssl_local.h"

static int cipher_enabled(const SSL_CIPHER *ciph)
{
    /*
     * ssl_cipher_get_overhead() actually works with AEAD ciphers even if the
     * underlying implementation is not present.
     */
    if ((ciph->algorithm_mac & SSL_AEAD) != 0)
        return 1;

    if (ciph->algorithm_enc != SSL_eNULL
        && EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(ciph)) == NULL)
        return 0;

    if (EVP_get_digestbynid(SSL_CIPHER_get_digest_nid(ciph)) == NULL)
        return 0;

    return 1;
}

/* The DTLS 1.2 (and earlier) ciphers live in the ssl3_ciphers[] table. */
static int cipher_overhead(void)
{
    int ret = 1, i, n = ssl3_num_ciphers();
    const SSL_CIPHER *ciph;
    size_t mac, in, blk, ex;

    for (i = 0; i < n; i++) {
        ciph = ssl3_get_cipher(i);
        if (!ciph->min_dtls)
            continue;
        if (!cipher_enabled(ciph)) {
            TEST_skip("Skipping disabled cipher %s", ciph->name);
            continue;
        }
        if (!TEST_true(ssl_cipher_get_overhead(ciph, DTLS1_2_VERSION,
                &mac, &in, &blk, &ex))) {
            TEST_info("Failed getting %s", ciph->name);
            ret = 0;
        } else {
            TEST_info("Cipher %s: %zu %zu %zu %zu",
                ciph->name, mac, in, blk, ex);
        }
    }
    return ret;
}

/*
 * The DTLS 1.3 ciphers are the TLS 1.3 ciphersuites, which are not reachable
 * through ssl3_get_cipher(), so look them up by id instead.
 */
static const struct {
    uint32_t id;
    size_t ext; /* expected external overhead in DTLS 1.3 (no explicit IV) */
} dtls13_ciphers[] = {
    { TLS1_3_CK_AES_128_GCM_SHA256, EVP_GCM_TLS_TAG_LEN },
    { TLS1_3_CK_AES_256_GCM_SHA384, EVP_GCM_TLS_TAG_LEN },
    { TLS1_3_CK_CHACHA20_POLY1305_SHA256, 16 },
    { TLS1_3_CK_AES_128_CCM_SHA256, 16 },
    { TLS1_3_CK_AES_128_CCM_8_SHA256, 8 },
};

static int dtls13_cipher_overhead(int idx)
{
    const SSL_CIPHER *ciph = ssl3_get_cipher_by_id(dtls13_ciphers[idx].id);
    size_t mac, in, blk, ex;

    if (!TEST_ptr(ciph))
        return 0;
    if (!cipher_enabled(ciph)) {
        TEST_skip("Skipping disabled cipher %s", ciph->name);
        return 1;
    }

    /* DTLS 1.3 uses an implicit nonce, so there is no explicit IV on the wire. */
    if (!TEST_true(ssl_cipher_get_overhead(ciph, DTLS1_3_VERSION,
            &mac, &in, &blk, &ex))) {
        TEST_info("Failed getting %s (DTLSv1.3)", ciph->name);
        return 0;
    }
    TEST_info("Cipher %s (DTLSv1.3): %zu %zu %zu %zu",
        ciph->name, mac, in, blk, ex);
    if (!TEST_size_t_eq(ex, dtls13_ciphers[idx].ext))
        return 0;

    return 1;
}

int setup_tests(void)
{
    OPENSSL_init_ssl(0, NULL);
    ADD_TEST(cipher_overhead);
    ADD_ALL_TESTS(dtls13_cipher_overhead, OSSL_NELEM(dtls13_ciphers));
    return 1;
}
