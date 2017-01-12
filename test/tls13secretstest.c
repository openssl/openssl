/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include "../ssl/ssl_locl.h"

#include "testutil.h"
#include "test_main.h"

#define IVLEN   12
#define KEYLEN  16

/* The following are unofficial test vectors generated from a locally modified
 * version of picotls.
 * TODO(TLS1.3): As and when official vectors become available we should use
 * those, e.g. see
 * https://www.ietf.org/id/draft-thomson-tls-tls13-vectors-00.txt, however at
 * the time of writing these are not suitable because they are based on
 * draft -16, which works slightly differently to the draft -18 vectors below.
 */

static unsigned char hs_start_hash[] = {
0xec, 0x14, 0x7a, 0x06, 0xde, 0xa3, 0xc8, 0x84, 0x6c, 0x02, 0xb2, 0x23, 0x8e,
0x41, 0xbd, 0xdc, 0x9d, 0x89, 0xf9, 0xae, 0xa1, 0x7b, 0x5e, 0xfd, 0x4d, 0x74,
0x82, 0xaf, 0x75, 0x88, 0x1c, 0x0a
};

static unsigned char hs_full_hash[] = {
0x75, 0x1a, 0x3d, 0x4a, 0x14, 0xdf, 0xab, 0xeb, 0x68, 0xe9, 0x2c, 0xa5, 0x91,
0x8e, 0x24, 0x08, 0xb9, 0xbc, 0xb0, 0x74, 0x89, 0x82, 0xec, 0x9c, 0x32, 0x30,
0xac, 0x30, 0xbb, 0xeb, 0x23, 0xe2,
};

static unsigned char early_secret[] = {
0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93,
0x68, 0x0c, 0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2,
0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a
};

static unsigned char ecdhe_secret[] = {
0xe7, 0xb8, 0xfe, 0xf8, 0x90, 0x3b, 0x52, 0x0c, 0xb9, 0xa1, 0x89, 0x71, 0xb6,
0x9d, 0xd4, 0x5d, 0xca, 0x53, 0xce, 0x2f, 0x12, 0xbf, 0x3b, 0xef, 0x93, 0x15,
0xe3, 0x12, 0x71, 0xdf, 0x4b, 0x40
};

static unsigned char handshake_secret[] = {
0xdf, 0xc9, 0x41, 0xd8, 0x26, 0x93, 0x2a, 0x59, 0x11, 0xb3, 0xb7, 0xd0, 0x38,
0xcb, 0x65, 0x6f, 0xda, 0xaf, 0x77, 0x07, 0x1e, 0x40, 0x9a, 0x9b, 0xa6, 0xca,
0x74, 0xda, 0x17, 0xb4, 0xe0, 0x04,
};

static const char *client_hts_label = "client handshake traffic secret";

static unsigned char client_hts[] = {
0x4b, 0x38, 0x48, 0xf1, 0x5d, 0xb1, 0x5e, 0x88, 0xcf, 0x3e, 0x3b, 0xff, 0xa6,
0xba, 0x02, 0xc1, 0xc5, 0xd1, 0xe5, 0xb1, 0xc3, 0xf3, 0x10, 0xdf, 0xe5, 0xc9,
0x69, 0x5a, 0x4a, 0xc6, 0x06, 0x38,
};

static unsigned char client_hts_key[] = {
0xe5, 0x7b, 0x8c, 0x38, 0x6d, 0x6f, 0x09, 0x14, 0xe2, 0xe5, 0x4e, 0x36, 0x23,
0x91, 0x2a, 0xd4
};

static unsigned char client_hts_iv[] = {
0x4d, 0x2e, 0x61, 0x0c, 0x4d, 0x3a, 0x8e, 0x5f, 0x15, 0x41, 0x1e, 0xfd
};

static const char *server_hts_label = "server handshake traffic secret";

static unsigned char server_hts[] = {
0x74, 0x1f, 0xb3, 0xb8, 0x41, 0x24, 0xc4, 0x7e, 0x1b, 0x2e, 0xa9, 0x4f, 0x0c,
0x42, 0xc9, 0x06, 0xb7, 0x7c, 0x84, 0x92, 0x05, 0xed, 0x5f, 0x19, 0xda, 0xbb,
0xbb, 0xce, 0xc7, 0x29, 0x06, 0x7e,
};

static unsigned char server_hts_key[] = {
0x72, 0x61, 0x1c, 0xc8, 0x0d, 0x65, 0x9c, 0x89, 0xf8, 0x94, 0x9e, 0x32, 0x67,
0xe1, 0x6c, 0x2d

};

static unsigned char server_hts_iv[] = {
0x43, 0xfe, 0x11, 0x29, 0x0f, 0xe8, 0xfe, 0x84, 0x9c, 0x9b, 0x21, 0xef,
};

static unsigned char master_secret[] = {
0xfe, 0x8d, 0xfb, 0xd0, 0x14, 0x94, 0x4e, 0x22, 0x65, 0x16, 0x7d, 0xc4, 0x20,
0x01, 0x5b, 0x10, 0x64, 0x74, 0xb7, 0x22, 0x9a, 0x95, 0xd1, 0x48, 0x0c, 0xb9,
0xac, 0xd1, 0xa0, 0x28, 0xb7, 0x67
};

static const char *client_ats_label = "client application traffic secret";

static unsigned char client_ats[] = {
0x56, 0x9e, 0x9c, 0x17, 0xe3, 0x52, 0x1f, 0xdd, 0x09, 0xf4, 0xb8, 0x4f, 0x6c,
0xd6, 0x6d, 0xa8, 0x23, 0xde, 0xeb, 0x81, 0xbb, 0xb1, 0xde, 0x61, 0xe2, 0x82,
0x56, 0x27, 0xf7, 0x00, 0x63, 0x81,
};

static unsigned char client_ats_key[] = {
0xcb, 0xfa, 0xae, 0x71, 0x8d, 0xfb, 0x52, 0xba, 0x7b, 0x87, 0xde, 0x8b, 0x6d,
0xac, 0x92, 0x60
};

static unsigned char client_ats_iv[] = {
0x74, 0x86, 0x88, 0xe9, 0x7f, 0x72, 0xfb, 0xf3, 0x33, 0x1e, 0xfb, 0x55
};

static const char *server_ats_label = "server application traffic secret";

static unsigned char server_ats[] = {
0xd1, 0xbf, 0xdc, 0x8b, 0x84, 0xf4, 0x16, 0xb7, 0xc6, 0x90, 0xd9, 0xc9, 0x2c,
0x23, 0x11, 0xb3, 0x05, 0xad, 0x75, 0xfc, 0xe6, 0x29, 0x90, 0x2b, 0xe1, 0x03,
0xdd, 0x0c, 0x12, 0x51, 0xea, 0xd2,
};

static unsigned char server_ats_key[] = {
0x35, 0xc2, 0xd1, 0x54, 0xa8, 0x43, 0x03, 0xc6, 0x55, 0xa0, 0x2e, 0x5e, 0x1f,
0x82, 0x31, 0x62
};

static unsigned char server_ats_iv[] = {
0xe5, 0x77, 0xd9, 0x8a, 0xb3, 0x2e, 0xec, 0x79, 0xb1, 0x63, 0x68, 0xc2
};

/* Mocked out implementations of various functions */
int ssl3_digest_cached_records(SSL *s, int keep)
{
    return 1;
}

static int full_hash = 0;

/* Give a hash of the currently set handshake */
int ssl_handshake_hash(SSL *s, unsigned char *out, size_t outlen,
                       size_t *hashlen)
{
    if (sizeof(hs_start_hash) > outlen
            || sizeof(hs_full_hash) != sizeof(hs_start_hash))
        return 0;

    if (full_hash) {
        memcpy(out, hs_full_hash, sizeof(hs_full_hash));
        *hashlen = sizeof(hs_full_hash);
    } else {
        memcpy(out, hs_start_hash, sizeof(hs_start_hash));
        *hashlen = sizeof(hs_start_hash);
    }

    return 1;
}

const EVP_MD *ssl_handshake_md(SSL *s)
{
    return EVP_sha256();
}

void RECORD_LAYER_reset_read_sequence(RECORD_LAYER *rl)
{
}

void RECORD_LAYER_reset_write_sequence(RECORD_LAYER *rl)
{
}

int ssl_cipher_get_evp(const SSL_SESSION *s, const EVP_CIPHER **enc,
                       const EVP_MD **md, int *mac_pkey_type,
                       size_t *mac_secret_size, SSL_COMP **comp, int use_etm)

{
    return 0;
}

int tls1_alert_code(int code)
{
    return code;
}

/* End of mocked out code */

static int test_secret(SSL *s, unsigned char *prk,
                       const unsigned char *label, size_t labellen,
                       const unsigned char *ref_secret,
                       const unsigned char *ref_key, const unsigned char *ref_iv)
{
    size_t hashsize;
    unsigned char gensecret[EVP_MAX_MD_SIZE];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned char key[KEYLEN];
    unsigned char iv[IVLEN];

    if (!ssl_handshake_hash(s, hash, sizeof(hash), &hashsize)) {
        fprintf(stderr, "Failed to get hash\n");
        return 0;
    }

    if (!tls13_hkdf_expand(s, prk, label, labellen, hash, gensecret,
                           hashsize)) {
        fprintf(stderr, "Secret generation failed\n");
        return 0;
    }

    if (memcmp(gensecret, ref_secret, hashsize) != 0) {
        fprintf(stderr, "Generated secret does not match\n");
        return 0;
    }

    if (!tls13_derive_key(s, gensecret, key, KEYLEN)) {
        fprintf(stderr, "Key generation failed\n");
        return 0;
    }

    if (memcmp(key, ref_key, KEYLEN) != 0) {
        fprintf(stderr, "Generated key does not match\n");
        return 0;
    }

    if (!tls13_derive_iv(s, gensecret, iv, IVLEN)) {
        fprintf(stderr, "IV generation failed\n");
        return 0;
    }

    if (memcmp(iv, ref_iv, IVLEN) != 0) {
        fprintf(stderr, "Generated IV does not match\n");
        return 0;
    }

    return 1;
}

static int test_handshake_secrets(void)
{
    SSL_CTX *ctx = NULL;
    SSL *s = NULL;
    int ret = 0;
    size_t hashsize;
    unsigned char out_master_secret[EVP_MAX_MD_SIZE];
    size_t master_secret_length;

    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL)
        goto err;

    s = SSL_new(ctx);
    if (s == NULL)
        goto err;

    if (!tls13_generate_early_secret(s, NULL, 0)) {
        fprintf(stderr, "Early secret generation failed\n");
        goto err;
    }

    if (memcmp(s->early_secret, early_secret, sizeof(early_secret)) != 0) {
        fprintf(stderr, "Early secret does not match\n");
        goto err;
    }

    if (!tls13_generate_handshake_secret(s, ecdhe_secret,
                                         sizeof(ecdhe_secret))) {
        fprintf(stderr, "Hanshake secret generation failed\n");
        goto err;
    }

    if (memcmp(s->handshake_secret, handshake_secret,
               sizeof(handshake_secret)) != 0) {
        fprintf(stderr, "Handshake secret does not match\n");
        goto err;
    }

    hashsize = EVP_MD_size(ssl_handshake_md(s));
    if (sizeof(client_hts) != hashsize || sizeof(client_hts_key) != KEYLEN
            || sizeof(client_hts_iv) != IVLEN) {
        fprintf(stderr, "Internal test error\n");
        goto err;
    }

    if (!test_secret(s, s->handshake_secret, (unsigned char *)client_hts_label,
                     strlen(client_hts_label), client_hts, client_hts_key,
                     client_hts_iv)) {
        fprintf(stderr, "Client handshake secret test failed\n");
        goto err;
    }

    if (sizeof(server_hts) != hashsize || sizeof(server_hts_key) != KEYLEN
            || sizeof(server_hts_iv) != IVLEN) {
        fprintf(stderr, "Internal test error\n");
        goto err;
    }

    if (!test_secret(s, s->handshake_secret, (unsigned char *)server_hts_label,
                     strlen(server_hts_label), server_hts, server_hts_key,
                     server_hts_iv)) {
        fprintf(stderr, "Server handshake secret test failed\n");
        goto err;
    }

    /*
     * Ensure the mocked out ssl_handshake_hash() returns the full handshake
     * hash.
     */
    full_hash = 1;

    if (!tls13_generate_master_secret(s, out_master_secret,
                                      s->handshake_secret, hashsize,
                                      &master_secret_length)) {
        fprintf(stderr, "Master secret generation failed\n");
        goto err;
    }

    if (master_secret_length != sizeof(master_secret) ||
            memcmp(out_master_secret, master_secret,
                   sizeof(master_secret)) != 0) {
        fprintf(stderr, "Master secret does not match\n");
        goto err;
    }

    if (sizeof(client_ats) != hashsize || sizeof(client_ats_key) != KEYLEN
            || sizeof(client_ats_iv) != IVLEN) {
        fprintf(stderr, "Internal test error\n");
        goto err;
    }

    if (!test_secret(s, out_master_secret, (unsigned char *)client_ats_label,
                     strlen(client_ats_label), client_ats, client_ats_key,
                     client_ats_iv)) {
        fprintf(stderr, "Client application data secret test failed\n");
        goto err;
    }

    if (sizeof(server_ats) != hashsize || sizeof(server_ats_key) != KEYLEN
            || sizeof(server_ats_iv) != IVLEN) {
        fprintf(stderr, "Internal test error\n");
        goto err;
    }

    if (!test_secret(s, out_master_secret, (unsigned char *)server_ats_label,
                     strlen(server_ats_label), server_ats, server_ats_key,
                     server_ats_iv)) {
        fprintf(stderr, "Server application data secret test failed\n");
        goto err;
    }

    ret = 1;
 err:
    SSL_free(s);
    SSL_CTX_free(ctx);
    return ret;
}

void register_tests()
{
    ADD_TEST(test_handshake_secrets);
}
