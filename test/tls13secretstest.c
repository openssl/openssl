/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/evp.h>

#ifdef __VMS
# pragma names save
# pragma names as_is,shortened
#endif

#include "../ssl/ssl_locl.h"

#ifdef __VMS
# pragma names restore
#endif

#include "testutil.h"

#define IVLEN   12
#define KEYLEN  16

/* The following are self-generated test vectors. This gives us very little
 * confidence that we've got the implementation right, but at least tells us
 * if we accidentally  break something in the future. Until we can get some
 * other source of test vectors this is all we've got.
 * TODO(TLS1.3): As and when official vectors become available we should use
 * those, e.g. see
 * https://www.ietf.org/id/draft-thomson-tls-tls13-vectors-00.txt, however at
 * the time of writing these are not suitable because they are based on
 * draft -16, which works differently to the draft -20 vectors below.
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
0xf5, 0x51, 0xd0, 0xbd, 0x9e, 0x6a, 0xc0, 0x95, 0x5f, 0x8e, 0xae, 0xb6, 0x28,
0x2e, 0x8d, 0x9e, 0xf3, 0xd4, 0x08, 0x57, 0x81, 0xbc, 0x9d, 0x80, 0x91, 0x8a,
0x81, 0x33, 0x86, 0x58, 0x7f, 0x46
};

static const char *client_hts_label = "c hs traffic";

static unsigned char client_hts[] = {
0x61, 0x7b, 0x35, 0x07, 0x6b, 0x9d, 0x0e, 0x08, 0xcf, 0x73, 0x1d, 0x94, 0xa8,
0x66, 0x14, 0x78, 0x41, 0x09, 0xef, 0x25, 0x55, 0x51, 0x92, 0x1d, 0xd4, 0x6e,
0x04, 0x01, 0x35, 0xcf, 0x46, 0xab
};

static unsigned char client_hts_key[] = {
0x62, 0xd0, 0xdd, 0x00, 0xf6, 0x96, 0x19, 0xd3, 0xb8, 0x19, 0x3a, 0xb4, 0xa0,
0x95, 0x85, 0xa7
};

static unsigned char client_hts_iv[] = {
0xff, 0xf7, 0x5d, 0xf5, 0xad, 0x35, 0xd5, 0xcb, 0x3c, 0x53, 0xf3, 0xa9
};

static const char *server_hts_label = "s hs traffic";

static unsigned char server_hts[] = {
0xfc, 0xf7, 0xdf, 0xe6, 0x4f, 0xa2, 0xc0, 0x4f, 0x62, 0x35, 0x38, 0x7f, 0x43,
0x4e, 0x01, 0x42, 0x23, 0x36, 0xd9, 0xc0, 0x39, 0xde, 0x68, 0x47, 0xa0, 0xb9,
0xdd, 0xcf, 0x29, 0xa8, 0x87, 0x59
};

static unsigned char server_hts_key[] = {
0x04, 0x67, 0xf3, 0x16, 0xa8, 0x05, 0xb8, 0xc4, 0x97, 0xee, 0x67, 0x04, 0x7b,
0xbc, 0xbc, 0x54
};

static unsigned char server_hts_iv[] = {
0xde, 0x83, 0xa7, 0x3e, 0x9d, 0x81, 0x4b, 0x04, 0xc4, 0x8b, 0x78, 0x09
};

static unsigned char master_secret[] = {
0x34, 0x83, 0x83, 0x84, 0x67, 0x12, 0xe7, 0xff, 0x24, 0xe8, 0x6e, 0x70, 0x56,
0x95, 0x16, 0x71, 0x43, 0x7f, 0x19, 0xd7, 0x85, 0x06, 0x9d, 0x75, 0x70, 0x49,
0x6e, 0x6c, 0xa4, 0x81, 0xf0, 0xb8
};

static const char *client_ats_label = "c ap traffic";

static unsigned char client_ats[] = {
0xc1, 0x4a, 0x6d, 0x79, 0x76, 0xd8, 0x10, 0x2b, 0x5a, 0x0c, 0x99, 0x51, 0x49,
0x3f, 0xee, 0x87, 0xdc, 0xaf, 0xf8, 0x2c, 0x24, 0xca, 0xb2, 0x14, 0xe8, 0xbe,
0x71, 0xa8, 0x20, 0x6d, 0xbd, 0xa5
};

static unsigned char client_ats_key[] = {
0xcc, 0x9f, 0x5f, 0x98, 0x0b, 0x5f, 0x10, 0x30, 0x6c, 0xba, 0xd7, 0xbe, 0x98,
0xd7, 0x57, 0x2e
};

static unsigned char client_ats_iv[] = {
0xb8, 0x09, 0x29, 0xe8, 0xd0, 0x2c, 0x70, 0xf6, 0x11, 0x62, 0xed, 0x6b
};

static const char *server_ats_label = "s ap traffic";

static unsigned char server_ats[] = {
0x2c, 0x90, 0x77, 0x38, 0xd3, 0xf8, 0x37, 0x02, 0xd1, 0xe4, 0x59, 0x8f, 0x48,
0x48, 0x53, 0x1d, 0x9f, 0x93, 0x65, 0x49, 0x1b, 0x9f, 0x7f, 0x52, 0xc8, 0x22,
0x29, 0x0d, 0x4c, 0x23, 0x21, 0x92
};

static unsigned char server_ats_key[] = {
0x0c, 0xb2, 0x95, 0x62, 0xd8, 0xd8, 0x8f, 0x48, 0xb0, 0x2c, 0xbf, 0xbe, 0xd7,
0xe6, 0x2b, 0xb3
};

static unsigned char server_ats_iv[] = {
0x0d, 0xb2, 0x8f, 0x98, 0x85, 0x86, 0xa1, 0xb7, 0xe4, 0xd5, 0xc6, 0x9c
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

int ssl_log_secret(SSL *ssl,
                   const char *label,
                   const uint8_t *secret,
                   size_t secret_len)
{
    return 1;
}

const EVP_MD *ssl_md(int idx)
{
    return EVP_sha256();
}

void ossl_statem_fatal(SSL *s, int al, int func, int reason, const char *file,
                           int line)
{
}

int ossl_statem_export_allowed(SSL *s)
{
    return 1;
}

int ossl_statem_export_early_allowed(SSL *s)
{
    return 1;
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
    const EVP_MD *md = ssl_handshake_md(s);

    if (!ssl_handshake_hash(s, hash, sizeof(hash), &hashsize)) {
        TEST_error("Failed to get hash");
        return 0;
    }

    if (!tls13_hkdf_expand(s, md, prk, label, labellen, hash, hashsize,
                           gensecret, hashsize)) {
        TEST_error("Secret generation failed");
        return 0;
    }

    if (!TEST_mem_eq(gensecret, hashsize, ref_secret, hashsize))
        return 0;

    if (!tls13_derive_key(s, md, gensecret, key, KEYLEN)) {
        TEST_error("Key generation failed");
        return 0;
    }

    if (!TEST_mem_eq(key, KEYLEN, ref_key, KEYLEN))
        return 0;

    if (!tls13_derive_iv(s, md, gensecret, iv, IVLEN)) {
        TEST_error("IV generation failed");
        return 0;
    }

    if (!TEST_mem_eq(iv, IVLEN, ref_iv, IVLEN))
        return 0;

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
    if (!TEST_ptr(ctx))
        goto err;

    s = SSL_new(ctx);
    if (!TEST_ptr(s ))
        goto err;

    s->session = SSL_SESSION_new();
    if (!TEST_ptr(s->session))
        goto err;

    if (!TEST_true(tls13_generate_secret(s, ssl_handshake_md(s), NULL, NULL, 0,
                                         (unsigned char *)&s->early_secret))) {
        TEST_info("Early secret generation failed");
        goto err;
    }

    if (!TEST_mem_eq(s->early_secret, sizeof(early_secret),
                     early_secret, sizeof(early_secret))) {
        TEST_info("Early secret does not match");
        goto err;
    }

    if (!TEST_true(tls13_generate_handshake_secret(s, ecdhe_secret,
                                                   sizeof(ecdhe_secret)))) {
        TEST_info("Handshake secret generation failed");
        goto err;
    }

    if (!TEST_mem_eq(s->handshake_secret, sizeof(handshake_secret),
                     handshake_secret, sizeof(handshake_secret)))
        goto err;

    hashsize = EVP_MD_size(ssl_handshake_md(s));
    if (!TEST_size_t_eq(sizeof(client_hts), hashsize))
        goto err;
    if (!TEST_size_t_eq(sizeof(client_hts_key), KEYLEN))
        goto err;
    if (!TEST_size_t_eq(sizeof(client_hts_iv), IVLEN))
        goto err;

    if (!TEST_true(test_secret(s, s->handshake_secret,
                               (unsigned char *)client_hts_label,
                               strlen(client_hts_label), client_hts,
                               client_hts_key, client_hts_iv))) {
        TEST_info("Client handshake secret test failed");
        goto err;
    }

    if (!TEST_size_t_eq(sizeof(server_hts), hashsize))
        goto err;
    if (!TEST_size_t_eq(sizeof(server_hts_key), KEYLEN))
        goto err;
    if (!TEST_size_t_eq(sizeof(server_hts_iv), IVLEN))
        goto err;

    if (!TEST_true(test_secret(s, s->handshake_secret,
                               (unsigned char *)server_hts_label,
                               strlen(server_hts_label), server_hts,
                               server_hts_key, server_hts_iv))) {
        TEST_info("Server handshake secret test failed");
        goto err;
    }

    /*
     * Ensure the mocked out ssl_handshake_hash() returns the full handshake
     * hash.
     */
    full_hash = 1;

    if (!TEST_true(tls13_generate_master_secret(s, out_master_secret,
                                                s->handshake_secret, hashsize,
                                                &master_secret_length))) {
        TEST_info("Master secret generation failed");
        goto err;
    }

    if (!TEST_mem_eq(out_master_secret, master_secret_length,
                     master_secret, sizeof(master_secret))) {
        TEST_info("Master secret does not match");
        goto err;
    }

    if (!TEST_size_t_eq(sizeof(client_ats), hashsize))
        goto err;
    if (!TEST_size_t_eq(sizeof(client_ats_key), KEYLEN))
        goto err;
    if (!TEST_size_t_eq(sizeof(client_ats_iv), IVLEN))
        goto err;

    if (!TEST_true(test_secret(s, out_master_secret,
                               (unsigned char *)client_ats_label,
                               strlen(client_ats_label), client_ats,
                               client_ats_key, client_ats_iv))) {
        TEST_info("Client application data secret test failed");
        goto err;
    }

    if (!TEST_size_t_eq(sizeof(server_ats), hashsize))
        goto err;
    if (!TEST_size_t_eq(sizeof(server_ats_key), KEYLEN))
        goto err;
    if (!TEST_size_t_eq(sizeof(server_ats_iv), IVLEN))
        goto err;

    if (!TEST_true(test_secret(s, out_master_secret,
                               (unsigned char *)server_ats_label,
                               strlen(server_ats_label), server_ats,
                               server_ats_key, server_ats_iv))) {
        TEST_info("Server application data secret test failed");
        goto err;
    }

    ret = 1;
 err:
    SSL_free(s);
    SSL_CTX_free(ctx);
    return ret;
}

int setup_tests()
{
    ADD_TEST(test_handshake_secrets);
    return 1;
}
