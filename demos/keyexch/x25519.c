/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

/*
 * This is a demonstration of key exchange using X25519.
 *
 * The variables beginning `peer1_` / `peer2_` are data which would normally be
 * accessible to that peer.
 *
 * Ordinarily you would use random keys, which are demonstrated
 * below when use_kat=0. A known answer test is demonstrated
 * when use_kat=1.
 */

/* A property query used for selecting the X25519 implementation. */
static const char *propq = NULL;

static const unsigned char peer1_privk_data[32] = {
    0x80, 0x5b, 0x30, 0x20, 0x25, 0x4a, 0x70, 0x2c,
    0xad, 0xa9, 0x8d, 0x7d, 0x47, 0xf8, 0x1b, 0x20,
    0x89, 0xd2, 0xf9, 0x14, 0xac, 0x92, 0x27, 0xf2,
    0x10, 0x7e, 0xdb, 0x21, 0xbd, 0x73, 0x73, 0x5d
};

static const unsigned char peer2_privk_data[32] = {
    0xf8, 0x84, 0x19, 0x69, 0x79, 0x13, 0x0d, 0xbd,
    0xb1, 0x76, 0xd7, 0x0e, 0x7e, 0x0f, 0xb6, 0xf4,
    0x8c, 0x4a, 0x8c, 0x5f, 0xd8, 0x15, 0x09, 0x0a,
    0x71, 0x78, 0x74, 0x92, 0x0f, 0x85, 0xc8, 0x43
};

static const unsigned char expected_result[32] = {
  0x19, 0x71, 0x26, 0x12, 0x74, 0xb5, 0xb1, 0xce,
  0x77, 0xd0, 0x79, 0x24, 0xb6, 0x0a, 0x5c, 0x72,
  0x0c, 0xa6, 0x56, 0xc0, 0x11, 0xeb, 0x43, 0x11,
  0x94, 0x3b, 0x01, 0x45, 0xca, 0x19, 0xfe, 0x09
};

static int keyexch_x25519(int use_kat)
{
    int rv = 1;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *peer1_privk = NULL, *peer2_privk = NULL,
             *peer1_pubk = NULL, *peer2_pubk = NULL;
    EVP_PKEY_CTX *peer1_ctx = NULL, *peer2_ctx = NULL;
    size_t peer1_secret_len = 0,
           peer2_secret_len = 0,
           peer1_pubk_data_len = 0,
           peer2_pubk_data_len = 0;
    unsigned char *peer1_secret = NULL, *peer2_secret = NULL;
    unsigned char peer1_pubk_data[32], peer2_pubk_data[32];

    /* Generate X25519 key for peer 1 */
    if (use_kat)
        peer1_privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", propq,
            peer1_privk_data, sizeof(peer1_privk_data));
    else
        peer1_privk = EVP_PKEY_Q_keygen(libctx, propq, "X25519");
    if (peer1_privk == NULL) {
        fprintf(stderr, "EVP_PKEY_Q_keygen() returned NULL\n");
        goto end;
    }

    /* Generate X25519 key for peer 2 */
    if (use_kat)
        peer2_privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", propq,
            peer2_privk_data, sizeof(peer2_privk_data));
    else
        peer2_privk = EVP_PKEY_Q_keygen(libctx, propq, "X25519");
    if (peer2_privk == NULL) {
        fprintf(stderr, "EVP_PKEY_Q_keygen() returned NULL\n");
        goto end;
    }

    /* Get public key corresponding to peer 1's private key */
    if (EVP_PKEY_get_octet_string_param(peer1_privk, OSSL_PKEY_PARAM_PUB_KEY,
                                    peer1_pubk_data, sizeof(peer1_pubk_data),
                                    &peer1_pubk_data_len) == 0) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param() failed\n");
        goto end;
    }

    if (peer1_pubk_data_len != 32) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param() "
            "yielded wrong length\n");
        goto end;
    }

    /* Get public key corresponding to peer 2's private key */
    if (EVP_PKEY_get_octet_string_param(peer2_privk, OSSL_PKEY_PARAM_PUB_KEY,
                                    peer2_pubk_data, sizeof(peer1_pubk_data),
                                    &peer2_pubk_data_len) == 0) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param() failed\n");
        goto end;
    }

    if (peer2_pubk_data_len != 32) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param() "
            "yielded wrong length\n");
        goto end;
    }

    /*
     * At this point peer 1 and peer 2 would typically exchange
     * their pubk_data values.
     */

    /* Load public key for peer 1 (used by peer 2). */
    peer1_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", propq,
        peer1_pubk_data, peer1_pubk_data_len);
    if (peer1_pubk == NULL) {
        fprintf(stderr, "EVP_PKEY_new_raw_public_key_ex() failed\n");
        goto end;
    }

    /* Load public key for peer 2 (used by peer 1). */
    peer2_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", propq,
        peer2_pubk_data, peer2_pubk_data_len);
    if (peer2_pubk == NULL) {
        fprintf(stderr, "EVP_PKEY_new_raw_public_key_ex() failed\n");
        goto end;
    }

    /* Create key exchange context for each peer. */
    peer1_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, peer1_privk, propq);
    if (peer1_ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed\n");
        goto end;
    }

    peer2_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, peer2_privk, propq);
    if (peer2_ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed\n");
        goto end;
    }

    /* Initialize derivation process. */
    if (EVP_PKEY_derive_init(peer1_ctx) == 0) {
        fprintf(stderr, "EVP_PKEY_derive_init() failed\n");
        goto end;
    }
    if (EVP_PKEY_derive_init(peer2_ctx) == 0) {
        fprintf(stderr, "EVP_PKEY_derive_init() failed\n");
        goto end;
    }

    /* Configure each peer with the other peer's public key. */
    if (EVP_PKEY_derive_set_peer(peer1_ctx, peer2_pubk) == 0) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer() failed\n");
        goto end;
    }
    if (EVP_PKEY_derive_set_peer(peer2_ctx, peer1_pubk) == 0) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer() failed\n");
        goto end;
    }

    /* Determine the secret length. */
    if (EVP_PKEY_derive(peer1_ctx, NULL, &peer1_secret_len) == 0) {
        fprintf(stderr, "EVP_PKEY_derive() failed\n");
        goto end;
    }
    if (EVP_PKEY_derive(peer2_ctx, NULL, &peer2_secret_len) == 0) {
        fprintf(stderr, "EVP_PKEY_derive() failed\n");
        goto end;
    }

    /*
     * We are using X25519, so the secret generated will always be 32 bytes.
     * However for exposition, the code below demonstrates a generic
     * implementation for arbitrary lengths.
     */
    if (peer1_secret_len != 32 || peer2_secret_len != 32) { /* unreachable */
        fprintf(stderr, "Secret is always 32 bytes for X25519\n");
        goto end;
    }

    /* Allocate memory for shared secrets. */
    peer1_secret = OPENSSL_zalloc(peer1_secret_len);
    if (peer1_secret == NULL) {
        fprintf(stderr, "Could not allocate memory for secret\n");
        goto end;
    }

    peer2_secret = OPENSSL_zalloc(peer2_secret_len);
    if (peer2_secret == NULL) {
        fprintf(stderr, "Could not allocate memory for secret\n");
        goto end;
    }

    /* Derive the shared secret. */
    if (EVP_PKEY_derive(peer1_ctx, peer1_secret, &peer1_secret_len) == 0) {
        fprintf(stderr, "EVP_PKEY_derive() failed\n");
        goto end;
    }
    if (EVP_PKEY_derive(peer2_ctx, peer2_secret, &peer2_secret_len) == 0) {
        fprintf(stderr, "EVP_PKEY_derive() failed\n");
        goto end;
    }

    printf("Shared secret (peer 1):\n");
    BIO_dump_indent_fp(stdout, peer1_secret, peer1_secret_len, 2);
    putchar('\n');

    printf("Shared secret (peer 2):\n");
    BIO_dump_indent_fp(stdout, peer2_secret, peer2_secret_len, 2);
    putchar('\n');

    /*
     * Here we demonstrate the secrets are equal for exposition purposes.
     *
     * Although in practice you will generally not need to compare secrets
     * produced through key exchange, if you do compare cryptographic secrets,
     * always do so using a constant-time function such as CRYPTO_memcmp, never
     * using memcmp(3).
     */
    if (CRYPTO_memcmp(peer1_secret, peer2_secret, peer1_secret_len) != 0) {
        fprintf(stderr, "Negotiated secrets do not match\n");
        goto end;
    }

    /* If we are doing the KAT, the secret should equal our reference result. */
    if (use_kat && CRYPTO_memcmp(peer1_secret,
                        expected_result, peer1_secret_len) != 0) {
        fprintf(stderr, "Did not get expected result\n");
        goto end;
    }

    rv = 0;
end:
    /* The secrets are sensitive, so ensure they are erased before freeing. */
    OPENSSL_clear_free(peer1_secret, peer1_secret_len);
    OPENSSL_clear_free(peer2_secret, peer2_secret_len);

    EVP_PKEY_CTX_free(peer1_ctx);
    EVP_PKEY_CTX_free(peer2_ctx);
    EVP_PKEY_free(peer1_pubk);
    EVP_PKEY_free(peer2_pubk);
    EVP_PKEY_free(peer1_privk);
    EVP_PKEY_free(peer2_privk);
    OSSL_LIB_CTX_free(libctx);
    return rv;
}

int main(int argc, char **argv)
{
    /* Test X25519 key exchange with known result. */
    printf("Key exchange using known answer (deterministic):\n");
    if (keyexch_x25519(1) != 0)
        return 1;

    /* Test X25519 key exchange with random keys. */
    printf("Key exchange using random keys:\n");
    if (keyexch_x25519(0) != 0)
        return 1;

    return 0;
}
